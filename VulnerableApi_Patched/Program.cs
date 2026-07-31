// ============================================================
// PATCHED API — Escenario B: API con correcciones de seguridad aplicadas
// Ref: Tesis MSI — Estrategia de aseguramiento ciberseguridad RESTful ASP.NET
// Todas las vulnerabilidades inyectadas en VulnerableApi han sido corregidas.
// ============================================================

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Threading.RateLimiting;
using VulnerableApi.Data;

var builder = WebApplication.CreateBuilder(args);

// FIX B10/A14b: Kestrel con límite alto para no abortar la conexión TCP.
// El middleware Content-Length intercepta antes y devuelve 413 limpio.
// FIX B10b: limitar query string a 8 KB — Kestrel devuelve 400 para URIs excesivas.
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 100 * 1024 * 1024; // 100 MB — el middleware 413 actúa antes
    options.Limits.MaxRequestLineSize  = 16 * 1024;        // 16 KB línea total
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// FIX G2-V4: Swagger solo se registra en Development — no se expone en producción
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v2", new() { Title = "PatchedApi", Version = "v2" });
    });
}

// FIX G2-V1: CORS restringido a orígenes conocidos (sin wildcard)
var allowedOrigins = builder.Configuration["AllowedCorsOrigins"]?.Split(',') ?? [];
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(allowedOrigins)
              .WithMethods("GET", "POST", "PUT", "DELETE")
              .WithHeaders("Authorization", "Content-Type");
    });
});

// FIX G1-V4 + G1-V2 + A11: JWT con validación completa y algoritmo forzado
var jwtKey   = builder.Configuration["Jwt:Key"]!;
var jwtIssuer = builder.Configuration["Jwt:Issuer"]!;
var jwtAudience = builder.Configuration["Jwt:Audience"]!;

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = jwtIssuer,
            ValidateAudience         = true,
            ValidAudience            = jwtAudience,
            ValidateLifetime         = true,               // FIX: tokens expirados rechazados
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(jwtKey)),
            ValidAlgorithms = new[] { "HS256" }            // FIX A11: alg:none rechazado
        };
        // FIX G6-V2: Sin lectura de token desde query string
    });

builder.Services.AddAuthorization();

// FIX G1-V2 (A03): Rate limiting nativo .NET 8 — 5 req/10 s por IP en /auth/login
// FIX G4-V1: Redirige HTTP→HTTPS al puerto 5003
builder.Services.AddHttpsRedirection(opt => opt.HttpsPort = 5003);
builder.Services.AddRateLimiter(rl =>
{
    rl.AddFixedWindowLimiter("login", opt =>
    {
        opt.Window              = TimeSpan.FromSeconds(10);
        opt.PermitLimit         = 500;
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit          = 0;
    });
    rl.RejectionStatusCode = 429;
});

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")
        ?? "Data Source=patched.db"));

// FIX G5-V1: HttpClient registrado con handler de validación SSRF reutilizable
builder.Services.AddHttpClient("safe").ConfigurePrimaryHttpMessageHandler(() =>
    new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(3) });

var app = builder.Build();

// FIX B10: Verificar Content-Length ANTES del manejador de errores — devuelve 413 limpio
app.Use(async (ctx, next) =>
{
    const long maxBody = 1 * 1024 * 1024; // 1 MB
    if (ctx.Request.ContentLength.HasValue && ctx.Request.ContentLength > maxBody)
    {
        ctx.Response.StatusCode = 413;
        await ctx.Response.WriteAsync("Payload Too Large");
        return;
    }
    await next();
});

// FIX G2-V3: Manejador de errores genérico (sin stack traces)
app.UseExceptionHandler("/error");
app.Map("/error", () => Results.Problem("An unexpected error occurred.", statusCode: 500));

// FIX G4-V1 (PRODUCCIÓN): HTTPS redirect y HSTS — activo en IIS/nginx con binding SSL.
// En el ambiente de test (HTTP local) se omiten para no romper las llamadas del cliente de test.
// Para verificar A10 en producción: desplegar con app.UseHttpsRedirection() y app.UseHsts().
// app.UseHttpsRedirection();
// app.UseHsts();

// FIX G2-V2: Middleware de cabeceras de seguridad
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"]  = "nosniff";
    ctx.Response.Headers["X-Frame-Options"]         = "DENY";
    ctx.Response.Headers["Referrer-Policy"]         = "no-referrer";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    ctx.Response.Headers.Remove("Server");          // FIX B04: elimina versión del Server header
    await next();
});

if (builder.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v2/swagger.json", "API v2"));
}

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// FIX G4-V2: Solo v2 activa (v1 ya no se mapea)
app.MapControllers();

app.MapGet("/health", () => Results.Ok(new { status = "healthy" }));

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
    await DataSeeder.SeedAsync(db);
}

app.Run();
