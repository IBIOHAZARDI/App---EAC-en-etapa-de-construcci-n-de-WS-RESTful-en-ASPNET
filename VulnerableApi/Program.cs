// ============================================================
// VULNERABLE API — SOLO PARA PRUEBAS CONTROLADAS EN AMBIENTE NO PRODUCTIVO
// NO DESPLEGAR EN PRODUCCIÓN
// Ground truth: 28 vulnerabilidades inyectadas intencionalmente
// Ref: Tesis MSI — Estrategia de aseguramiento ciberseguridad RESTful ASP.NET
// ============================================================

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using VulnerableApi.Data;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "VulnerableApi", Version = "v1" });
    c.SwaggerDoc("v2", new() { Title = "VulnerableApi", Version = "v2" });
});

// G2-V1 VULNERABLE: CORS wildcard — permite cualquier origen
// FIX: .WithOrigins("https://mi-app.com").WithMethods("GET","POST")
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// G1-V4 VULNERABLE: JWT sin validación de issuer, audience ni lifetime
// Clave criptográficamente débil ("weak-key" = 8 bytes)
// FIX: validar issuer/audience/lifetime, clave >= 256 bits
// G6-V2 VULNERABLE: JWT aceptado vía query string (?token=...) además del header Authorization.
// Permite que el token aparezca en logs de servidor, historial de navegador y referrer headers.
// FIX: eliminar OnMessageReceived y exigir exclusivamente el header Authorization: Bearer
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,       // Tokens nunca expiran
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("weak-key"))
        };

        // G6-V2 VULNERABLE: lee el token del query string (?token=...)
        options.Events = new Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                var token = ctx.Request.Query["token"];
                if (!string.IsNullOrWhiteSpace(token))
                    ctx.Token = token;
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")
        ?? "Data Source=vulnerable.db"));

var app = builder.Build();

// G2-V3 VULNERABLE: DeveloperExceptionPage activo en todos los ambientes
// Expone stack traces, rutas y versiones en errores 500
// FIX: app.UseExceptionHandler("/error") en producción
app.UseDeveloperExceptionPage();

// G2-V4 VULNERABLE: Swagger expuesto sin restricción de ambiente
// FIX: envolver en if (app.Environment.IsDevelopment())
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1 (deprecada)");
    c.SwaggerEndpoint("/swagger/v2/swagger.json", "API v2");
});

// G4-V1 VULNERABLE: Sin HTTPS redirect ni HSTS
// FIX: app.UseHttpsRedirection(); app.UseHsts();

// G2-V2 VULNERABLE: Sin middleware de cabeceras de seguridad
// FIX: agregar middleware que inyecte X-Content-Type-Options, X-Frame-Options,
//      Content-Security-Policy, Referrer-Policy

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// G4-V2 VULNERABLE: API v1 sigue activa sin deprecación formal
// Los controladores con [ApiVersion("1.0")] responden normalmente
app.MapControllers();

// Endpoint de health check para el pipeline
app.MapGet("/health", () => Results.Ok(new { status = "healthy", version = "2.0" }));

// Seed de datos de prueba
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
    await DataSeeder.SeedAsync(db);
}

app.Run();
