using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace VulnerableApi.Controllers;

/// <summary>
/// G5-V1 VULNERABLE: Debug endpoint expone variables de entorno, configuración y versiones
///   GET /diagnostics/info accesible sin autenticación.
/// G5-V3 VULNERABLE: SSRF — el servidor realiza peticiones HTTP a URLs controladas por el cliente
///   GET /diagnostics/ping?url=...
/// Assert objetivo: A16 (G5-V1 debug), A15 (G5-V3 SSRF)
/// </summary>
[ApiController]
[Route("api/v2/diagnostics")]
public class DiagnosticsController : ControllerBase
{
    private readonly IConfiguration _config;

    public DiagnosticsController(IConfiguration config) => _config = config;

    /// <summary>
    /// G5-V3 VULNERABLE: SSRF (Server-Side Request Forgery)
    /// El servidor realiza una petición HTTP a cualquier URL proporcionada por el cliente.
    /// Payloads:
    ///   ?url=http://169.254.169.254/latest/meta-data/          (metadata AWS EC2)
    ///   ?url=http://localhost:5985/                             (WinRM interno)
    ///   ?url=file:///C:/Windows/System32/drivers/etc/hosts
    /// Assert A15: el endpoint debe rechazar URLs a rangos privados (RFC 1918) → 400 o 403.
    /// FIX: whitelist de dominios permitidos, bloquear rangos RFC 1918/loopback/link-local
    /// </summary>
    [HttpGet("ping")]
    public async Task<IActionResult> Ping([FromQuery] string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return BadRequest("El parámetro 'url' es requerido.");

        // VULNERABLE: sin validación de la URL destino
        // FIX: parsear Uri, bloquear IPPrivateRanges, loopback, link-local, file://
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var response = await client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            return Ok(new
            {
                statusCode  = (int)response.StatusCode,
                headers     = response.Headers.ToDictionary(h => h.Key, h => h.Value),
                body        = body.Length > 2000 ? body[..2000] : body
            });
        }
        catch (Exception ex)
        {
            // VULNERABLE: expone el mensaje de excepción (dirección interna, tipo de error)
            return StatusCode(500, new { error = ex.Message, url });
        }
    }

    /// <summary>
    /// G5-V1 VULNERABLE: Debug endpoint expone información interna del servidor.
    /// — Variables de entorno (pueden contener secretos como DATABASE_URL, API_KEY)
    /// — Cadena de conexión (contraseña de BD si es SQL Server)
    /// — Versión exacta del runtime y sistema operativo
    /// — Directorio de trabajo y rutas absolutas
    /// Assert A16: el endpoint de diagnóstico debe retornar HTTP 404 o requerir autenticación.
    /// FIX: eliminar en producción, o proteger con [Authorize(Roles = "admin")] y solo en IsDevelopment
    /// </summary>
    [HttpGet("info")]
    public IActionResult Info()
    {
        // VULNERABLE: accesible sin autenticación, expone datos sensibles del servidor
        return Ok(new
        {
            environment     = Environment.GetEnvironmentVariables().Keys.Cast<string>()
                                .ToDictionary(k => k, k => Environment.GetEnvironmentVariable(k)),
            connectionString = _config.GetConnectionString("DefaultConnection"),
            dotnetRuntime   = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            os              = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            machineName     = Environment.MachineName,
            workingDir      = Directory.GetCurrentDirectory(),
            processId       = Environment.ProcessId
        });
    }

    /// <summary>
    /// G2-V6 VULNERABLE: Health check con información de versión detallada
    /// Expone versión exacta del servidor en respuesta pública.
    /// </summary>
    [HttpGet("health-verbose")]
    public IActionResult HealthVerbose()
    {
        return Ok(new
        {
            status  = "healthy",
            version = typeof(DiagnosticsController).Assembly.GetName().Version?.ToString(),
            runtime = Environment.Version.ToString(),
            server  = $"IIS/10 ASP.NET Core/{Environment.Version} Windows",
            uptime  = (DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime()).ToString()
        });
    }
}
