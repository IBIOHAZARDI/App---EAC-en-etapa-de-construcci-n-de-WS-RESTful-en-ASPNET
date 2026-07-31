using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableApi.Data;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: SSRF y debug-info corregidos.
/// - /info requiere autenticación admin (FIX G5-V1)
/// - /ping bloquea rangos RFC 1918, loopback y link-local (FIX G5-V3)
/// - /health-verbose elimina información de versión (FIX G2-V6)
/// </summary>
[ApiController]
[Route("api/v2/diagnostics")]
public class DiagnosticsController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly IHttpClientFactory _httpClientFactory;

    public DiagnosticsController(IConfiguration config, IHttpClientFactory httpClientFactory)
    {
        _config = config;
        _httpClientFactory = httpClientFactory;
    }

    private static bool IsPrivateOrRestrictedAddress(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return true;

        // FIX: bloquear esquemas no-HTTP
        if (uri.Scheme != "http" && uri.Scheme != "https")
            return true;

        // FIX: bloquear loopback, link-local y RFC 1918 por nombre de host
        var host = uri.Host.ToLowerInvariant();
        if (host == "localhost" || host == "127.0.0.1" || host == "::1")
            return true;

        // Intentar parsear como IP directamente
        if (System.Net.IPAddress.TryParse(host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                // 10.0.0.0/8
                if (bytes[0] == 10) return true;
                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168) return true;
                // 169.254.0.0/16 (link-local / AWS metadata)
                if (bytes[0] == 169 && bytes[1] == 254) return true;
                // 127.0.0.0/8
                if (bytes[0] == 127) return true;
            }
        }

        return false;
    }

    /// <summary>
    /// FIX G5-V3: SSRF — valida URL antes del check de autenticación.
    /// Las URLs privadas son rechazadas (400) incluso para usuarios no autenticados.
    /// Usuarios públicos sin auth reciben 401 solo para URLs públicas válidas.
    /// </summary>
    [HttpGet("ping")]
    [AllowAnonymous]  // FIX: SSRF check debe ejecutarse ANTES que la autenticación
    public async Task<IActionResult> Ping([FromQuery] string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return BadRequest("El parámetro 'url' es requerido.");

        // FIX: bloquear URLs privadas ANTES del check de autenticación
        if (IsPrivateOrRestrictedAddress(url))
            return StatusCode(400, new { error = "URL no permitida: destino bloqueado por política SSRF." });

        // FIX: autenticación manual — solo admins pueden usar el ping con URLs públicas
        if (!(User.Identity?.IsAuthenticated ?? false))
            return Unauthorized();
        if (!User.IsInRole("admin"))
            return Forbid();
        try
        {
            var client = _httpClientFactory.CreateClient("safe");
            client.Timeout = TimeSpan.FromSeconds(5);
            var response = await client.GetAsync(url);
            var body = await response.Content.ReadAsStringAsync();

            return Ok(new
            {
                statusCode = (int)response.StatusCode,
                body = body.Length > 500 ? body[..500] : body
            });
        }
        catch (Exception)
        {
            return StatusCode(502, new { error = "No se pudo conectar al destino." });
        }
    }

    /// <summary>
    /// FIX G5-V1: Debug info protegido por rol admin — NO accesible anónimamente.
    /// </summary>
    [HttpGet("info")]
    [Authorize(Roles = "admin")]
    public IActionResult Info()
    {
        return Ok(new
        {
            dotnetRuntime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            uptime = (DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess()
                        .StartTime.ToUniversalTime()).ToString()
        });
    }

    /// <summary>
    /// FIX G2-V6: Health check sin información de versión.
    /// </summary>
    [HttpGet("health-verbose")]
    public IActionResult HealthVerbose()
    {
        return Ok(new { status = "healthy" });
    }
}
