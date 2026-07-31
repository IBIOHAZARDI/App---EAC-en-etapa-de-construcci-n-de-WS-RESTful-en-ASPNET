using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: HMAC y SSRF de webhooks corregidos.
/// - Receive verifica firma HMAC-SHA256 (FIX G8-V1)
/// - Register bloquea callbackUrls privadas (FIX G8-V2)
/// - Logs no incluyen el payload completo (FIX G2-V8)
/// </summary>
[ApiController]
[Route("api/v2/webhooks")]
[Authorize]
public class WebhooksController : ControllerBase
{
    private readonly ILogger<WebhooksController> _logger;
    private readonly IConfiguration _config;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebhooksController(
        ILogger<WebhooksController> logger,
        IConfiguration config,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _config = config;
        _httpClientFactory = httpClientFactory;
    }

    private static string ComputeHmac(string payload, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var dataBytes = Encoding.UTF8.GetBytes(payload);
        using var hmac = new HMACSHA256(keyBytes);
        return "sha256=" + Convert.ToHexString(hmac.ComputeHash(dataBytes)).ToLowerInvariant();
    }

    private static bool IsPrivateAddress(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return true;
        if (uri.Scheme != "https") return true;  // Solo HTTPS para webhooks

        var host = uri.Host.ToLowerInvariant();
        if (host == "localhost" || host == "127.0.0.1" || host == "::1") return true;

        if (IPAddress.TryParse(host, out var ip))
        {
            var b = ip.GetAddressBytes();
            if (b.Length == 4)
            {
                if (b[0] == 10) return true;
                if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
                if (b[0] == 192 && b[1] == 168) return true;
                if (b[0] == 169 && b[1] == 254) return true;
                if (b[0] == 127) return true;
            }
        }
        return false;
    }

    /// <summary>
    /// FIX G8-V1: Verifica X-Hub-Signature-256 con HMAC-SHA256 en tiempo constante.
    /// </summary>
    [HttpPost("receive")]
    [AllowAnonymous]
    public async Task<IActionResult> Receive()
    {
        using var bodyReader = new StreamReader(Request.Body);
        var body = await bodyReader.ReadToEndAsync();

        var receivedSig = Request.Headers["X-Hub-Signature-256"].ToString();
        if (string.IsNullOrWhiteSpace(receivedSig))
            return Unauthorized(new { error = "Cabecera X-Hub-Signature-256 requerida." });

        var secret = _config["Webhook:SharedSecret"]!;
        var expected = ComputeHmac(body, secret);

        // FIX: comparación en tiempo constante para evitar timing attacks
        if (!CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(receivedSig),
                Encoding.UTF8.GetBytes(expected)))
        {
            return Unauthorized(new { error = "Firma HMAC inválida." });
        }

        // FIX G2-V8: NO se loguea el body completo, solo metadatos
        _logger.LogInformation("Webhook válido recibido — bytes: {Len}", body.Length);

        return Ok(new { received = true, processedAt = DateTime.UtcNow });
    }

    /// <summary>
    /// FIX G8-V2: callbackUrl bloqueada si apunta a rangos privados.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] WebhookRegistrationDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.CallbackUrl))
            return BadRequest(new { error = "callbackUrl es requerida." });

        if (IsPrivateAddress(dto.CallbackUrl))
            return BadRequest(new { error = "callbackUrl apunta a un destino no permitido." });

        try
        {
            var client = _httpClientFactory.CreateClient("safe");
            client.Timeout = TimeSpan.FromSeconds(5);
            var pingResp = await client.GetAsync(dto.CallbackUrl);

            _logger.LogInformation("Webhook registrado: ping {Status}", (int)pingResp.StatusCode);

            return Ok(new
            {
                registered   = true,
                callbackUrl  = dto.CallbackUrl,
                pingStatus   = (int)pingResp.StatusCode
            });
        }
        catch (Exception)
        {
            return BadRequest(new { error = "No se pudo verificar el endpoint de callback." });
        }
    }
}

public record WebhookRegistrationDto(string CallbackUrl);
