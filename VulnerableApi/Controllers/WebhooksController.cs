// ============================================================
// G8-V1 VULNERABLE: Webhook sin verificación de firma HMAC
//   El endpoint /webhooks/receive acepta cualquier petición POST sin verificar
//   la cabecera X-Hub-Signature-256. Un atacante puede inyectar eventos falsos.
//   FIX: calcular HMAC-SHA256 del body con la clave compartida y comparar con
//        la firma recibida en X-Hub-Signature-256 usando comparación en tiempo constante.
//
// G8-V2 VULNERABLE: SSRF via webhook callback URL
//   El endpoint /webhooks/register acepta una callbackUrl arbitraria y realiza
//   una petición HTTP de verificación sin validar el destino. Permite acceder a
//   recursos internos (loopback, RFC 1918, metadatos de nube).
//   FIX: validar que la URL sea HTTPS y pertenezca a dominios de una whitelist.
//
// G2-V8 VULNERABLE: Datos sensibles en logs de webhook
//   El body completo del webhook se registra en el logger, exponiendo potencialmente
//   datos de negocio o tokens en los logs del sistema.
//   FIX: loguear únicamente metadatos (longitud, eventType) no el payload completo.
//
// Assert objetivo: A26 (no HMAC), A27 (SSRF webhook), A28 (sensitive log)
// ============================================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/v2/webhooks")]
[Authorize]
public class WebhooksController : ControllerBase
{
    private readonly ILogger<WebhooksController> _logger;

    public WebhooksController(ILogger<WebhooksController> logger) => _logger = logger;

    /// <summary>
    /// G8-V1 VULNERABLE: Recepción de webhook sin verificación de firma HMAC.
    ///
    /// GitHub, Stripe y otros proveedores firman el payload con HMAC-SHA256 y
    /// envían la firma en X-Hub-Signature-256 (p.ej. "sha256=abc123...").
    /// Este endpoint ignora esa cabecera y procesa cualquier evento.
    ///
    /// Ataque: cualquier actor puede emitir eventos falsificados:
    ///   POST /api/v2/webhooks/receive
    ///   Content-Type: application/json
    ///   { "eventType": "payment.completed", "amount": 99999 }
    ///
    /// Assert A26: sin cabecera X-Hub-Signature-256 válida el endpoint
    ///             debe responder 401, no 200.
    ///
    /// FIX:
    ///   var signature = Request.Headers["X-Hub-Signature-256"].ToString();
    ///   var expected = "sha256=" + ComputeHmac(body, sharedSecret);
    ///   if (!CryptographicOperations.FixedTimeEquals(
    ///           Encoding.UTF8.GetBytes(signature),
    ///           Encoding.UTF8.GetBytes(expected)))
    ///       return Unauthorized();
    /// </summary>
    [HttpPost("receive")]
    [AllowAnonymous]
    public async Task<IActionResult> Receive()
    {
        using var bodyReader = new StreamReader(Request.Body);
        var body = await bodyReader.ReadToEndAsync();

        // VULNERABLE: sin verificación de firma — cualquier cliente puede enviar eventos falsos
        // G8-V1: la cabecera X-Hub-Signature-256 nunca se valida
        // FIX: implementar VerifyHmacSignature(body, Request.Headers["X-Hub-Signature-256"])

        // G2-V8 VULNERABLE: el cuerpo completo del webhook se registra en logs
        // Puede contener datos sensibles (tokens, PII, montos de transacción)
        // FIX: _logger.LogInformation("Webhook recibido — eventType: {Type}, bytes: {Len}", eventType, body.Length);
        _logger.LogInformation("Webhook recibido completo: {Body}", body);

        return Ok(new { received = true, processedAt = DateTime.UtcNow });
    }

    /// <summary>
    /// G8-V2 VULNERABLE: SSRF mediante callbackUrl de webhook.
    ///
    /// Al registrar un webhook, el servidor realiza una petición HTTP de "ping"
    /// a la URL indicada por el cliente para verificar que el endpoint existe.
    /// Sin validación del destino, un atacante registra una URL interna:
    ///
    /// Payloads:
    ///   { "callbackUrl": "http://169.254.169.254/latest/meta-data/" }   ← metadatos AWS
    ///   { "callbackUrl": "http://192.168.1.1/admin" }                    ← router interno
    ///   { "callbackUrl": "http://localhost:5985/wsman" }                  ← WinRM local
    ///
    /// La respuesta HTTP del recurso interno puede aparecer en el campo pingStatus
    /// o en los mensajes de error, filtrando información de la red interna.
    ///
    /// Assert A27: callbackUrl a rangos RFC 1918 / loopback / link-local
    ///             debe retornar 400, no 200.
    ///
    /// FIX:
    ///   var uri = new Uri(callbackUrl);
    ///   var addresses = Dns.GetHostAddresses(uri.Host);
    ///   if (addresses.Any(IsPrivateOrLoopback)) return BadRequest("callbackUrl no permitida.");
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] WebhookRegistrationDto dto)
    {
        if (string.IsNullOrWhiteSpace(dto.CallbackUrl))
            return BadRequest(new { error = "callbackUrl es requerida." });

        // VULNERABLE: sin validación de la URL de destino → SSRF
        // FIX: verificar que la URL no apunte a rangos privados (RFC 1918, loopback, link-local)
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            // Ping de verificación al endpoint del cliente → SSRF
            var pingResp = await client.GetAsync(dto.CallbackUrl);

            _logger.LogInformation("Webhook registrado: {Url} → ping {Status}",
                dto.CallbackUrl, (int)pingResp.StatusCode);

            return Ok(new
            {
                registered  = true,
                callbackUrl = dto.CallbackUrl,
                eventType   = dto.EventType,
                pingStatus  = (int)pingResp.StatusCode
            });
        }
        catch (Exception ex)
        {
            // VULNERABLE: el mensaje de error puede revelar detalles de la red interna
            return Ok(new
            {
                registered  = true,
                callbackUrl = dto.CallbackUrl,
                eventType   = dto.EventType,
                pingError   = ex.Message
            });
        }
    }
}

public record WebhookRegistrationDto(
    string CallbackUrl,
    string EventType = "order.created"
);
