using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Xml;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: Open Redirect (G7-V1) y XXE (G7-V2) corregidos.
/// - RedirectAfterLogin valida que returnUrl sea relativa (FIX G7-V1)
/// - ParseReport deshabilita DTD completamente (FIX G7-V2)
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Authorize]
public class ReportsController : ControllerBase
{
    private readonly ILogger<ReportsController> _logger;

    public ReportsController(ILogger<ReportsController> logger) => _logger = logger;

    /// <summary>
    /// FIX G7-V2: XmlResolver = null + DtdProcessing.Prohibit — sin entidades externas.
    /// </summary>
    [HttpPost("parse")]
    [Consumes("application/xml", "text/xml")]
    public async Task<IActionResult> ParseReport()
    {
        using var bodyReader = new StreamReader(Request.Body);
        var xmlContent = await bodyReader.ReadToEndAsync();

        try
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,  // FIX: DTD prohibido
                XmlResolver   = null                      // FIX: sin resolver externo
            };

            using var reader = XmlReader.Create(new StringReader(xmlContent), settings);
            var doc = new XmlDocument { XmlResolver = null };
            doc.Load(reader);

            var title   = doc.SelectSingleNode("//title")?.InnerText   ?? string.Empty;
            var content = doc.SelectSingleNode("//content")?.InnerText ?? string.Empty;

            _logger.LogInformation("Reporte parseado — longitud título: {Len}", title.Length);

            return Ok(new { title, content, message = "Reporte procesado correctamente" });
        }
        catch (XmlException)
        {
            // FIX G2-V3: sin detalles internos del parser en la respuesta
            return BadRequest(new { error = "El documento XML es inválido." });
        }
    }

    /// <summary>
    /// FIX G7-V1: Open Redirect — solo se permiten URLs relativas (no protocol-relative).
    /// </summary>
    [HttpGet("redirect")]
    [AllowAnonymous]
    public IActionResult RedirectAfterLogin([FromQuery] string returnUrl = "/")
    {
        // FIX: rechazar protocol-relative URLs (//evil.com) que son absolutas en navegadores
        if (returnUrl.StartsWith("//", StringComparison.Ordinal)
            || returnUrl.StartsWith("%2f%2f", StringComparison.OrdinalIgnoreCase)
            || returnUrl.StartsWith("%2F%2F", StringComparison.Ordinal))
            return BadRequest(new { error = "returnUrl no permitida: protocol-relative URL." });

        // FIX: solo URLs relativas son permitidas
        if (!Uri.TryCreate(returnUrl, UriKind.Relative, out _))
            return BadRequest(new { error = "returnUrl debe ser una URL relativa." });

        return Redirect(returnUrl);
    }
}
