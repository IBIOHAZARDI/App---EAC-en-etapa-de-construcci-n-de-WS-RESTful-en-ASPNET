// ============================================================
// G7-V1 VULNERABLE: Open Redirect
//   El parámetro returnUrl no valida el dominio de destino.
//   Un atacante puede redirigir a los usuarios a sitios de phishing.
//   OWASP API8:2023 / CWE-601
//   FIX: validar que returnUrl sea relativa o pertenezca a orígenes permitidos
//
// G7-V2 VULNERABLE: XXE (XML External Entity Injection)
//   XmlDocument con XmlUrlResolver activo permite leer archivos del sistema
//   y SSRF interno mediante entidades externas en el DTD del documento XML.
//   OWASP API3:2023 / API10:2023 / CWE-611
//   FIX: XmlResolver = null y DtdProcessing = DtdProcessing.Prohibit
//   NOTA: Esta vulnerabilidad fue agregada durante la implementación como
//   vector adicional de inyección en el endpoint de procesamiento XML.
//
// Assert objetivo: A22 (XXE → G7-V2), A23 (Open Redirect → G7-V1)
// ============================================================

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Xml;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/v2/[controller]")]
[Route("api/v1/[controller]")]
[Authorize]
public class ReportsController : ControllerBase
{
    private readonly ILogger<ReportsController> _logger;

    public ReportsController(ILogger<ReportsController> logger) => _logger = logger;

    /// <summary>
    /// G7-V2 VULNERABLE: Parseo de XML con DTD habilitado → XXE Injection.
    ///
    /// Payload que extrae el archivo de hosts del sistema:
    ///   Content-Type: application/xml
    ///   <?xml version="1.0"?>
    ///   <!DOCTYPE report [
    ///     <!ENTITY xxe SYSTEM "file:///C:/Windows/System32/drivers/etc/hosts">
    ///   ]>
    ///   <report>
    ///     <title>&xxe;</title>
    ///     <content>test</content>
    ///   </report>
    ///
    /// Con XmlUrlResolver habilitado el parser resuelve la entidad &xxe; leyendo
    /// el archivo local especificado en SYSTEM. El contenido del archivo aparece
    /// en la respuesta JSON dentro del campo "title".
    ///
    /// FIX:
    ///   var doc = new XmlDocument { XmlResolver = null };
    ///   o bien:
    ///   settings.DtdProcessing = DtdProcessing.Prohibit;
    /// </summary>
    [HttpPost("parse")]
    [Consumes("application/xml", "text/xml")]
    public async Task<IActionResult> ParseReport()
    {
        using var bodyReader = new StreamReader(Request.Body);
        var xmlContent = await bodyReader.ReadToEndAsync();

        try
        {
            // VULNERABLE: XmlResolver habilitado → resuelve entidades externas (SYSTEM, PUBLIC)
            // FIX: new XmlDocument { XmlResolver = null }
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();   // VULNERABLE
            doc.LoadXml(xmlContent);

            var title   = doc.SelectSingleNode("//title")?.InnerText   ?? string.Empty;
            var content = doc.SelectSingleNode("//content")?.InnerText ?? string.Empty;

            _logger.LogInformation("Reporte parseado — title length: {Len}", title.Length);

            return Ok(new { title, content, message = "Reporte procesado correctamente" });
        }
        catch (XmlException ex)
        {
            // G2-V3 encadenado: expone detalles internos del parser XML
            return BadRequest(new
            {
                error      = "Error al parsear XML",
                detail     = ex.Message,
                lineNumber = ex.LineNumber,
                linePos    = ex.LinePosition
            });
        }
    }

    /// <summary>
    /// G7-V1 VULNERABLE: Open Redirect sin validación del dominio de destino.
    ///
    /// Flujo de ataque:
    ///   1. Atacante envía enlace: https://mi-api-legitima.com/api/v2/reports/redirect?returnUrl=https://evil.com/phishing
    ///   2. Víctima confía en el dominio legítimo y hace clic.
    ///   3. El servidor emite HTTP 302 → Location: https://evil.com/phishing
    ///   4. El navegador redirige al sitio malicioso.
    ///
    /// Payload de prueba:
    ///   GET /api/v2/reports/redirect?returnUrl=https://attacker.example.com/phishing
    ///
    /// Assert A23: returnUrl con dominio externo → 400 (no 302 a destino ajeno).
    ///
    /// FIX:
    ///   if (!Uri.TryCreate(returnUrl, UriKind.Relative, out _) &&
    ///       !_allowedHosts.Contains(new Uri(returnUrl).Host))
    ///       return BadRequest("returnUrl no permitido.");
    /// </summary>
    [HttpGet("redirect")]
    [AllowAnonymous]
    public IActionResult RedirectAfterLogin([FromQuery] string returnUrl = "/")
    {
        // VULNERABLE: redirige a cualquier URL sin verificar el dominio
        // Un atacante puede forzar un redirect a dominios externos (phishing, token theft)
        // FIX: validar que returnUrl sea relativa (comience con "/") o pertenezca a allowed origins
        return Redirect(returnUrl);
    }
}
