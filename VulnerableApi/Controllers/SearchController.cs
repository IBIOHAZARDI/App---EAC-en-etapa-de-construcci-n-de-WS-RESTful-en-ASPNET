// ============================================================
// G3-V4 VULNERABLE: HTTP Response Header Injection (CRLF Injection)
//   El valor del parámetro ?query= se incluye en la cabecera X-Search-Query
//   sin eliminar \r ni \n. Un atacante puede inyectar cabeceras arbitrarias
//   (Set-Cookie, Location, etc.) o incluso dividir la respuesta HTTP.
//   Payload: ?query=legit%0d%0aSet-Cookie:%20session=hijacked
//   FIX: sanitizar eliminando \r y \n antes de asignar al header
//
// G6-V3 VULNERABLE: ReDoS (Regular Expression Denial of Service)
//   El endpoint /search/filter acepta un patrón regex del cliente sin timeout.
//   Un atacante puede enviar un patrón catastrófico que congela el hilo de proceso
//   durante segundos o minutos (e.g., ?pattern=(a+)+&input=aaaaaaaaaaaaaaab).
//   FIX: new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100))
//
// Assert objetivo: A24 (Header Injection), A25 (ReDoS / timeout)
// ============================================================

using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
using VulnerableApi.Data;

namespace VulnerableApi.Controllers;

[ApiController]
[Route("api/v2/[controller]")]
[Route("api/v1/[controller]")]
public class SearchController : ControllerBase
{
    private readonly AppDbContext _db;

    public SearchController(AppDbContext db) => _db = db;

    /// <summary>
    /// G3-V4 VULNERABLE: HTTP Response Header Injection / CRLF Injection.
    ///
    /// El valor de 'query' se copia literalmente en la cabecera X-Search-Query.
    /// Si el valor contiene \r\n (URL-encoded como %0d%0a), el servidor emite
    /// cabeceras adicionales elegidas por el atacante.
    ///
    /// Payload:
    ///   GET /api/v2/search?query=test%0d%0aSet-Cookie:%20session=evil
    ///
    /// Resultado: la respuesta incluye Set-Cookie: session=evil (inyectado).
    ///
    /// Variante de HTTP Response Splitting:
    ///   ?query=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK...
    ///
    /// Assert A24: la cabecera X-Search-Query no debe contener CRLF.
    ///
    /// FIX:
    ///   var safeQuery = query.Replace("\r", "").Replace("\n", "");
    ///   Response.Headers.Append("X-Search-Query", safeQuery);
    /// </summary>
    [HttpGet]
    public IActionResult Search([FromQuery] string query = "")
    {
        // VULNERABLE: el valor de query va directo al header sin sanitizar CRLF
        // FIX: filtrar \r y \n del valor antes de añadirlo a la cabecera
        Response.Headers.Append("X-Search-Query", query);

        var results = _db.Products
            .Where(p => p.Name.Contains(query) || p.Description.Contains(query))
            .Select(p => new { p.Id, p.Name, p.Category, p.Price })
            .ToList();

        return Ok(new { query, count = results.Count, results });
    }

    /// <summary>
    /// G6-V3 VULNERABLE: ReDoS — expresión regular controlada por el usuario sin timeout.
    ///
    /// El parámetro 'pattern' se compila y ejecuta con Regex.IsMatch sin límite de tiempo.
    /// Con un patrón de backtracking exponencial y un input diseñado, el hilo del servidor
    /// queda bloqueado durante un tiempo proporcional a O(2^n):
    ///
    /// Payload catastrófico:
    ///   GET /api/v2/search/filter?pattern=(a%2B)%2B&input=aaaaaaaaaaaaaaaaaab
    ///   (pattern = (a+)+, input = "aaaaaaaaaaaaaaaaaab" — sin coincidencia al final)
    ///
    /// Otro ejemplo:
    ///   pattern=([a-zA-Z]+)*&input=aaaaaaaaaaaaaaaaaaaaaaaa!
    ///
    /// Con 20 caracteres puede tardar varios segundos; con 30 supera el minuto.
    ///
    /// Assert A25: la evaluación no debe superar 500 ms para ningún input (timeout estricto).
    ///
    /// FIX:
    ///   var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
    ///   // Capturar RegexMatchTimeoutException y retornar 400
    /// </summary>
    [HttpGet("filter")]
    public IActionResult Filter([FromQuery] string pattern, [FromQuery] string input = "")
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return BadRequest(new { error = "El parámetro 'pattern' es requerido." });

        try
        {
            // VULNERABLE: Regex sin timeout → ReDoS posible
            // FIX: new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100))
            var isMatch = Regex.IsMatch(input, pattern);

            return Ok(new { pattern, input, isMatch });
        }
        catch (RegexParseException ex)
        {
            return BadRequest(new { error = "Patrón regex inválido", detail = ex.Message });
        }
        // VULNERABLE: RegexMatchTimeoutException nunca se lanza porque no hay timeout configurado
    }
}
