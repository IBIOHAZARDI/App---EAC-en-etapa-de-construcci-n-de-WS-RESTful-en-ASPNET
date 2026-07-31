using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
using VulnerableApi.Data;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: CRLF Injection y ReDoS corregidos.
/// - Search sanitiza \r\n antes de escribir en el header (FIX G3-V4)
/// - Filter usa Regex con timeout de 100 ms (FIX G6-V3)
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
public class SearchController : ControllerBase
{
    private readonly AppDbContext _db;

    public SearchController(AppDbContext db) => _db = db;

    /// <summary>
    /// FIX G3-V4: Elimina \r y \n del valor antes de escribirlo en el header.
    /// </summary>
    [HttpGet]
    public IActionResult Search([FromQuery] string query = "")
    {
        // FIX: sanitizar CRLF antes de añadir al header
        var safeQuery = query.Replace("\r", "").Replace("\n", "");
        Response.Headers.Append("X-Search-Query", safeQuery);

        var results = _db.Products
            .Where(p => p.Name.Contains(query) || p.Description.Contains(query))
            .Select(p => new { p.Id, p.Name, p.Category, p.Price })
            .ToList();

        return Ok(new { count = results.Count, results });
    }

    /// <summary>
    /// FIX G6-V3: Regex con timeout de 100 ms — elimina riesgo de ReDoS.
    /// </summary>
    [HttpGet("filter")]
    public IActionResult Filter([FromQuery] string pattern, [FromQuery] string input = "")
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return BadRequest(new { error = "El parámetro 'pattern' es requerido." });

        try
        {
            // FIX: timeout de 100 ms — lanza RegexMatchTimeoutException ante backtracking excesivo
            var regex = new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
            var isMatch = regex.IsMatch(input);
            return Ok(new { isMatch });
        }
        catch (RegexMatchTimeoutException)
        {
            return BadRequest(new { error = "Evaluación del patrón excedió el tiempo máximo permitido." });
        }
        catch (RegexParseException ex)
        {
            return BadRequest(new { error = "Patrón regex inválido", detail = ex.Message });
        }
    }
}
