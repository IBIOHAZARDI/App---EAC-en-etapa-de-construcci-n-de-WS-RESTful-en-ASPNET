using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableApi.Data;
using VulnerableApi.Models;

namespace VulnerableApi.Controllers;

/// <summary>
/// G3-V1 VULNERABLE: Inyección SQL via FromSqlRaw con interpolación
/// G3-V2 VULNERABLE: XSS reflejado en respuesta
/// G2-V5 VULNERABLE: Sin rate limiting, sin paginación
/// Assert objetivo: A08, A09, B08
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Route("api/v1/[controller]")]
public class ProductsController : ControllerBase
{
    private readonly AppDbContext _db;
    public ProductsController(AppDbContext db) => _db = db;

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        // G2-V5 VULNERABLE: Sin paginación
        var products = await _db.Products.ToListAsync();
        return Ok(products);
    }

    /// <summary>
    /// G3-V1 VULNERABLE: Interpolación directa en FromSqlRaw → SQLi
    /// Payload: ?name=' OR '1'='1 retorna TODOS los productos
    /// Payload: ?name='; DROP TABLE Products; --
    /// Assert A08: el payload OR '1'='1 NO debe retornar todos los registros.
    /// </summary>
    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return BadRequest("Parámetro 'name' requerido.");

        // VULNERABLE: interpolación directa — permite SQLi
        // FIX opción 1: LINQ → _db.Products.Where(p => p.Name.Contains(name))
        // FIX opción 2: FromSqlInterpolated($"SELECT * FROM Products WHERE Name LIKE {pattern}")
        var sql = $"SELECT * FROM Products WHERE Name LIKE '%{name}%'";
        var products = await _db.Products.FromSqlRaw(sql).ToListAsync();

        return Ok(products);
    }

    /// <summary>
    /// G3-V2 VULNERABLE: El valor del parámetro 'category' se refleja sin sanitizar.
    /// Payload: ?category=`<script>alert(1)</script>`
    /// Assert A09: la respuesta NO debe contener el script sin escapar.
    /// </summary>
    [HttpGet("by-category")]
    public IActionResult ByCategory([FromQuery] string category)
    {
        // VULNERABLE: refleja el input sin sanitizar en el body de respuesta
        // FIX: no reflejar el input, o usar HtmlEncoder.Encode(category)
        return Ok(new
        {
            query = category, // XSS reflejado si el cliente renderiza el JSON como HTML
            results = _db.Products.Where(p => p.Category == category).ToList()
        });
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetById(int id)
    {
        var product = await _db.Products.FindAsync(id);
        return product == null ? NotFound() : Ok(product);
    }
}
