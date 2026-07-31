using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableApi.Data;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: SQLi y XSS corregidos.
/// - Search usa LINQ parametrizado (FIX G3-V1)
/// - ByCategory no refleja el input en la respuesta (FIX G3-V2)
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
public class ProductsController : ControllerBase
{
    private readonly AppDbContext _db;
    public ProductsController(AppDbContext db) => _db = db;

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var products = await _db.Products
            .Select(p => new { p.Id, p.Name, p.Category, p.Price })
            .ToListAsync();
        return Ok(products);
    }

    /// <summary>
    /// FIX G3-V1: LINQ parametrizado — sin interpolación de strings en SQL.
    /// </summary>
    [HttpGet("search")]
    public async Task<IActionResult> Search([FromQuery] string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return BadRequest("Parámetro 'name' requerido.");

        // FIX: LINQ genera consulta parametrizada automáticamente
        var products = await _db.Products
            .Where(p => p.Name.Contains(name))
            .Select(p => new { p.Id, p.Name, p.Category, p.Price })
            .ToListAsync();

        return Ok(products);
    }

    /// <summary>
    /// FIX G3-V2: El input 'category' NO se refleja en la respuesta.
    /// </summary>
    [HttpGet("by-category")]
    public IActionResult ByCategory([FromQuery] string category)
    {
        if (string.IsNullOrWhiteSpace(category))
            return BadRequest("Parámetro 'category' requerido.");

        var results = _db.Products
            .Where(p => p.Category == category)
            .Select(p => new { p.Id, p.Name, p.Price })
            .ToList();

        // FIX: NO se incluye el valor de 'category' en la respuesta
        return Ok(new { count = results.Count, results });
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetById(int id)
    {
        var product = await _db.Products.FindAsync(id);
        return product == null ? NotFound() : Ok(new { product!.Id, product.Name, product.Category, product.Price });
    }
}
