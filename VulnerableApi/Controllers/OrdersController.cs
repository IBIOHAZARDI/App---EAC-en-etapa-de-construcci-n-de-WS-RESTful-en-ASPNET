using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableApi.Data;
using VulnerableApi.Models;

namespace VulnerableApi.Controllers;

/// <summary>
/// G1-V1 VULNERABLE: BOLA en órdenes — sin validación de ownership
/// Assert objetivo: A02
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Route("api/v1/[controller]")]
[Authorize]
public class OrdersController : ControllerBase
{
    private readonly AppDbContext _db;
    public OrdersController(AppDbContext db) => _db = db;

    /// <summary>
    /// G1-V1 VULNERABLE: Retorna cualquier orden por ID sin verificar que pertenezca al usuario.
    /// Escenario: UserA puede acceder a órdenes de UserB manipulando el ID.
    /// Assert A02: GET /api/v2/orders/{orden_de_userB} con token de userA → HTTP 403 o 404.
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetOrder(int id)
    {
        // VULNERABLE: sin filtro por UserId
        // FIX:
        //   var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        //   var order = await _db.Orders
        //       .Where(o => o.Id == id && o.UserId == userId)
        //       .FirstOrDefaultAsync();
        var order = await _db.Orders
            .Include(o => o.User)
            .FirstOrDefaultAsync(o => o.Id == id);

        if (order == null) return NotFound();
        return Ok(order);
    }

    [HttpGet]
    public async Task<IActionResult> GetMyOrders()
    {
        var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var orders = await _db.Orders
            .Where(o => o.UserId == userId)
            .ToListAsync();
        return Ok(orders);
    }

    [HttpPost]
    public async Task<IActionResult> CreateOrder([FromBody] Order order)
    {
        var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        order.UserId = userId;
        order.CreatedAt = DateTime.UtcNow;
        _db.Orders.Add(order);
        await _db.SaveChangesAsync();
        return CreatedAtAction(nameof(GetOrder), new { id = order.Id }, order);
    }
}
