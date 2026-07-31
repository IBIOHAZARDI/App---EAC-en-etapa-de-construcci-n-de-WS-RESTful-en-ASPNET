using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableApi.Data;
using VulnerableApi.Models;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: BOLA en órdenes corregido (FIX G1-V1).
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Authorize]
public class OrdersController : ControllerBase
{
    private readonly AppDbContext _db;
    public OrdersController(AppDbContext db) => _db = db;

    /// <summary>
    /// FIX G1-V1: Verifica que la orden pertenezca al usuario autenticado.
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetOrder(int id)
    {
        var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var isAdmin = User.IsInRole("admin");

        var order = await _db.Orders
            .Include(o => o.User)
            .FirstOrDefaultAsync(o => o.Id == id);

        if (order == null) return NotFound();

        // FIX: solo el propietario o admin puede ver la orden
        if (!isAdmin && order.UserId != userId)
            return StatusCode(403, new { error = "Acceso denegado." });

        return Ok(new { order.Id, order.Amount, order.CreatedAt, order.UserId });
    }

    [HttpGet]
    public async Task<IActionResult> GetMyOrders()
    {
        var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var orders = await _db.Orders
            .Where(o => o.UserId == userId)
            .Select(o => new { o.Id, o.Amount, o.CreatedAt })
            .ToListAsync();
        return Ok(orders);
    }

    [HttpPost]
    public async Task<IActionResult> CreateOrder([FromBody] Order order)
    {
        var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        order.UserId    = userId;
        order.CreatedAt = DateTime.UtcNow;
        _db.Orders.Add(order);
        await _db.SaveChangesAsync();
        return CreatedAtAction(nameof(GetOrder), new { id = order.Id }, new { order.Id });
    }
}
