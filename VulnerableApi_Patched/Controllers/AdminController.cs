using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableApi.Data;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: BFLA corregido — todas las rutas admin requieren rol "admin".
/// </summary>
[ApiController]
[Route("api/v2/admin")]
[Authorize(Roles = "admin")]  // FIX G1-V5: rol explícito requerido
public class AdminController : ControllerBase
{
    private readonly AppDbContext _db;
    public AdminController(AppDbContext db) => _db = db;

    [HttpDelete("users/{id:int}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var callerId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        if (id == callerId)
            return BadRequest(new { error = "No puede eliminar su propia cuenta." });

        var user = await _db.Users.FindAsync(id);
        if (user == null) return NotFound();

        _db.Users.Remove(user);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    [HttpGet("users")]
    public async Task<IActionResult> ListAllUsers()
    {
        // FIX A18c: retorna DTO sin contraseñas
        var users = await _db.Users
            .Select(u => new { u.Id, u.Name, u.Email, u.Role, u.IsAdmin })
            .ToListAsync();
        return Ok(users);
    }

    [HttpPost("users/{id:int}/promote")]
    public async Task<IActionResult> PromoteToAdmin(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user == null) return NotFound();

        user.Role    = "admin";
        user.IsAdmin = true;
        await _db.SaveChangesAsync();
        return Ok(new { message = $"Usuario {id} promovido a admin" });
    }
}
