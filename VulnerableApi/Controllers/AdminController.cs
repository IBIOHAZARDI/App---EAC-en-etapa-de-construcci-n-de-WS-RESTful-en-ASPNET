using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using VulnerableApi.Data;

namespace VulnerableApi.Controllers;

/// <summary>
/// G1-V5 VULNERABLE: BFLA — funciones administrativas accesibles por rol "user"
/// El atributo [Authorize] solo verifica autenticación, NO el rol admin.
/// Assert objetivo: A06 — DELETE con token de rol "user" debe retornar HTTP 403.
/// </summary>
[ApiController]
[Route("api/v2/admin")]
[Authorize] // VULNERABLE: debería ser [Authorize(Roles = "admin")]
public class AdminController : ControllerBase
{
    private readonly AppDbContext _db;
    public AdminController(AppDbContext db) => _db = db;

    /// <summary>
    /// BFLA VULNERABLE: cualquier usuario autenticado puede eliminar otros usuarios.
    /// FIX: [Authorize(Roles = "admin")]
    /// </summary>
    [HttpDelete("users/{id:int}")]
    public async Task<IActionResult> DeleteUser(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user == null) return NotFound();

        _db.Users.Remove(user);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    [HttpGet("users")]
    public async Task<IActionResult> ListAllUsers()
    {
        // VULNERABLE: cualquier usuario autenticado ve todos los usuarios con sus contraseñas
        var users = await _db.Users.ToListAsync();
        return Ok(users);
    }

    [HttpPost("users/{id:int}/promote")]
    public async Task<IActionResult> PromoteToAdmin(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user == null) return NotFound();

        // BFLA: cualquier usuario autenticado puede promover a otros a admin
        user.Role = "admin";
        user.IsAdmin = true;
        await _db.SaveChangesAsync();
        return Ok(new { message = $"Usuario {id} promovido a admin" });
    }
}
