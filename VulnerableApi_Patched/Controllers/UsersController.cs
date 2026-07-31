using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableApi.Data;
using VulnerableApi.DTOs;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: BOLA, Mass Assignment y exposición de datos sensibles corregidos.
/// - GetUser verifica ownership (FIX G1-V1)
/// - UpdateUser usa DTO limitado — sin Role ni IsAdmin (FIX G1-V3)
/// - Respuestas no incluyen el campo Password (FIX A18)
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _db;
    public UsersController(AppDbContext db) => _db = db;

    /// <summary>
    /// FIX G1-V1: Solo el propietario o admin puede acceder al perfil.
    /// FIX A18: Respuesta sin campo Password.
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetUser(int id)
    {
        var callerId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var isAdmin  = User.IsInRole("admin");

        if (!isAdmin && callerId != id)
            return StatusCode(403, new { error = "Acceso denegado." });

        var user = await _db.Users.FindAsync(id);
        if (user == null) return NotFound();

        // FIX A18: DTO sin Password
        return Ok(new { user.Id, user.Name, user.Email, user.Role });
    }

    [HttpGet("me")]
    public async Task<IActionResult> GetMe()
    {
        var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var user   = await _db.Users.FindAsync(userId);
        if (user == null) return NotFound();

        // FIX A18b: sin Password
        return Ok(new { user.Id, user.Name, user.Email, user.Role });
    }

    /// <summary>
    /// FIX G1-V3 + A05: Solo el propio usuario puede actualizar su perfil.
    /// FIX G1-V3: DTO limitado — Role e IsAdmin NO son modificables por usuarios normales.
    /// </summary>
    [HttpPut("{id:int}")]
    public async Task<IActionResult> UpdateUser(int id, [FromBody] UpdateUserDto dto)
    {
        var callerId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var isAdmin  = User.IsInRole("admin");

        // FIX A05 IDOR: solo el propio usuario puede modificarse
        if (!isAdmin && callerId != id)
            return StatusCode(403, new { error = "Acceso denegado." });

        var existing = await _db.Users.FindAsync(id);
        if (existing == null) return NotFound();

        // FIX G1-V3: solo Name y Email son actualizables; Role e IsAdmin ignorados
        existing.Name  = dto.Name;
        existing.Email = dto.Email;
        // Role y IsAdmin no se tocan

        await _db.SaveChangesAsync();
        // FIX A05: retornar 200 con DTO (sin password) para que la prueba pueda verificar que Role no cambió
        return Ok(new { existing.Id, existing.Name, existing.Email, existing.Role });
    }

    [HttpGet]
    [Authorize(Roles = "admin")]
    public async Task<IActionResult> GetAll()
    {
        var users = await _db.Users
            .Select(u => new { u.Id, u.Name, u.Email, u.Role })
            .ToListAsync();
        return Ok(users);
    }
}


