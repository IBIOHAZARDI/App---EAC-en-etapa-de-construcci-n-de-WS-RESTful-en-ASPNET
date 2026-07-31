using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using VulnerableApi.Data;
using VulnerableApi.Models;

namespace VulnerableApi.Controllers;

/// <summary>
/// G1-V1 VULNERABLE: BOLA — sin validación de ownership
/// G1-V3 VULNERABLE: Mass Assignment — model binding directo al modelo User
/// Assert objetivo: A01, A03, A04, A05, A11
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Route("api/v1/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly AppDbContext _db;
    public UsersController(AppDbContext db) => _db = db;

    /// <summary>
    /// G1-V1 VULNERABLE: Retorna cualquier usuario por ID sin verificar ownership.
    /// Assert A01: GET /api/v2/users/{id_ajeno} debe retornar HTTP 403 o 404.
    /// </summary>
    [HttpGet("{id:int}")]
    public async Task<IActionResult> GetUser(int id)
    {
        // VULNERABLE: cualquier usuario autenticado puede consultar cualquier usuario
        // FIX: verificar que id == userId del token
        var user = await _db.Users.FindAsync(id);
        if (user == null) return NotFound();

        // VULNERABLE: retorna todos los campos incluyendo Password
        // FIX: retornar un UserDto sin Password
        return Ok(user);
    }

    [HttpGet("me")]
    public async Task<IActionResult> GetMe()
    {
        var userId = int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var user = await _db.Users.FindAsync(userId);
        return user == null ? NotFound() : Ok(user);
    }

    /// <summary>
    /// G1-V3 VULNERABLE: Mass Assignment — model binding vincula Role e IsAdmin.
    /// Assert A05: PUT con {"role":"admin"} NO debe modificar el campo Role.
    /// </summary>
    [HttpPut("{id:int}")]
    public async Task<IActionResult> UpdateUser(int id, [FromBody] User user)
    {
        // VULNERABLE: acepta todos los campos del modelo incluyendo Role e IsAdmin
        // FIX: usar UpdateUserDto que solo exponga Name y Email
        var existing = await _db.Users.FindAsync(id);
        if (existing == null) return NotFound();

        existing.Name = user.Name;
        existing.Email = user.Email;
        existing.Role = user.Role;       // VULNERABLE: rol modificable
        existing.IsAdmin = user.IsAdmin; // VULNERABLE: IsAdmin modificable

        await _db.SaveChangesAsync();
        return NoContent();
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        // G2-V5 VULNERABLE: Sin paginación — puede retornar tabla completa
        // Assert B08: debe haber paginación obligatoria
        var users = await _db.Users.ToListAsync();
        return Ok(users);
    }
}
