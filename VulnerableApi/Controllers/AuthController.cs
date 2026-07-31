using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using VulnerableApi.Data;
using VulnerableApi.DTOs;

namespace VulnerableApi.Controllers;

/// <summary>
/// G1-V2 VULNERABLE: Broken Authentication
/// — Sin rate limiting en login
/// — Sin bloqueo por intentos fallidos
/// — Token sin tiempo de expiración (G1-V4)
/// — Contraseña comparada en texto plano
/// G5-V2 VULNERABLE: Credenciales registradas en texto plano en los logs
/// Assert objetivo: A03, A04, A07, A11, A17
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Route("api/v1/[controller]")] // G4-V2: v1 activa sin deprecar
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly ILogger<AuthController> _logger;

    public AuthController(AppDbContext db, ILogger<AuthController> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Login — G1-V2 VULNERABLE: sin rate limiting, sin lockout.
    /// Assert objetivo: A07 — 10+ intentos fallidos deben resultar en HTTP 429.
    /// </summary>
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // G5-V2 VULNERABLE: Credenciales en texto plano escritas en el log de la aplicación.
        // Un atacante con acceso a los logs obtiene directamente usuario y contraseña.
        // FIX: nunca registrar credenciales; registrar solo el email y el resultado.
        _logger.LogInformation("LOGIN ATTEMPT — email: {Email} password: {Password}",
            request.Email, request.Password);

        // VULNERABLE: sin throttling, sin registro de intentos fallidos
        // VULNERABLE: comparación de contraseña en texto plano
        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Email == request.Email
                                   && u.Password == request.Password);

        if (user == null)
            return Unauthorized(new { message = "Credenciales inválidas" });

        // G1-V4 VULNERABLE: Token sin expiración (ValidateLifetime = false en Program.cs)
        var token = GenerateToken(user.Id, user.Role);

        return Ok(new AuthResponse(token, user.Role, user.Id));
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (await _db.Users.AnyAsync(u => u.Email == request.Email))
            return Conflict(new { message = "Email ya registrado" });

        // VULNERABLE: sin hash de contraseña
        var user = new Models.User
        {
            Name = request.Name,
            Email = request.Email,
            Password = request.Password
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return CreatedAtAction(nameof(Login), new { id = user.Id });
    }

    private static string GenerateToken(int userId, string role)
    {
        // G1-V4 VULNERABLE: clave débil ("weak-key"), sin issuer/audience, sin expiración
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("weak-key"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Role, role)
        };

        var token = new JwtSecurityToken(
            claims: claims,
            signingCredentials: creds
            // SIN expires: token nunca vence
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
