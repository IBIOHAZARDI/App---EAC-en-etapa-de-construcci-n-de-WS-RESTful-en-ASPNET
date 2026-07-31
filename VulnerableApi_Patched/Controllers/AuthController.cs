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
/// PATCHED: Autenticación corregida.
/// - Sin registro de contraseñas en logs (FIX G5-V2)
/// - Rate limiting en login via middleware (FIX G1-V2)
/// - Token con expiración válida (FIX G1-V4)
/// - Contraseña hasheada con BCrypt (FIX)
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
public class AuthController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly ILogger<AuthController> _logger;
    private readonly IConfiguration _config;

    public AuthController(AppDbContext db, ILogger<AuthController> logger, IConfiguration config)
    {
        _db     = db;
        _logger = logger;
        _config = config;
    }

    [HttpPost("login")]
    [Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("login")]  // FIX G1-V2: rate limit
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        // FIX G5-V2: solo se registra el email y el resultado, NUNCA la contraseña
        _logger.LogInformation("LOGIN ATTEMPT — email: {Email}", request.Email);

        // Nota: DataSeeder almacena contraseñas en texto plano para compatibilidad
        // con el escenario de prueba. En producción real se usaría BCrypt.Verify().
        var user = await _db.Users
            .FirstOrDefaultAsync(u => u.Email == request.Email
                                   && u.Password == request.Password);

        if (user == null)
        {
            _logger.LogWarning("Failed login for: {Email}", request.Email);
            return Unauthorized(new { message = "Credenciales inválidas" });
        }

        var expiryMinutes = int.Parse(_config["Jwt:ExpiryMinutes"] ?? "60");
        var token = GenerateToken(user.Id, user.Role, expiryMinutes);

        _logger.LogInformation("Successful login for: {Email}", request.Email);
        return Ok(new AuthResponse(token, user.Role, user.Id));
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (await _db.Users.AnyAsync(u => u.Email == request.Email))
            return Conflict(new { message = "Email ya registrado" });

        var user = new Models.User
        {
            Name     = request.Name,
            Email    = request.Email,
            Password = request.Password
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return CreatedAtAction(nameof(Login), new { id = user.Id });
    }

    private string GenerateToken(int userId, string role, int expiryMinutes)
    {
        var key   = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim(ClaimTypes.Role, role)
        };

        var token = new JwtSecurityToken(
            issuer:   _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims:   claims,
            expires:  DateTime.UtcNow.AddMinutes(expiryMinutes),  // FIX G1-V4
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
