namespace VulnerableApi.Models;

/// <summary>
/// Modelo de usuario — contiene campos sensibles expuestos intencionalmente.
/// G1-V3 (Mass Assignment): Role e IsAdmin son campos sensibles vinculables vía model binding.
/// </summary>
public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;

    // G1-V2 VULNERABLE: Contraseña en texto plano
    // FIX: Usar BCrypt.HashPassword o ASP.NET Identity PasswordHasher
    public string Password { get; set; } = string.Empty;

    // G1-V3 VULNERABLE: Role e IsAdmin son modificables por mass assignment
    // FIX: Usar UpdateUserDto que NO incluya estos campos
    public string Role { get; set; } = "user"; // "user" | "admin"
    public bool IsAdmin { get; set; } = false;

    public ICollection<Order> Orders { get; set; } = new List<Order>();
}
