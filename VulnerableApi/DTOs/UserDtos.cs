namespace VulnerableApi.DTOs;

public record LoginRequest(string Email, string Password);

public record RegisterRequest(string Name, string Email, string Password);

/// <summary>
/// DTO seguro para actualización de usuario — no incluye Role ni IsAdmin.
/// Usado en el endpoint seguro (demostración de fix para G1-V3).
/// </summary>
public record UpdateUserDto(string Name, string Email);

public record AuthResponse(string Token, string Role, int UserId);
