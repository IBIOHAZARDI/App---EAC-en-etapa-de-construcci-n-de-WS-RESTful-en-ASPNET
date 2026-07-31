using VulnerableApi.Models;

namespace VulnerableApi.Data;

/// <summary>
/// Siembra datos de prueba para el ground truth.
/// Usuarios predefinidos para los asserts del Inyector.
/// </summary>
public static class DataSeeder
{
    public static async Task SeedAsync(AppDbContext db)
    {
        if (db.Users.Any()) return;

        // Contraseñas en texto plano — VULNERABLE G1-V2
        var admin = new User { Name = "Administrador", Email = "admin@test.local", Password = "Admin123!", Role = "admin", IsAdmin = true };
        var userA = new User { Name = "Usuario A", Email = "usera@test.local", Password = "UserA123!", Role = "user", IsAdmin = false };
        var userB = new User { Name = "Usuario B", Email = "userb@test.local", Password = "UserB123!", Role = "user", IsAdmin = false };

        db.Users.AddRange(admin, userA, userB);
        await db.SaveChangesAsync();

        // Órdenes de UserA — usadas en assert A01 (BOLA)
        db.Orders.AddRange(
            new Order { UserId = userA.Id, Description = "Orden confidencial UserA #1", Amount = 1500.00m },
            new Order { UserId = userA.Id, Description = "Orden confidencial UserA #2", Amount = 3200.00m }
        );

        // Órdenes de UserB — UserA NO debe poder verlas (assert A02)
        db.Orders.AddRange(
            new Order { UserId = userB.Id, Description = "Orden privada UserB #1", Amount = 800.00m },
            new Order { UserId = userB.Id, Description = "Orden privada UserB #2", Amount = 4500.00m }
        );

        db.Products.AddRange(
            new Product { Name = "Laptop ProBook", Description = "Laptop empresarial", Price = 3500000m, Category = "Tecnología" },
            new Product { Name = "Monitor UltraWide", Description = "34 pulgadas", Price = 1800000m, Category = "Tecnología" },
            new Product { Name = "Teclado Mecánico", Description = "Cherry MX Blue", Price = 350000m, Category = "Periféricos" }
        );

        await db.SaveChangesAsync();
    }
}
