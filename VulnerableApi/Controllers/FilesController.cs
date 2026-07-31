using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

/// <summary>
/// G3-V3 VULNERABLE: Path Traversal — descarga de archivos sin sanitización de ruta
/// G6-V1 VULNERABLE: Carga de archivos sin validación de tipo, extensión ni tamaño
/// Assert objetivo: A13, A14
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Route("api/v1/[controller]")]
[Authorize]
public class FilesController : ControllerBase
{
    // Directorio base intencionalmente amplio para que el traversal sea efectivo
    private static readonly string BaseDir =
        Path.Combine(Directory.GetCurrentDirectory(), "uploads");

    public FilesController()
    {
        if (!Directory.Exists(BaseDir)) Directory.CreateDirectory(BaseDir);
    }

    /// <summary>
    /// G3-V3 VULNERABLE: Path Traversal — el parámetro 'path' se concatena directamente.
    /// Payload: ?path=../../appsettings.json  → expone cadena de conexión y clave JWT
    /// Payload: ?path=../../Windows/win.ini   → lectura arbitraria de archivos del servidor
    /// Assert A13: path con '../' debe retornar HTTP 400 o 403.
    /// FIX: Path.GetFullPath + validar que el resultado comience por BaseDir
    /// </summary>
    [HttpGet("download")]
    public IActionResult Download([FromQuery] string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest("El parámetro 'path' es requerido.");

        // VULNERABLE: concatenación directa sin normalizar ni validar
        var fullPath = Path.Combine(BaseDir, path);

        // FIX correcto sería:
        // var fullPath = Path.GetFullPath(Path.Combine(BaseDir, path));
        // if (!fullPath.StartsWith(BaseDir, StringComparison.OrdinalIgnoreCase))
        //     return StatusCode(403, "Acceso denegado.");

        if (!System.IO.File.Exists(fullPath))
            return NotFound(new { message = "Archivo no encontrado.", path = fullPath });

        var content = System.IO.File.ReadAllBytes(fullPath);
        var mime = "application/octet-stream";
        return File(content, mime, Path.GetFileName(fullPath));
    }

    /// <summary>
    /// G6-V1 VULNERABLE: Carga de archivos sin validación de tipo ni tamaño.
    /// — Acepta .exe, .aspx, .ps1, .bat (ejecución remota de código potencial)
    /// — Sin límite de tamaño (DoS por disco)
    /// — El nombre de archivo del cliente se usa directamente (Path Traversal en upload)
    /// Assert A14: subir un archivo .exe debe retornar HTTP 400 o 415.
    /// FIX: whitelist de extensiones, validar Content-Type, límite de tamaño
    /// </summary>
    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("Archivo requerido.");

        // VULNERABLE: usa el FileName del cliente directamente (traversal + tipo arbitrario)
        var fileName = file.FileName;

        // FIX correcto:
        // var allowedExtensions = new[] { ".pdf", ".png", ".jpg", ".docx" };
        // var ext = Path.GetExtension(fileName).ToLowerInvariant();
        // if (!allowedExtensions.Contains(ext)) return StatusCode(415, "Tipo de archivo no permitido.");
        // if (file.Length > 5 * 1024 * 1024) return BadRequest("Tamaño máximo 5 MB.");
        // fileName = Guid.NewGuid() + ext; // nombre seguro

        var savePath = Path.Combine(BaseDir, fileName);
        using var stream = System.IO.File.Create(savePath);
        await file.CopyToAsync(stream);

        return Ok(new { message = "Archivo guardado.", path = savePath, size = file.Length });
    }

    [HttpGet("list")]
    public IActionResult List()
    {
        var files = Directory.GetFiles(BaseDir)
            .Select(f => new { name = Path.GetFileName(f), size = new FileInfo(f).Length });
        return Ok(files);
    }
}
