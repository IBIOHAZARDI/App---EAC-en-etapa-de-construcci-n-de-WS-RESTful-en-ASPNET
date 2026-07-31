using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace VulnerableApi.Controllers;

/// <summary>
/// PATCHED: Path Traversal y File Upload corregidos.
/// - Download valida que la ruta resultante esté dentro de BaseDir (FIX G3-V3)
/// - Upload restringe extensiones a una whitelist (FIX G6-V1)
/// </summary>
[ApiController]
[Route("api/v2/[controller]")]
[Authorize]
public class FilesController : ControllerBase
{
    private static readonly string BaseDir =
        Path.Combine(Directory.GetCurrentDirectory(), "uploads");

    private static readonly string[] AllowedExtensions =
        { ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".docx", ".txt" };

    private const long MaxFileSizeBytes = 5 * 1024 * 1024; // 5 MB

    public FilesController()
    {
        if (!Directory.Exists(BaseDir)) Directory.CreateDirectory(BaseDir);
    }

    /// <summary>
    /// FIX G3-V3: Path Traversal — valida que el path final esté dentro de BaseDir.
    /// </summary>
    [HttpGet("download")]
    public IActionResult Download([FromQuery] string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return BadRequest("El parámetro 'path' es requerido.");

        // FIX: normalizar la ruta y verificar que comienza con BaseDir
        var fullPath = Path.GetFullPath(Path.Combine(BaseDir, path));
        if (!fullPath.StartsWith(BaseDir + Path.DirectorySeparatorChar,
                                  StringComparison.OrdinalIgnoreCase)
            && !fullPath.Equals(BaseDir, StringComparison.OrdinalIgnoreCase))
        {
            return StatusCode(403, new { error = "Acceso denegado: ruta fuera del directorio permitido." });
        }

        if (!System.IO.File.Exists(fullPath))
            return NotFound(new { message = "Archivo no encontrado." });

        var content = System.IO.File.ReadAllBytes(fullPath);
        return File(content, "application/octet-stream", Path.GetFileName(fullPath));
    }

    /// <summary>
    /// FIX G6-V1: Solo extensiones permitidas, límite de tamaño, nombre generado por servidor.
    /// </summary>
    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        if (file == null || file.Length == 0)
            return BadRequest("Archivo requerido.");

        // FIX A14c: rechazar nombres de archivo con path traversal
        var originalName = file.FileName ?? "";
        if (originalName.Contains("..") || originalName.Contains('/') || originalName.Contains('\\'))
            return BadRequest(new { error = "Nombre de archivo no permitido." });

        // FIX: validar extensión
        var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
        if (!AllowedExtensions.Contains(ext))
            return StatusCode(415, new { error = "Tipo de archivo no permitido.", allowed = AllowedExtensions });

        // FIX: validar tamaño
        if (file.Length > MaxFileSizeBytes)
            return BadRequest(new { error = "Tamaño máximo excedido (5 MB)." });

        // FIX: nombre seguro generado por el servidor
        var safeName = Guid.NewGuid().ToString("N") + ext;
        var savePath = Path.Combine(BaseDir, safeName);

        using var stream = System.IO.File.Create(savePath);
        await file.CopyToAsync(stream);

        return Ok(new { message = "Archivo guardado.", size = file.Length });
    }

    [HttpGet("list")]
    public IActionResult List()
    {
        var files = Directory.GetFiles(BaseDir)
            .Select(f => new { name = Path.GetFileName(f), size = new FileInfo(f).Length });
        return Ok(files);
    }
}
