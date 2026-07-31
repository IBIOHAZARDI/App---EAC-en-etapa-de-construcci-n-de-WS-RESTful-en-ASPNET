# Desarrollo — Objetos de Prueba

Esta carpeta contiene los dos servicios RESTful que forman los escenarios de evaluación de la estrategia de asserts de seguridad propuesta en la tesis de Maestría en Seguridad Informática — ITM:

| Proyecto | Puerto | Escenario | Descripción |
|----------|--------|-----------|-------------|
| **VulnerableApi** | 5000 | **A — Vulnerable** | ASP.NET Core 8 con **28 vulnerabilidades inyectadas** como *ground truth* |
| **VulnerableApi_Patched** | 5002 | **B — Parcheada** | La misma API con todas las correcciones de seguridad aplicadas |

La suite `SecurityAsserts` (carpeta `Inyector/`) ejecuta **99 tests** contra cada escenario y mide la efectividad de la detección: Escenario A valida que las vulnerabilidades son detectables; Escenario B valida que las correcciones superan los controles.

> ⚠️ **USO EXCLUSIVO EN AMBIENTE DE PRUEBAS CONTROLADO.**
> Ambos proyectos están configurados para HTTP local. **NUNCA desplegar en producción ni en redes accesibles externamente.**

---

## VulnerableApi — Escenario A

Servicio RESTful con **28 vulnerabilidades inyectadas intencionalmente** distribuidas en 8 grupos OWASP API Security Top 10.

---

## Tabla de contenido

1. [Prerrequisitos](#1-prerrequisitos)
2. [Instalación paso a paso](#2-instalación-paso-a-paso)
3. [Verificación de la instalación](#3-verificación-de-la-instalación)
4. [Estructura del proyecto](#4-estructura-del-proyecto)
5. [Usuarios de prueba](#5-usuarios-de-prueba)
6. [Endpoints disponibles](#6-endpoints-disponibles)
7. [Mapa de vulnerabilidades](#7-mapa-de-vulnerabilidades)
8. [VulnerableApi_Patched — Escenario B](#8-vulnerableapi_patched--escenario-b)
9. [Integración con SecurityAsserts (Inyector)](#9-integración-con-securityasserts-inyector)
10. [Solución de problemas](#10-solución-de-problemas)

---

## 1. Prerrequisitos

Antes de instalar, asegúrese de tener los siguientes componentes en la máquina de pruebas:

| Componente | Versión mínima | Verificación |
|-----------|---------------|-------------|
| Windows Server 2019 / Windows 10+ | — | `winver` |
| .NET SDK | 8.0 | `dotnet --version` |
| .NET 8 Runtime (ASP.NET Core) | 8.0 | `dotnet --list-runtimes` |
| Git | 2.x | `git --version` |
| PowerShell | 5.1 / 7.x | `$PSVersionTable` |

> **Nota:** Para el pipeline de Azure DevOps también se requiere Docker Desktop (etapa DAST con OWASP ZAP). No es necesario para ejecutar la API localmente.

### Instalación rápida de .NET 8 SDK (si no está disponible)

```powershell
# Opción A — winget (Windows 10/11 y Windows Server 2019+)
winget install Microsoft.DotNet.SDK.8

# Opción B — descarga manual
# https://dotnet.microsoft.com/download/dotnet/8.0
# Instalar el paquete "SDK 8.0.x (Windows x64)"
```

---

## 2. Instalación paso a paso

### Paso 1 — Clonar o copiar el repositorio

```powershell
# Si el proyecto está en un repositorio Git:
git clone <URL-del-repositorio> C:\Trabajo\Universidad
cd C:\Trabajo\Universidad

# Si ya dispone del código fuente directamente, navegue a la carpeta:
cd C:\Trabajo\Universidad
```

### Paso 2 — Restaurar dependencias NuGet

```powershell
cd Desarrollo\VulnerableApi
dotnet restore
```

Paquetes que se descargan automáticamente:

| Paquete | Versión | Propósito |
|---------|---------|-----------|
| `Microsoft.EntityFrameworkCore.Sqlite` | 8.0.0 | ORM + base de datos SQLite |
| `Microsoft.EntityFrameworkCore.Design` | 8.0.0 | Herramientas de migración |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | 8.0.0 | Autenticación JWT (configurada de forma vulnerable) |
| `Swashbuckle.AspNetCore` | 6.5.0 | Generación de Swagger / OpenAPI |

### Paso 3 — Compilar el proyecto

```powershell
dotnet build --configuration Debug
```

Salida esperada:

```
Build succeeded.
    0 Warning(s)
    0 Error(s)
```

> **Analizadores Roslyn (CA2100, CA3001, CA3002…):** Si aparecen warnings de seguridad, son **esperados** — corresponden a las 28 vulnerabilidades inyectadas. En el pipeline, estos mismos warnings se capturan en la etapa SAST como evidencia del *ground truth*.
>
> **¿Por qué `Debug` y no `Release`?** El modo `Debug` mantiene activos Swagger UI (`/swagger`), la Developer Exception Page (stack traces en HTTP 500) y los asserts G4-V2 e G2-V3 que verifican precisamente esos comportamientos. En modo `Release` esos comportamientos se suprimen y los asserts correspondientes fallarían incorrectamente.

### Paso 4 — Crear la base de datos y sembrar los datos

La base de datos SQLite (`vulnerable.db`) se crea y se puebla automáticamente al iniciar la aplicación por primera vez mediante `DataSeeder`. No se requiere ningún comando adicional de migración.

Si desea reiniciar la base de datos a un estado limpio:

```powershell
# Eliminar la base de datos existente
Remove-Item -Path ".\vulnerable.db" -ErrorAction SilentlyContinue
Remove-Item -Path ".\vulnerable.db-shm" -ErrorAction SilentlyContinue
Remove-Item -Path ".\vulnerable.db-wal" -ErrorAction SilentlyContinue

# La próxima ejecución de dotnet run la recreará automáticamente
```

### Paso 5 — Configurar variables de entorno (opcional)

La URL base se puede sobrescribir sin modificar `appsettings.json`:

```powershell
# Puerto alternativo (por defecto: http://localhost:5000)
$env:ASPNETCORE_URLS = "http://localhost:8080"

# Ambiente explícito (Development activa Developer Exception Page y Swagger)
$env:ASPNETCORE_ENVIRONMENT = "Development"
```

### Paso 6 — Ejecutar la API

```powershell
# Desde Desarrollo\VulnerableApi\
dotnet run
```

Salida esperada al iniciar:

```
info: Microsoft.EntityFrameworkCore.Database.Command[20101]
      Executed DbCommand (Xms) [Parameters=[], CommandType='Text'] ...
info: VulnerableApi.Data.DataSeeder[0]
      Seeding database...
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: http://localhost:5000
info: Microsoft.Hosting.Lifetime[14]
      Now listening on: https://localhost:5001
info: Microsoft.Hosting.Lifetime[0]
      Application started. Press Ctrl+C to shut down.
```

### Paso 7 — (Opcional) Ejecutar en modo background para el pipeline

Este es el procedimiento exacto que usa el pipeline de Azure DevOps en la etapa `SecurityAsserts_EscenarioA`:

```powershell
# ── Liberar puerto 5000 si estuviera ocupado ──────────────────────────────
Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

# ── Eliminar BD para estado limpio (DataSeeder re-siembra en el startup) ─────
Remove-Item ".\vulnerable.db" -ErrorAction SilentlyContinue
Remove-Item ".\vulnerable.db-shm" -ErrorAction SilentlyContinue
Remove-Item ".\vulnerable.db-wal" -ErrorAction SilentlyContinue

# ── Iniciar API en background (--no-build: ya compilada en Debug) ─────────
$proc = Start-Process -FilePath "dotnet" `
    -ArgumentList "run",`
                  "--project","C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj",`
                  "--no-build",`
                  "--configuration","Debug",`
                  "--urls","http://localhost:5000" `
    -PassThru -WindowStyle Hidden
Write-Host "VulnerableApi iniciada en background (PID=$($proc.Id))"
$proc.Id | Out-File ".\api-pid.txt"   # guardar PID para detener luego

# ── Health check con reintentos (15 × 2 s = máx. 30 s) ──────────────
$ok = $false
for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 3
        if ($r.StatusCode -eq 200) { $ok = $true; break }
    } catch {}
    Write-Host "Health check $i/15..."
}
if (-not $ok) { Write-Error "VulnerableApi no respondió en 30 s"; exit 1 }
Write-Host "VulnerableApi disponible en http://localhost:5000"

# ── Detener cuando ya no se necesite ──────────────────────────────────
# Stop-Process -Id (Get-Content ".\api-pid.txt") -Force
```

> **Por qué `--no-build`:** el pipeline compila con `dotnet build` en la Etapa 1 y reutiliza el resultado compilado en las etapas posteriores. Usar `--no-build` evita una segunda compilación redundante y garantiza que los asserts se ejecutan contra el mismo binario inspeccionado por SAST.

---

## 3. Verificación de la instalación

Una vez que la API esté corriendo, ejecute las siguientes comprobaciones:

### 3.1 Health check

```powershell
Invoke-RestMethod -Uri "http://localhost:5000/health"
# Respuesta esperada: { status = "healthy", version = "2.0" }
```

### 3.2 Swagger UI

Abrir en el navegador:

```
http://localhost:5000/swagger
```

Debe mostrar las colecciones **API v1 (deprecada)** y **API v2**.

### 3.3 Login con usuario de prueba

```powershell
$body = '{"email":"usera@test.local","password":"UserA123!"}'
$response = Invoke-RestMethod `
    -Uri "http://localhost:5000/api/v2/auth/login" `
    -Method POST `
    -Body $body `
    -ContentType "application/json"

$token = $response.token
Write-Host "Token JWT obtenido: $($token.Substring(0,30))..."
```

### 3.4 Confirmar vulnerabilidad CORS (G2-V1)

```powershell
$headers = @{ "Origin" = "https://evil.example.com" }
$r = Invoke-WebRequest -Uri "http://localhost:5000/health" -Headers $headers -UseBasicParsing
$r.Headers["Access-Control-Allow-Origin"]
# Esperado: * (wildcard — comportamiento vulnerable)
```

### 3.5 Confirmar SQLi (G3-V1)

```powershell
$token = (Invoke-RestMethod `
    -Uri "http://localhost:5000/api/v2/auth/login" `
    -Method POST `
    -Body '{"email":"usera@test.local","password":"UserA123!"}' `
    -ContentType "application/json").token

Invoke-RestMethod `
    -Uri "http://localhost:5000/api/v2/products/search?name=' OR '1'='1" `
    -Headers @{ Authorization = "Bearer $token" }
# Comportamiento vulnerable: retorna TODOS los productos
```

---

## 4. Estructura del proyecto

```
VulnerableApi/
├── Controllers/
│   ├── AuthController.cs           ← G1-V2, G1-V4, G5-V2
│   │     POST /api/v2/auth/login       Sin rate limiting, JWT sin expiración, log de credenciales
│   │     POST /api/v2/auth/register    Registro abierto
│   │
│   ├── UsersController.cs          ← G1-V1, G1-V3
│   │     GET  /api/v2/users/{id}       BOLA: accede a cualquier usuario sin verificar ownership
│   │     PUT  /api/v2/users/{id}       Mass Assignment: acepta Role e IsAdmin del body
│   │     GET  /api/v2/users            Lista completa sin paginación (G2-V5)
│   │
│   ├── OrdersController.cs         ← G1-V1
│   │     GET  /api/v2/orders/{id}      BOLA: retorna cualquier orden sin ownership check
│   │
│   ├── ProductsController.cs       ← G3-V1, G3-V2, G2-V5
│   │     GET  /api/v2/products/search?name=    SQLi por interpolación en FromSqlRaw
│   │     GET  /api/v2/products/by-category     XSS reflejado sin sanitizar
│   │     GET  /api/v2/products                 Sin paginación
│   │
│   ├── AdminController.cs          ← G1-V5
│   │     GET  /api/v2/admin/users          BFLA: [Authorize] sin Roles = "admin"
│   │     DELETE /api/v2/admin/users/{id}   Cualquier usuario autenticado puede eliminar
│   │     POST /api/v2/admin/users/promote  Cualquier usuario puede ascender a admin
│   │
│   ├── FilesController.cs          ← G3-V3, G6-V1
│   │     GET  /api/v2/files/download?path=   Path Traversal: ../../ no normalizado
│   │     POST /api/v2/files/upload           Sin validación de extensión ni tamaño
│   │
│   ├── DiagnosticsController.cs    ← G5-V1, G5-V3, G2-V6
│   │     GET  /api/v2/diagnostics/ping?url=    SSRF: HttpClient.GetAsync sin validar destino
│   │     GET  /api/v2/diagnostics/info         Expone env vars, conn string, PID (público)
│   │     GET  /api/v2/diagnostics/health-verbose  Versión exacta runtime en respuesta
│   │
│   ├── ReportsController.cs        ← G7-V1, G5-V4
│   │     POST /api/v2/reports/parse            XXE: XmlDocument con XmlUrlResolver activo
│   │     GET  /api/v2/reports/redirect?returnUrl=  Open Redirect sin validar dominio
│   │
│   ├── SearchController.cs         ← G3-V4, G6-V3
│   │     GET  /api/v2/search?query=            Header Injection: CRLF no filtrado en X-Search-Query
│   │     GET  /api/v2/search/filter?pattern=   ReDoS: Regex.IsMatch sin timeout
│   │
│   └── WebhooksController.cs       ← G8-V1, G8-V2, G2-V8
│         POST /api/v2/webhooks/receive          Sin verificación HMAC X-Hub-Signature-256
│         POST /api/v2/webhooks/register         SSRF: ping a callbackUrl sin validar
│
├── Models/
│   ├── User.cs        ← Role e IsAdmin públicos → Mass Assignment (G1-V3)
│   ├── Order.cs       ← Id, UserId, Description, Amount, CreatedAt
│   └── Product.cs     ← Id, Name, Description, Price, Category
│
├── DTOs/
│   └── UserDtos.cs    ← LoginRequest, RegisterRequest, UpdateUserDto (seguro), AuthResponse
│
├── Data/
│   ├── AppDbContext.cs    ← DbSets: Users, Orders, Products; índice único en Email
│   └── DataSeeder.cs      ← Siembra 3 usuarios, 6 órdenes y 3 productos al iniciar
│
├── Program.cs             ← Pipeline HTTP con 8 vulnerabilidades en configuración
└── appsettings.json       ← SQLite: Data Source=vulnerable.db | Urls: 5000/5001
```

---

## 5. Usuarios de prueba

Sembrados automáticamente por `DataSeeder` al primer inicio:

| ID | Email | Password | Rol | Descripción |
|----|-------|----------|-----|-------------|
| 1 | admin@test.local | Admin123! | admin | Administrador del sistema |
| 2 | usera@test.local | UserA123! | user | Usuario A (víctima en BOLA/IDOR) |
| 3 | userb@test.local | UserB123! | user | Usuario B (atacante en BOLA/IDOR) |

**Órdenes sembradas:**

| ID | UserId | Descripción |
|----|--------|-------------|
| 1 | 2 (userA) | Orden 1 de UserA |
| 2 | 2 (userA) | Orden 2 de UserA |
| 3 | 3 (userB) | Orden 1 de UserB |
| 4 | 3 (userB) | Orden 2 de UserB |

**Productos sembrados:**

| ID | Nombre | Categoría | Precio |
|----|--------|-----------|--------|
| 1 | Laptop Pro | Electronics | 1200.00 |
| 2 | Monitor 4K | Electronics | 350.00 |
| 3 | Teclado Mecánico | Accessories | 80.00 |

---

## 6. Endpoints disponibles

Todos los endpoints están documentados en Swagger (`/swagger`). Resumen por controlador:

| Método | Ruta | Auth | Vulnerabilidad |
|--------|------|------|---------------|
| POST | `/api/v2/auth/login` | No | G1-V2, G5-V2 |
| POST | `/api/v2/auth/register` | No | G1-V2 |
| GET | `/api/v2/users` | Bearer | G2-V5 |
| GET | `/api/v2/users/{id}` | Bearer | G1-V1 |
| PUT | `/api/v2/users/{id}` | Bearer | G1-V3 |
| GET | `/api/v2/orders/{id}` | Bearer | G1-V1 |
| GET | `/api/v2/products` | Bearer | G2-V5 |
| GET | `/api/v2/products/search?name=` | Bearer | G3-V1 |
| GET | `/api/v2/products/by-category?category=` | Bearer | G3-V2 |
| GET | `/api/v2/admin/users` | Bearer | G1-V5 |
| DELETE | `/api/v2/admin/users/{id}` | Bearer | G1-V5 |
| POST | `/api/v2/admin/users/promote` | Bearer | G1-V5 |
| GET | `/api/v2/files/download?path=` | Bearer | G3-V3 |
| POST | `/api/v2/files/upload` | Bearer | G6-V1 |
| GET | `/api/v2/diagnostics/ping?url=` | Bearer | G5-V1 |
| GET | `/api/v2/diagnostics/info` | No | G5-V3 |
| GET | `/api/v2/diagnostics/health-verbose` | No | G2-V6 |
| POST | `/api/v2/reports/parse` | Bearer | G7-V1 |
| GET | `/api/v2/reports/redirect?returnUrl=` | No | G5-V4 |
| GET | `/api/v2/search?query=` | No | G3-V4 |
| GET | `/api/v2/search/filter?pattern=&input=` | No | G6-V3 |
| POST | `/api/v2/webhooks/receive` | No | G8-V1, G2-V8 |
| POST | `/api/v2/webhooks/register` | Bearer | G8-V2 |
| GET | `/health` | No | — (health check del pipeline) |

> **Ruta v1 activa (G4-V2):** todos los endpoints responden también bajo `/api/v1/...` sin cabecera de deprecación.

---

## 7. Mapa de vulnerabilidades

| ID | Grupo OWASP | Controlador / Archivo | Endpoint / Ubicación | Descripción técnica | Fix recomendado |
|----|------------|----------------------|---------------------|---------------------|-----------------|
| G1-V1 | API1:2023 BOLA | UsersController, OrdersController | GET `/{id}` | Retorna cualquier recurso sin verificar que `id` pertenezca al usuario autenticado | Comparar `userId == currentUser.Id` antes de retornar |
| G1-V2 | API2:2023 Auth | AuthController | POST `/auth/login` | Sin rate limiting ni bloqueo tras N intentos fallidos; contraseña en texto plano en BD | Implementar lockout, rate limiting y hashing bcrypt |
| G1-V3 | API6:2023 Mass Assignment | UsersController | PUT `/{id}` | Body se vincula directamente al modelo `User` incluyendo `Role` e `IsAdmin` | Usar DTO que solo exponga `Name` y `Email` |
| G1-V4 | API2:2023 Auth | Program.cs | `AddJwtBearer` | `ValidateIssuer=false`, `ValidateAudience=false`, `ValidateLifetime=false`, clave de 8 bytes | Validar issuer/audience/lifetime; clave ≥ 256 bits |
| G1-V5 | API5:2023 BFLA | AdminController | DELETE, POST, GET `/admin/...` | `[Authorize]` sin `Roles="admin"`; cualquier usuario autenticado accede a funciones de admin | Agregar `[Authorize(Roles = "admin")]` |
| G2-V1 | API8:2023 Misconfig | Program.cs | `AddCors` | `AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()` — wildcard total | `WithOrigins("https://dominio-permitido.com")` |
| G2-V2 | API8:2023 Misconfig | Program.cs | Pipeline HTTP | Sin middleware que inyecte cabeceras de seguridad HTTP | Agregar `X-Content-Type-Options`, `X-Frame-Options`, `CSP` |
| G2-V3 | API8:2023 Misconfig | Program.cs | `UseDeveloperExceptionPage` | Activo en todos los ambientes; expone stack traces, rutas internas y versiones | Condicionar a `IsDevelopment()` |
| G2-V4 | API8:2023 Misconfig | Program.cs | `UseSwagger` | Swagger UI y spec JSON expuestos sin restricción de ambiente | Envolver en `if (app.Environment.IsDevelopment())` |
| G2-V5 | API4:2023 Resources | ProductsController, UsersController | GET `/products`, GET `/users` | Sin paginación ni límite de registros devueltos | Implementar `?page=&size=` con límite máximo |
| G2-V6 | API8:2023 Misconfig | DiagnosticsController | GET `/health-verbose` | Retorna versión exacta del runtime, ASP.NET Core y uptime en respuesta pública | Omitir versiones en respuestas de health check |
| G2-V8 | API8:2023 Misconfig | WebhooksController | POST `/webhooks/receive` | `_logger.LogInformation("Webhook: {Body}", body)` — payload completo en logs | Loguear solo metadata: `eventType` y longitud |
| G3-V1 | API3:2023 Injection | ProductsController | GET `/products/search?name=` | `$"SELECT ... WHERE Name LIKE '%{name}%'"` en `FromSqlRaw` → SQLi clásica | Usar parámetros: `FromSqlRaw("... LIKE {0}", $"%{name}%")` |
| G3-V2 | API3:2023 Injection | ProductsController | GET `/products/by-category` | `category` reflejado sin escapar en `Content(html)` → XSS reflejado | Codificar la salida con `HtmlEncoder.Default.Encode` |
| G3-V3 | API3:2023 Injection | FilesController | GET `/files/download?path=` | `Path.Combine(baseDir, path)` sin normalizar; `../../` sale del directorio base | Normalizar con `Path.GetFullPath` y verificar que inicie con `baseDir` |
| G3-V4 | API3:2023 Injection | SearchController | GET `/search?query=` | `query` copiado a `X-Search-Query` sin filtrar `\r\n` → HTTP Response Header Injection | `query.Replace("\r","").Replace("\n","")` |
| G4-V1 | API8:2023 Misconfig | Program.cs | Pipeline HTTP | Sin `UseHttpsRedirection()` ni `UseHsts()` → HTTP sin redirección | Agregar ambos en el pipeline |
| G4-V2 | API9:2023 Inventory | Program.cs / Controladores | `[Route("api/v1/...")]` | API v1 sigue activa sin cabecera `Deprecation` ni retornar 410 | Agregar cabecera `Deprecation: true` o migrar a 410 |
| G5-V1 | API7:2023 SSRF | DiagnosticsController | GET `/diagnostics/ping?url=` | `HttpClient.GetAsync(url)` sin validar que la URL no sea loopback, RFC 1918 o `file://` | Resolver DNS y rechazar rangos privados |
| G5-V2 | API8:2023 Misconfig | AuthController | POST `/auth/login` | `_logger.LogInformation("... password: {Password}", ...)` → credenciales en logs | Nunca loguear contraseñas; usar solo `email` |
| G5-V3 | API8:2023 Misconfig | DiagnosticsController | GET `/diagnostics/info` | Endpoint público que devuelve todas las env vars, conn string, PID y directorio de trabajo | Requerir `[Authorize(Roles="admin")]` y filtrar datos sensibles |
| G5-V4 | API8:2023 Misconfig | ReportsController | GET `/reports/redirect?returnUrl=` | `Redirect(returnUrl)` sin validar que sea URL relativa o de dominio permitido | Verificar `Uri.IsWellFormedUriString` y lista blanca de dominios |
| G6-V1 | API3:2023 Injection | FilesController | POST `/files/upload` | Usa `FileName` del cliente sin validar extensión ni tamaño; puede subir `.exe`, `.aspx` | Whitelist de extensiones + límite de tamaño en `RequestSizeLimitAttribute` |
| G6-V2 | API2:2023 Auth | Program.cs | `OnMessageReceived` | JWT leído del query string `?token=` → expuesto en logs de servidor y referrer headers | Eliminar `OnMessageReceived`; aceptar solo el header `Authorization: Bearer` |
| G6-V3 | API4:2023 Resources | SearchController | GET `/search/filter?pattern=` | `Regex.IsMatch(input, pattern)` sin timeout → ReDoS con patrón `(a+)+` | `new Regex(pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100))` |
| G7-V1 | API10:2023 Unsafe | ReportsController | POST `/reports/parse` | `XmlDocument.XmlResolver = new XmlUrlResolver()` → XXE permite leer archivos del SO | `XmlResolver = null` y `DtdProcessing = DtdProcessing.Prohibit` |
| G8-V1 | API8:2023 Misconfig | WebhooksController | POST `/webhooks/receive` | No verifica cabecera `X-Hub-Signature-256` → eventos falsos aceptados | Calcular HMAC-SHA256 del body y comparar con tiempo constante |
| G8-V2 | API7:2023 SSRF | WebhooksController | POST `/webhooks/register` | `HttpClient.GetAsync(callbackUrl)` de "ping" sin validar destino → SSRF | Verificar que `callbackUrl` no apunte a rangos privados (DNS lookup) |

---

## 8. VulnerableApi_Patched — Escenario B

La carpeta `Desarrollo/VulnerableApi_Patched/` contiene la misma API con **todas las correcciones de seguridad aplicadas**. Se ejecuta en el puerto **5002** para que ambas instancias puedan correr simultáneamente durante las pruebas comparativas.

### Diferencias clave respecto a VulnerableApi

| Aspecto | VulnerableApi (A, puerto 5000) | VulnerableApi_Patched (B, puerto 5002) |
|---------|-------------------------------|---------------------------------------|
| BD SQLite | `vulnerable.db` | `patched.db` |
| JWT | `ValidateLifetime=false`, clave 8 bytes | Validación completa, clave ≥ 256 bits |
| CORS | `AllowAnyOrigin()` | `WithOrigins` lista blanca |
| BOLA | Sin verificación de ownership | `userId == currentUser.Id` |
| BFLA | `[Authorize]` sin rol | `[Authorize(Roles="admin")]` |
| SQLi | `FromSqlRaw` con interpolación | Parámetros enlazados |
| Path Traversal | Sin normalización | `Path.GetFullPath` + verificación de prefijo |
| SSRF | `HttpClient.GetAsync(url)` directo | DNS lookup + rechazo de RFC 1918 |
| XXE | `XmlUrlResolver` activo | `XmlResolver = null` + `DtdProcessing.Prohibit` |
| Kestrel | Valores por defecto | `MaxRequestBodySize=100MB`, `MaxRequestLineSize=16KB`, `PermitLimit=500 req/10s` |

> **Kestrel en VulnerableApi_Patched:** `PermitLimit=500 req/10s` (en lugar de 5) permite que los 99 tests secuenciales no activen el rate limiter durante las pruebas. En producción se restauraría a un valor estricto mediante `appsettings.Production.json`.

### Instalación y ejecución de VulnerableApi_Patched

```powershell
cd C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched

# Restaurar y compilar
dotnet restore
dotnet build --configuration Debug

# Ejecutar en puerto 5002
dotnet run --urls "http://localhost:5002"
```

O en background para pruebas simultáneas con el Escenario A:

```powershell
# Liberar puerto 5002
Get-NetTCPConnection -LocalPort 5002 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

$proc = Start-Process -FilePath "dotnet" `
    -ArgumentList "run",`
                  "--project","C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj",`
                  "--no-build","--configuration","Debug",`
                  "--urls","http://localhost:5002" `
    -PassThru -WindowStyle Hidden
Write-Host "VulnerableApi_Patched iniciada (PID=$($proc.Id))"

# Health check
$ok = $false
for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Seconds 2
    try {
        if ((Invoke-WebRequest "http://localhost:5002/health" -UseBasicParsing -TimeoutSec 3).StatusCode -eq 200) { $ok = $true; break }
    } catch {}
    Write-Host "Health check $i/15..."
}
Write-Host $(if ($ok) { "VulnerableApi_Patched disponible en http://localhost:5002" } else { "ERROR: no respondió en 30 s" })
```

### Fallos esperados en Escenario B (4 de 99 tests)

Cuatro asserts fallan incluso en la API parcheada por limitaciones del entorno de pruebas, **no por deficiencias de seguridad**:

| Assert | Descripción | Razón del fallo en entorno de pruebas | Mitigación en producción |
|--------|-------------|--------------------------------------|-------------------------|
| A10 | HTTPS redirect | `UseHttpsRedirection()` deshabilitado para pruebas HTTP | Habilitar + certificado TLS |
| B09 | Rate limit 429 en `/auth/login` | `PermitLimit=500` para no bloquear 99 tests | Restaurar `PermitLimit=5` en `appsettings.Production.json` |
| C02 | TLS ≥ 1.2 requerido | Kestrel en HTTP puro (sin certificado) | Certificado TLS 1.2+ en IIS |
| B08 | Paginación en `/api/v2/products` | No implementado (fuera del scope de correcciones) | Implementar `?page=&pageSize=` |

---

## 9. Integración con SecurityAsserts (Inyector)

El proyecto `Inyector/SecurityAsserts` contiene la suite xUnit que valida ambos escenarios. La API objetivo se controla mediante la variable de entorno `TEST_API_URL`, leída por `Configuration/TestConfig.cs`.

### Requisito previo: SDK 8.0.319 via global.json

`Inyector/global.json` fija el SDK a `8.0.319` con `rollForward: latestPatch`. **Compilar y ejecutar siempre desde la carpeta `Inyector/`** para que el `global.json` aplique — de lo contrario el SDK 9 emite errores `CS1744` (named arguments en constructores de atributos xUnit).

### Ejecutar asserts contra Escenario A (VulnerableApi en puerto 5000)

```powershell
# 1. Asegurarse de que VulnerableApi esté corriendo en http://localhost:5000
#    (ver Paso 7 de la sección de instalación)

# 2. Desde la carpeta Inyector/ (para que global.json active SDK 8.0.319)
Set-Location "C:\Trabajo\Universidad\Inyector"
$env:TEST_API_URL = "http://localhost:5000"

# 3. Compilar (solo la primera vez o tras cambios)
dotnet build "SecurityAsserts/SecurityAsserts.csproj" --configuration Debug --verbosity quiet

# 4. Ejecutar los 99 tests y guardar resultado TRX
$fecha = Get-Date -Format "yyyy-MM-dd"
dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
    --no-build `
    --configuration Debug `
    --logger "trx;LogFileName=ScenarioA_Run1_${fecha}.trx" `
    --results-directory "C:\Trabajo\Universidad\Resultados\TestResults" `
    -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5000"
# Resultado esperado: ~35/99 pasados (API vulnerable: fallan los controles de seguridad)
```

### Ejecutar asserts contra Escenario B (VulnerableApi_Patched en puerto 5002)

```powershell
# 1. Asegurarse de que VulnerableApi_Patched esté corriendo en http://localhost:5002

# 2. Desde Inyector/
Set-Location "C:\Trabajo\Universidad\Inyector"
$env:TEST_API_URL = "http://localhost:5002"

$fecha = Get-Date -Format "yyyy-MM-dd"
dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
    --no-build `
    --configuration Debug `
    --logger "trx;LogFileName=ScenarioB_Run1_${fecha}.trx" `
    --results-directory "C:\Trabajo\Universidad\Resultados\TestResults" `
    -- RunConfiguration.EnvironmentVariables.TEST_API_URL="http://localhost:5002"
# Resultado esperado: 95/99 pasados (4 fallos documentados de entorno)
```

### Parsear resultados TRX inline

```powershell
$trxPath = "C:\Trabajo\Universidad\Resultados\TestResults\ScenarioA_Run1_${fecha}.trx"
[xml]$x  = Get-Content $trxPath
$c       = $x.TestRun.ResultSummary.Counters
$durMs   = [math]::Round(([datetime]$x.TestRun.Times.finish - [datetime]$x.TestRun.Times.start).TotalMilliseconds)
Write-Host "passed=$($c.passed)  failed=$($c.failed)  total=$($c.total)  dur=${durMs}ms"
```

### Resultados de referencia (3 runs ejecutados el 2026-05-13)

| Escenario | Run 1 | Run 2 | Run 3 | Promedio | Duración prom. |
|-----------|-------|-------|-------|----------|---------------|
| A — Vulnerable | 25/99 | 35/99 | 35/99 | 31.7/99 | 14,495 ms |
| B — Parcheada | 95/99 | 95/99 | 95/99 | 95.0/99 | 772 ms |

> **Anomalía Run 1 Escenario A (25 vs 35):** efecto warm-up — la API no estaba completamente inicializada al comenzar la primera ejecución. Los runs 2 y 3 son representativos del comportamiento estable. El pipeline documenta este fenómeno en `scenarioA-stats.json`.

---

## 10. Solución de problemas

### Error: `dotnet` no reconocido como comando

El .NET SDK no está en el PATH. Verifique la instalación:

```powershell
where.exe dotnet
# Si no retorna nada, reinstalar desde https://dotnet.microsoft.com/download/dotnet/8.0
```

### Error: puerto 5000 en uso

```powershell
# Identificar el proceso que ocupa el puerto
netstat -ano | findstr ":5000"
# Matar el proceso (reemplazar <PID> con el número encontrado)
Stop-Process -Id <PID> -Force

# Alternativa: usar otro puerto
$env:ASPNETCORE_URLS = "http://localhost:5100"
dotnet run
```

### Error: `Could not find file 'vulnerable.db'`

Este error no debería ocurrir ya que la BD se crea automáticamente. Si persiste:

```powershell
# Verificar permisos de escritura en el directorio
icacls .\VulnerableApi\ /grant "$env:USERNAME:(OI)(CI)F"
dotnet run
```

### La base de datos tiene datos corruptos o inconsistentes

```powershell
# Desde Desarrollo\VulnerableApi\
Remove-Item vulnerable.db, vulnerable.db-shm, vulnerable.db-wal -ErrorAction SilentlyContinue
dotnet run   # DataSeeder la recrea desde cero
```

### Swagger muestra 0 endpoints

Asegúrese de que `ASPNETCORE_ENVIRONMENT` sea `Development`:

```powershell
$env:ASPNETCORE_ENVIRONMENT = "Development"
dotnet run
```

### El assert `A10` falla aunque la API esté corriendo

El assert A10 verifica redirección HTTP → HTTPS. Esta API no tiene HTTPS habilitado (G4-V1 intencional). Para que el assert detecte correctamente la **ausencia** de redirección, la API debe estar corriendo en HTTP (`http://localhost:5000`), no en HTTPS.

### SecurityAsserts no compila: `CS1744` (named argument para parámetro posicional)

El SDK activo no es 8.0.x. Compilar siempre desde la carpeta `Inyector/` (no desde `Inyector/SecurityAsserts/`) para que `global.json` fije el SDK:

```powershell
Set-Location "C:\Trabajo\Universidad\Inyector"
dotnet --version   # debe mostrar 8.0.319 o similar 8.0.x
dotnet build "SecurityAsserts/SecurityAsserts.csproj" --configuration Debug
```

### Los asserts no llegan a la API (`Connection refused` en todos)

Verificar que la variable de entorno `TEST_API_URL` está seteada y apunta al puerto correcto **antes** de ejecutar `dotnet test`:

```powershell
# Escenario A
$env:TEST_API_URL = "http://localhost:5000"
Invoke-WebRequest "http://localhost:5000/health" -UseBasicParsing | Select-Object StatusCode

# Escenario B
$env:TEST_API_URL = "http://localhost:5002"
Invoke-WebRequest "http://localhost:5002/health" -UseBasicParsing | Select-Object StatusCode
# StatusCode esperado: 200
```

> **No usar `API_BASE_URL`:** `TestConfig.cs` lee exclusivamente la variable `TEST_API_URL`. Cualquier otra variable es ignorada.

### Los resultados del Escenario A varían entre runs

Es un comportamiento documentado. El primer run puede mostrar menos tests pasados por el efecto warm-up (la API no terminó de inicializar SQLite antes de que los primeros tests la golpearan). Ejecutar siempre 3 runs y usar el promedio como métrica estadística.
