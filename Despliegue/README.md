# Despliegue — Pipeline de Seguridad y Configuración IIS

Carpeta con todos los artefactos necesarios para preparar el servidor de pruebas, registrar el agente de Azure DevOps y ejecutar el pipeline de **7 etapas** que valida la postura de seguridad de la `VulnerableApi` (Escenario A) y la `VulnerableApi_Patched` (Escenario B) mediante **3 ejecuciones independientes** por escenario.

> ⚠️ **AMBIENTE DE PRUEBAS CONTROLADO.** El pipeline está diseñado para ejecutarse sobre una red aislada con la `VulnerableApi` como objeto de prueba intencional. No conectar el servidor a redes de producción.

---

## Tabla de contenido

1. [Prerrequisitos](#1-prerrequisitos)
2. [Instalación del servidor paso a paso](#2-instalación-del-servidor-paso-a-paso)
3. [Configuración del pipeline en Azure DevOps](#3-configuración-del-pipeline-en-azure-devops)
4. [Ejecución del pipeline](#4-ejecución-del-pipeline)
5. [Detalle de cada etapa](#5-detalle-de-cada-etapa)
6. [Ejecución manual (sin Azure DevOps)](#6-ejecución-manual-sin-azure-devops)
7. [Lectura de resultados](#7-lectura-de-resultados)
8. [Estructura del proyecto](#8-estructura-del-proyecto)
9. [Variables de pipeline](#9-variables-de-pipeline)
10. [Solución de problemas](#10-solución-de-problemas)

> **Resumen del pipeline:**
> `Build` → `SAST` → `3A SecurityAsserts (Escenario A, ×3 runs)` → `3B SecurityAsserts (Escenario B, ×3 runs)` → `Deploy` → `DAST` → `Report`

---

## 1. Prerrequisitos

### Software requerido en el servidor

| Componente | Versión mínima | Verificación |
|-----------|---------------|-------------|
| Windows Server | 2019 / Windows 10+ | `winver` |
| IIS | 10.0 | `Get-WindowsFeature Web-Server` |
| ASP.NET Core Hosting Bundle | 8.x | `dotnet --list-runtimes` |
| .NET SDK | 8.0 | `dotnet --version` |
| Docker Desktop | 4.x | `docker --version` |
| PowerShell | 5.1 / 7.x | `$PSVersionTable` |

### Cuenta de Azure DevOps

- Organización en `https://dev.azure.com/<TU_ORG>`
- Proyecto creado con repositorio Git (puede ser un fork o copia del workspace)
- **PAT** (Personal Access Token) con los ámbitos: `Agent Pools (Read & manage)`, `Build (Read & execute)`, `Code (Read)`

### Generar el PAT en Azure DevOps

1. Ir a `https://dev.azure.com/<TU_ORG>` → icono de usuario → **Personal Access Tokens**
2. Clic en **New Token**
3. Nombre: `CybersecTest-Agent`, expiración: 90 días
4. Ámbitos: seleccionar **Agent Pools → Read & manage** y **Build → Read & execute**
5. Copiar el token generado — solo se muestra una vez

---

## 2. Instalación del servidor paso a paso

### Paso 1 — Ejecutar el script de preparación del ambiente

Abra una terminal de PowerShell **como Administrador** y ejecute:

```powershell
cd C:\Trabajo\Universidad\Despliegue
.\scripts\setup-environment.ps1
```

El script realiza automáticamente:

| Acción | Detalle |
|--------|---------|
| Habilita características de IIS | `Web-Server`, `Web-WebServer`, `Web-ISAPI-Ext`, `Web-Mgmt-Console`, etc. |
| Instala ASP.NET Core Hosting Bundle 8 | Si no está presente, descarga el instalador silencioso |
| Crea directorios de trabajo | `C:\CybersecTest\artifacts`, `\reports`, `\logs` |
| Descarga imagen Docker de OWASP ZAP | `ghcr.io/zaproxy/zaproxy:stable` |
| Configura regla de firewall | Puerto 5000 abierto en perfiles Domain y Private |

Parámetros opcionales del script:

```powershell
# Cambiar el directorio de trabajo (por defecto: C:\CybersecTest)
.\scripts\setup-environment.ps1 -WorkDir "D:\PruebasSeg"
```

### Paso 2 — Reiniciar IIS tras la instalación del Hosting Bundle

```powershell
iisreset /restart
```

Verificar que el módulo `AspNetCoreModuleV2` está registrado:

```powershell
Get-WebConfiguration -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/globalModules/add" |
    Where-Object { $_.name -eq "AspNetCoreModuleV2" } |
    Select-Object name, image
# Debe mostrar la ruta a aspnetcorev2.dll
```

### Paso 3 — Registrar el agente de Azure DevOps

```powershell
# Crear carpeta del agente
New-Item -ItemType Directory -Path C:\agent -Force
Set-Location C:\agent

# Descargar el agente (versión 3.230.0 — ajustar si hay versión más nueva)
$agentUrl = "https://vstsagentpackage.azureedge.net/agent/3.230.0/vsts-agent-win-x64-3.230.0.zip"
Invoke-WebRequest -Uri $agentUrl -OutFile agent.zip -UseBasicParsing
Expand-Archive -Path agent.zip -DestinationPath . -Force
Remove-Item agent.zip

# Configurar el agente (interactivo — responder a los prompts)
.\config.cmd `
    --url "https://dev.azure.com/<TU_ORG>" `
    --auth pat `
    --token "<TU_PAT>" `
    --pool "Default" `
    --agent "<NombreDelServidor>" `
    --work "_work" `
    --runAsService
```

El flag `--runAsService` registra el agente como servicio de Windows que arranca automáticamente.

### Paso 4 — Instalar e iniciar el servicio del agente

```powershell
# Instalar como servicio de Windows
.\svc.cmd install

# Iniciar el servicio
.\svc.cmd start

# Verificar estado
.\svc.cmd status
# Esperado: Running
```

Verificar en Azure DevOps que el agente aparece en línea:

```
https://dev.azure.com/<TU_ORG>/_settings/agentpools
→ Pool: Default → Agents → <NombreDelServidor> → Status: Online
```

### Paso 5 — Verificar el ambiente completo

```powershell
# .NET SDK
dotnet --version          # debe mostrar 8.x.x

# .NET Runtimes
dotnet --list-runtimes    # debe incluir Microsoft.AspNetCore.App 8.x.x

# IIS
Get-Service W3SVC | Select-Object Name, Status
# Status: Running

# Docker
docker run --rm hello-world
# Imprime "Hello from Docker!" si Docker funciona correctamente

# Puerto 5000 libre (VulnerableApi — Escenario A)
netstat -ano | findstr ":5000"
# Sin resultados = puerto disponible

# Puerto 5002 libre (VulnerableApi_Patched — Escenario B)
netstat -ano | findstr ":5002"
# Sin resultados = puerto disponible
```

---

## 3. Configuración del pipeline en Azure DevOps

### Paso 1 — Subir el código al repositorio

```powershell
cd C:\Trabajo\Universidad
git init
git remote add origin https://dev.azure.com/<TU_ORG>/<TU_PROYECTO>/_git/<TU_REPO>
git add .
git commit -m "feat: estrategia de asserts de seguridad — tesis MSI"
git push -u origin main
```

### Paso 2 — Crear el pipeline en Azure DevOps

1. En el portal de Azure DevOps, ir a **Pipelines → New pipeline**
2. Seleccionar **Azure Repos Git** como fuente
3. Seleccionar el repositorio
4. Seleccionar **Existing Azure Pipelines YAML file**
5. Branch: `main` | Path: `/Despliegue/azure-pipelines.yml`
6. Clic en **Continue** → revisar las variables → **Save and Run**

### Paso 3 — Configurar las variables del pipeline

En **Pipelines → <nombre del pipeline> → Edit → Variables**:

| Variable | Valor | Secreto |
|----------|-------|---------|
| `buildConfiguration` | `Debug` | No |
| `apiBaseUrl` | `http://localhost:5000` | No |
| `patchedApiBaseUrl` | `http://localhost:5002` | No |
| `iisAppName` | `VulnerableApi` | No |
| `iisPort` | `5000` | No |
| `numRuns` | `3` | No |

> Las variables `assertsBaseDir`, `vulnerableDbPath`, `patchedDbPath` y `testResultsDir` se calculan automáticamente desde `$(Build.SourcesDirectory)` y `$(Build.ArtifactStagingDirectory)` — no requieren configuración manual.

### Paso 4 — Crear el Environment para el deploy

1. Ir a **Pipelines → Environments → New environment**
2. Nombre: `Pruebas-NoProductivo`
3. Resource: **None**
4. Clic en **Create**

Este environment es requerido por la etapa de Deploy (`DeployIIS` usa `environment: 'Pruebas-NoProductivo'`).

---

## 4. Ejecución del pipeline

### Disparar una ejecución manual

1. Ir a **Pipelines → <nombre del pipeline>**
2. Clic en **Run pipeline**
3. Branch: `main`
4. Clic en **Run**

### Disparador automático (trigger)

El pipeline se activa automáticamente con cada push a `main` o `develop`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop
```

Para disparar desde la terminal:

```powershell
git add -A
git commit -m "fix: corrección en controlador de usuarios"
git push origin main
# El pipeline inicia automáticamente en ~30 segundos
```

### Seguimiento en tiempo real

En el portal de Azure DevOps:

```
Pipelines → <nombre> → <número de ejecución> → <etapa> → <job>
```

Cada etapa muestra sus logs en tiempo real. Si una etapa falla, las etapas dependientes se cancelan automáticamente.

**Tiempos de referencia por etapa** (medidos en servidor Windows con 4 vCPU, 8 GB RAM, SSD):

| Etapa | Tiempo estimado | Notas |
|-------|----------------|-------|
| Build | 3–5 min | Restore + compilación de 3 proyectos |
| SAST | 2–3 min | Roslyn sobre VulnerableApi + Patched |
| 3A SecurityAsserts | 10–20 min | 3 runs × (reinicio API + 99 tests ~14 s) |
| 3B SecurityAsserts | 3–5 min | 3 runs × 99 tests ~800 ms c/u, sin reinicio |
| Deploy | 2–4 min | IIS deploy + health check |
| DAST | 10–20 min | ZAP API Scan (varía según rutas y alertas) |
| Report | < 1 min | Parseo TRX + ZAP JSON → HTML |
| **Total** | **~30–60 min** | |

> **Etapa Report** siempre se ejecuta (`condition: always()`) aunque etapas anteriores fallen, garantizando que siempre existe un reporte descargable.

---

## 5. Detalle de cada etapa

### Etapa 1 — Compilación (`Build`)

**Objetivo:** Compilar los tres proyectos sin errores.
**Quality gate:** 0 errores de compilación en los tres proyectos.

| Paso | Tarea Azure DevOps | Proyecto | Descripción |
|------|-------------------|----------|-------------|
| 1 | `UseDotNet@2` | — | Instala .NET SDK 8.x en el agente |
| 2 | `DotNetCoreCLI@2 restore` | VulnerableApi | Descarga paquetes NuGet |
| 3 | `DotNetCoreCLI@2 build` | VulnerableApi | Compila en modo **Debug** con `--no-restore` |
| 4 | `DotNetCoreCLI@2 publish` | VulnerableApi | Genera artefacto ZIP en `api-vulnerable/` |
| 5 | `DotNetCoreCLI@2 restore` | VulnerableApi_Patched | Descarga paquetes NuGet |
| 6 | `DotNetCoreCLI@2 build` | VulnerableApi_Patched | Compila en modo **Debug** |
| 7 | `DotNetCoreCLI@2 publish` | VulnerableApi_Patched | Genera artefacto ZIP en `api-patched/` |
| 8 | `PowerShell@2` | SecurityAsserts | `Set-Location Inyector/` + `dotnet build` — aplica `global.json` SDK 8.0.319 |
| 9 | `PublishBuildArtifacts@1` | — | Sube artefactos `VulnerableApi` y `VulnerableApi_Patched` |

> **Por qué `Debug` y no `Release`:** El perfil de los asserts asume que la API corre en modo `Development` (Swagger activo, stack traces, sin compresión). El modo `Debug` garantiza compatibilidad con los asserts G4 (Swagger) y G2 (stack trace en 500).
>
> **Por qué `Set-Location Inyector/` para SecurityAsserts:** `Inyector/global.json` fija el SDK a `8.0.319` con `rollForward: latestPatch`. Sin ese `Set-Location`, el SDK 9 resolvería los archivos `.csproj` y emitiría errores `CS1744` (named arguments en constructores de xUnit `[Theory]`).

---

### Etapa 2 — Análisis Estático SAST (`SAST`)

**Objetivo:** Detectar vulnerabilidades en el código fuente sin ejecutar la aplicación.
**Quality gate:** 0 hallazgos de severidad `Critical` o `High`.
**Herramienta:** Roslyn Security Analyzers (incluidos en .NET 8 SDK).

Analizadores activados:

| ID | Nombre | Vulnerabilidad que detecta |
|----|--------|---------------------------|
| CA2100 | SQL injection | Consultas SQL concatenadas (`G3-V1`) |
| CA3001 | SQL injection review | Uso de `FromSqlRaw` con interpolación |
| CA3002 | XSS review | Salida sin codificar en HTML (`G3-V2`) |
| CA3006 | Process command injection | Ejecución de comandos del sistema |
| CA3061 | Do not add schema by URL | XmlResolver activo (`G7-V1`) |
| CA5359 | Do not disable certificate validation | Bypass de TLS |
| CA5369 | Use XmlReader for Deserialize | Deserialización XML insegura |

Los analizadores se activan con el parámetro `/p:WarningsAsErrors` en la invocación de `dotnet build`. Si algún analizador reporta CA2100 o CA3001, la etapa falla y el pipeline se detiene.

---

### Etapa 3A — Asserts de Seguridad Escenario A (`SecurityAsserts_EscenarioA`)

**Objetivo:** Confirmar que la API vulnerable **falla** los controles de seguridad esperados.
**Quality gate:** Anomalía si el promedio de pasados supera 99/99 (indicaría que el Inyector no está conectado).
**Herramienta:** xUnit — proyecto `Inyector/SecurityAsserts` — **99 tests** (55 asserts distintos con variantes paramétricas).
**Paralelismo:** deshabilitado vía `xunit.runner.json` (`parallelizeAssembly: false`).
**Env var:** `TEST_API_URL=http://localhost:5000` leída por `TestConfig.cs`.

Secuencia de ejecución dentro de la etapa:

```
Run 1:
  Limpiar puerto 5000 → Eliminar vulnerable.db → dotnet run (--no-build)
  Health check loop (15 reintentos × 2 s) → API disponible
  dotnet test --no-build → ScenarioA_Run1_<fecha>.trx
  Parsear TRX inline: passed/failed/durMs

Run 2 y 3 (limpieza entre cada uno):
  Stop-Process (PID guardado) → Eliminar vulnerable.db → dotnet run
  Health check loop → dotnet test → ScenarioA_Run2/3_<fecha>.trx

Resumen multi-run → scenarioA-stats.json
Quality Gate → alerta si avgPassed ≥ 99
Detener VulnerableApi (condition: always)
PublishTestResults → ScenarioA_Run*.trx en pestaña Tests
```

> **Por qué 3 runs con DB limpia:** Los asserts que crean datos (registro de usuarios, creación de órdenes) dejan estado en SQLite. Eliminar `vulnerable.db` y reiniciar la API hace que `DataSeeder` re-siembre los datos canónicos, garantizando que cada run parte del mismo estado inicial.

---

### Etapa 3B — Asserts de Seguridad Escenario B (`SecurityAsserts_EscenarioB`)

**Objetivo:** Confirmar que la API parcheada **pasa** los controles de seguridad.
**Quality gate:** Promedio de tests pasados ≥ 95/99 (tolerancia para 4 fallos de entorno documentados).
**Dependencia:** `succeededOrFailed()` — siempre corre después de 3A para obtener la comparativa.
**Env var:** `TEST_API_URL=http://localhost:5002` leída por `TestConfig.cs`.

Secuencia de ejecución:

```
Limpiar puerto 5002 → dotnet run VulnerableApi_Patched (--no-build)
Kestrel config aplicada desde Program.cs:
  MaxRequestBodySize = 100 MB   (assert A14b: archivo 6 MB → 413 via middleware)
  MaxRequestLineSize = 16 KB    (assert B10b: query string > 16 KB → 400)
  PermitLimit = 500 req/10s     (no bloquear 99 tests secuenciales)
Health check loop (15 reintentos × 2 s)

Run 1 → ScenarioB_Run1_<fecha>.trx
Run 2 → ScenarioB_Run2_<fecha>.trx   (sin reinicio de API: asserts estructurales)
Run 3 → ScenarioB_Run3_<fecha>.trx

Resumen multi-run → scenarioB-stats.json
Quality Gate → falla si avgPassed < 95
Detener VulnerableApi_Patched (condition: always)
PublishTestResults → ScenarioB_Run*.trx en pestaña Tests
```

**4 fallos esperados y documentados en Escenario B:**

| Assert | Test | Razón | Mitigación producción |
|--------|------|-------|----------------------|
| A10 | TLS_HttpRequest_ShouldRedirectToHttps | `UseHttpsRedirection()` deshabilitado para HTTP en tests | Habilitar en `Program.cs`; IIS gestiona TLS |
| B09 | RateLimit_AuthEndpoint_ShouldReturn429 | `PermitLimit=500` para no bloquear 99 tests | Restaurar `PermitLimit=5` en `appsettings.Production.json` |
| C02 | TLS_MinimumVersion_ShouldBeTls12 | Kestrel en HTTP puro (puerto 5002); TLS no configurado | Certificado TLS ≥ 1.2 en producción |
| B08 | Pagination_ProductsEndpoint | Paginación fuera del alcance de correcciones de seguridad | Implementar `page`/`pageSize` en `GET /api/v2/products` |

---

### Etapa 4 — Despliegue en IIS (`Deploy`)

**Objetivo:** Desplegar la API en IIS para la fase DAST.
**Quality gate:** `GET /health` retorna HTTP 200.

El script `deploy-iis.ps1` realiza:

| Paso | Acción |
|------|--------|
| 1 | Detiene el sitio IIS y el Application Pool si existen |
| 2 | Crea o actualiza el directorio físico en `C:\inetpub\VulnerableApi` |
| 3 | Expande el artefacto ZIP publicado en la Etapa 1 |
| 4 | Configura el Application Pool: sin managed runtime, `AlwaysRunning` |
| 5 | Crea o reconfigura el sitio IIS en el puerto 5000 |
| 6 | Copia `web.config` con `AspNetCoreModuleV2` y `hostingModel="inprocess"` |
| 7 | Inicia el Application Pool y el sitio |

Verificación de salud post-deploy:

```powershell
# El pipeline espera hasta 30 s a que la API responda
$r = Invoke-WebRequest -Uri "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 30
if ($r.StatusCode -ne 200) { exit 1 }
```

---

### Etapa 5 — DAST con OWASP ZAP (`DAST`)

**Objetivo:** Escaneo dinámico automatizado de la API desplegada en IIS.
**Quality gate:** 0 alertas de riesgo Alto o Crítico (`continueOnError: true` — no bloquea el pipeline; los hallazgos se consolidan en el Report).
**Herramienta:** OWASP ZAP vía Docker (`ghcr.io/zaproxy/zaproxy:stable`).

Secuencia ejecutada por el pipeline:

```powershell
# 1. Descargar la especificación OpenAPI desde el sitio IIS desplegado
#    (requiere que Swagger esté activo — buildConfiguration=Debug)
$spec = Invoke-WebRequest -Uri "http://localhost:$(iisPort)/swagger/v2/swagger.json" -UseBasicParsing
$spec.Content | Out-File -FilePath "$(Build.ArtifactStagingDirectory)/openapi.json" -Encoding utf8

# 2. Ejecutar ZAP API Scan via Docker
#    --network host: accede a localhost:$(iisPort) sin redirección de puertos
#    El volumen monta $(ArtifactStagingDirectory) como /zap/wrk/ para leer el spec y escribir reportes
docker run --rm --network host `
    -v "$(Build.ArtifactStagingDirectory):/zap/wrk/:rw" `
    ghcr.io/zaproxy/zaproxy:stable `
    zap-api-scan.py `
    -t /zap/wrk/openapi.json `
    -f openapi `
    -r zap-report.html `
    -J zap-report.json `
    -x zap-report.xml `
    -z "-config api.disablekey=true" `
    --fail-on-warn
# Código de salida 0: sin alertas. Código 2: alertas encontradas (no bloquea pipeline por continueOnError).
```

Los reportes `zap-report.html`, `zap-report.json` y `zap-report.xml` se publican como artefacto `ZAP-Report` en Azure DevOps.

---

### Etapa 6 — Reporte Consolidado (`Report`)

**Objetivo:** Generar un reporte HTML que consolida resultados de SAST + SecurityAsserts (A+B, promedios 3 runs) + DAST.
**Condición:** `condition: always()` — se ejecuta siempre, incluso si etapas anteriores fallaron.
**Herramienta:** `generate-report.ps1`

```powershell
# Invocación exacta del pipeline (parámetros usados en PowerShell@2 filePath task)
.\scripts\generate-report.ps1 `
    -BuildNumber "$(Build.BuildNumber)" `
    -ResultsPath  "$(Build.ArtifactStagingDirectory)" `
    -OutputPath   "$(Build.ArtifactStagingDirectory)/security-report"
```

> **`-ResultsPath`** apunta a `$(Build.ArtifactStagingDirectory)` (raíz) y no a un subdirectorio: el script busca recursivamente `ScenarioA_Run*.trx`, `ScenarioB_Run*.trx`, `scenarioA-stats.json`, `scenarioB-stats.json` y `zap-report.json`.

El reporte HTML incluye:

- Estado general (APROBADO / FALLIDO)
- Tabla resumen de asserts xUnit con promedios de los 3 runs por escenario
- Comparativa A vs B: tasa de detección y ratio de velocidad
- Tabla de alertas DAST de ZAP con riesgo ≥ Alto
- Referencias a OWASP API Security Top 10, MITRE ATT&CK v15 y Microsoft SDL

El reporte se publica como artefacto `Security-Report` descargable desde el portal de Azure DevOps.

---

## 6. Ejecución manual (sin Azure DevOps)

Si no dispone de Azure DevOps, puede ejecutar cada etapa localmente replicando exactamente los comandos del pipeline. Todos los comandos usan **PowerShell 7** (`pwsh`).

### Etapa 1 — Build (los 3 proyectos)

```powershell
# ── VulnerableApi ──────────────────────────────────────────────────────
dotnet restore "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj"
dotnet build   "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj" `
    --configuration Debug --no-restore

# ── VulnerableApi_Patched ──────────────────────────────────────────────
dotnet restore "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj"
dotnet build   "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj" `
    --configuration Debug --no-restore

# ── SecurityAsserts (desde Inyector/ para que global.json aplique SDK 8.0.319)
Set-Location "C:\Trabajo\Universidad\Inyector"
dotnet build "SecurityAsserts/SecurityAsserts.csproj" --configuration Debug --verbosity quiet
# Resultado esperado: 0 Errores
```

### Etapa 2 — SAST (Roslyn)

```powershell
# Analiza VulnerableApi con reglas de seguridad; en la API vulnerable
# se esperan warnings CA2100 (SQLi) y CA3002 (XSS) — documenta las vulnerabilidades.
dotnet build "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj" `
    --configuration Debug `
    /p:EnableNETAnalyzers=true `
    /p:AnalysisMode=All `
    /p:TreatWarningsAsErrors=false `
    /p:WarningsAsErrors="CA2100;CA3001;CA3002;CA3006;CA3061;CA5359;CA5369"

# Analiza VulnerableApi_Patched — debe pasar sin hallazgos críticos.
dotnet build "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj" `
    --configuration Debug `
    /p:EnableNETAnalyzers=true `
    /p:AnalysisMode=All `
    /p:TreatWarningsAsErrors=false `
    /p:WarningsAsErrors="CA2100;CA3001;CA3002;CA3006;CA3061;CA5359;CA5369"
```

### Etapa 3A — Escenario A: Asserts vs VulnerableApi (3 runs con DB limpia)

```powershell
# ── Variables locales ──────────────────────────────────────────────────
$apiProject  = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\VulnerableApi.csproj"
$dbPath      = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi\vulnerable.db"
$apiUrl      = "http://localhost:5000"
$resultsDir  = "C:\Trabajo\Universidad\Resultados\TestResults"
$buildDate   = Get-Date -Format "yyyy-MM-dd"

Set-Location "C:\Trabajo\Universidad\Inyector"
$env:TEST_API_URL = $apiUrl

for ($run = 1; $run -le 3; $run++) {

    # ── Entre runs: limpiar puerto, DB y reiniciar API ─────────
    Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    Remove-Item $dbPath -ErrorAction SilentlyContinue   # DataSeeder re-siembra en el próximo startup

    $proc = Start-Process -FilePath "dotnet" `
        -ArgumentList "run","--project",$apiProject,"--no-build",`
                      "--configuration","Debug","--urls",$apiUrl `
        -PassThru -WindowStyle Hidden
    Write-Host "VulnerableApi iniciada (PID=$($proc.Id)) — Run $run"

    # ── Health check: esperar hasta 30 s ──────────────────────
    $ok = $false
    for ($i = 1; $i -le 15; $i++) {
        Start-Sleep -Seconds 2
        try {
            $r = Invoke-WebRequest -Uri "$apiUrl/health" -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) { $ok = $true; break }
        } catch {}
        Write-Host "Health check $i/15..."
    }
    if (-not $ok) { Write-Error "API no respondió en 30 s"; break }

    # ── Ejecutar asserts ───────────────────────────────────────
    # TEST_API_URL es leída directamente por TestConfig.cs
    # xunit.runner.json garantiza ejecución secuencial (parallelizeAssembly=false)
    $trxFile = "ScenarioA_Run${run}_${buildDate}.trx"
    dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
        --no-build `
        --configuration Debug `
        --logger "trx;LogFileName=$trxFile" `
        --results-directory $resultsDir `
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL=$apiUrl

    # ── Parsear TRX inline ─────────────────────────────────────
    $trxPath = Join-Path $resultsDir $trxFile
    if (Test-Path $trxPath) {
        [xml]$x  = Get-Content $trxPath
        $c       = $x.TestRun.ResultSummary.Counters
        $durMs   = [math]::Round(([datetime]$x.TestRun.Times.finish - [datetime]$x.TestRun.Times.start).TotalMilliseconds)
        Write-Host "Run $run → passed=$($c.passed) failed=$($c.failed) total=$($c.total) dur=${durMs}ms"
    }
}

# Detener API al finalizar
Get-NetTCPConnection -LocalPort 5000 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Write-Host "VulnerableApi detenida"
```

### Etapa 3B — Escenario B: Asserts vs VulnerableApi_Patched (3 runs, sin reinicio de DB)

```powershell
# ── Variables locales ──────────────────────────────────────────────────
$patchedProject = "C:\Trabajo\Universidad\Desarrollo\VulnerableApi_Patched\VulnerableApi_Patched.csproj"
$patchedUrl     = "http://localhost:5002"
$resultsDir     = "C:\Trabajo\Universidad\Resultados\TestResults"
$buildDate      = Get-Date -Format "yyyy-MM-dd"

# ── Liberar puerto 5002 e iniciar VulnerableApi_Patched ───────────────
Get-NetTCPConnection -LocalPort 5002 -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

$proc = Start-Process -FilePath "dotnet" `
    -ArgumentList "run","--project",$patchedProject,"--no-build",`
                  "--configuration","Debug","--urls",$patchedUrl `
    -PassThru -WindowStyle Hidden
Write-Host "VulnerableApi_Patched iniciada (PID=$($proc.Id))"
# Kestrel config relevante aplicada en Program.cs:
#   MaxRequestBodySize = 100 MB  → assert A14b (archivo 6 MB no aborta conexión; middleware devuelve 413)
#   MaxRequestLineSize = 16 KB   → assert B10b (query string > 16 KB devuelve 400)
#   PermitLimit = 500 req/10s    → no bloquea los 99 tests secuenciales

# ── Health check ───────────────────────────────────────────────────────
$ok = $false
for ($i = 1; $i -le 15; $i++) {
    Start-Sleep -Seconds 2
    try {
        $r = Invoke-WebRequest -Uri "$patchedUrl/health" -UseBasicParsing -TimeoutSec 3
        if ($r.StatusCode -eq 200) { $ok = $true; break }
    } catch {}
    Write-Host "Health check $i/15..."
}
if (-not $ok) { Write-Error "VulnerableApi_Patched no respondió en 30 s"; exit 1 }

Set-Location "C:\Trabajo\Universidad\Inyector"
$env:TEST_API_URL = $patchedUrl

for ($run = 1; $run -le 3; $run++) {
    # Sin reinicio de API entre runs: los asserts de Escenario B son estructurales
    # (verifican headers, JWT validation, CORS, SQLi rechazado, etc.) — no dependen de estado de BD.
    $trxFile = "ScenarioB_Run${run}_${buildDate}.trx"
    Write-Host "`n=== Escenario B — Run $run / 3 ==="

    dotnet test "SecurityAsserts/SecurityAsserts.csproj" `
        --no-build `
        --configuration Debug `
        --logger "trx;LogFileName=$trxFile" `
        --results-directory $resultsDir `
        -- RunConfiguration.EnvironmentVariables.TEST_API_URL=$patchedUrl

    $trxPath = Join-Path $resultsDir $trxFile
    if (Test-Path $trxPath) {
        [xml]$x  = Get-Content $trxPath
        $c       = $x.TestRun.ResultSummary.Counters
        $durMs   = [math]::Round(([datetime]$x.TestRun.Times.finish - [datetime]$x.TestRun.Times.start).TotalMilliseconds)
        Write-Host "Run $run → passed=$($c.passed) failed=$($c.failed) total=$($c.total) dur=${durMs}ms"
    }
}

# Quality gate local: promedio ≥ 95/99
$allTrx = Get-ChildItem $resultsDir -Filter "ScenarioB_Run*_${buildDate}.trx"
$totalPassed = 0
foreach ($t in $allTrx) {
    [xml]$x = Get-Content $t.FullName
    $totalPassed += [int]$x.TestRun.ResultSummary.Counters.passed
}
$avg = [math]::Round($totalPassed / $allTrx.Count, 1)
Write-Host "Promedio Escenario B: $avg / 99 — $(if ($avg -ge 95) { 'APROBADO' } else { 'REVISAR' })"

# Detener API
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Host "VulnerableApi_Patched detenida"
```

### Etapa 4 — Deploy IIS (requiere Admin)

```powershell
cd C:\Trabajo\Universidad\Despliegue
.\scripts\deploy-iis.ps1 `
    -AppName "VulnerableApi" `
    -Port 5000 `
    -SourcePath "C:\CybersecTest\artifacts\api"

# Verificar health check post-deploy
$maxRetries = 10
for ($i = 1; $i -le $maxRetries; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 5
        if ($r.StatusCode -eq 200) {
            $body = $r.Content | ConvertFrom-Json
            Write-Host "Health OK — version=$($body.version) status=$($body.status)"
            break
        }
    } catch {}
    Write-Host "Intento $i/$maxRetries..."
    Start-Sleep -Seconds 3
}
```

### Etapa 5 — DAST con ZAP

```powershell
# Descargar spec OpenAPI (Swagger debe estar activo — buildConfiguration=Debug)
$spec = Invoke-WebRequest -Uri "http://localhost:5000/swagger/v2/swagger.json" -UseBasicParsing
$spec.Content | Out-File -FilePath "C:\CybersecTest\reports\openapi.json" -Encoding utf8
Write-Host "Rutas en spec: $(($spec.Content | ConvertFrom-Json).paths.PSObject.Properties.Count)"

# Ejecutar ZAP API Scan via Docker (--network host: accede a localhost:5000)
docker run --rm --network host `
    -v "C:\CybersecTest\reports:/zap/wrk/:rw" `
    ghcr.io/zaproxy/zaproxy:stable `
    zap-api-scan.py `
    -t /zap/wrk/openapi.json `
    -f openapi `
    -r zap-report.html `
    -J zap-report.json `
    -x zap-report.xml `
    -z "-config api.disablekey=true" `
    --fail-on-warn
# Salida 0: sin alertas de riesgo medio/alto. Salida 2: hallazgos encontrados.
```

### Etapa 6 — Reporte Consolidado

```powershell
cd C:\Trabajo\Universidad\Despliegue
.\scripts\generate-report.ps1 `
    -BuildNumber "local-$(Get-Date -Format 'yyyyMMdd-HHmm')" `
    -ResultsPath  "C:\Trabajo\Universidad\Resultados\TestResults" `
    -OutputPath   "C:\CybersecTest\reports"

# Abrir el reporte generado
Get-ChildItem "C:\CybersecTest\reports" -Filter "*.html" | Select-Object -Last 1 | ForEach-Object { Start-Process $_.FullName }
```

---

## 7. Lectura de resultados

### En Azure DevOps

| Ubicación | Contenido |
|-----------|-----------|
| **Pipelines → <ejecución> → Summary** | Estado general de las **7 etapas**, tiempo de ejecución total |
| **Pipelines → <ejecución> → Tests** | Resultados .trx de los **99 tests** (6 archivos TRX: ScenarioA_Run1/2/3 + ScenarioB_Run1/2/3) |
| **Pipelines → <ejecución> → Artifacts** | ZIP del artefacto compilado + HTML del reporte |
| **Pipelines → Environments → Pruebas-NoProductivo** | Historial de despliegues y aprobaciones |

### Interpretación del estado de las etapas

| Color en el portal | Significado | Acción |
|--------------------|-------------|--------|
| Verde | Etapa superó quality gate | Continuar |
| Rojo | Quality gate fallido — pipeline detenido | Revisar logs, corregir y hacer push |
| Amarillo | Warnings (Oleada2/3) | Registrar en tabla de riesgo aceptado |
| Gris | Cancelada por fallo en etapa anterior | No requiere acción directa |

### Leer los archivos de estadísticas multi-run

Las etapas 3A y 3B generan archivos JSON con los promedios de los 3 runs. Se publican dentro del artefacto junto con los TRX:

```powershell
# Descargar artefacto (az CLI) y leer las estadísticas
az pipelines runs artifact download `
    --run-id <RUN_ID> `
    --artifact-name "test-results" `
    --path C:\CybersecTest\stats

# Leer promedios
$statsA = Get-Content "C:\CybersecTest\stats\scenarioA-stats.json" | ConvertFrom-Json
$statsB = Get-Content "C:\CybersecTest\stats\scenarioB-stats.json" | ConvertFrom-Json
Write-Host "Escenario A — avg: $($statsA.avgPassed)/99 en $($statsA.avgDurMs) ms"
Write-Host "Escenario B — avg: $($statsB.avgPassed)/99 en $($statsB.avgDurMs) ms"
$ratio = [math]::Round($statsA.avgDurMs / $statsB.avgDurMs, 1)
Write-Host "Ratio de velocidad: Escenario B es ${ratio}x más rápido que A"
```

**Valores de referencia** (ejecución del 2026-05-13):

| Métrica | Escenario A (Vulnerable) | Escenario B (Parcheada) |
|---------|--------------------------|------------------------|
| Promedio pasados | 31.7 / 99 | 95.0 / 99 |
| Promedio duración | 14,495 ms | 772 ms |
| Runs estables | Run 2 y 3 (35/99) | Los 3 runs (95/99) |
| Ratio velocidad | — | **18.8× más rápido** |

### Leer el reporte HTML de seguridad

```powershell
# Descargar desde Azure DevOps con az CLI (opcional)
az pipelines runs artifact download `
    --run-id <RUN_ID> `
    --artifact-name Security-Report `
    --path C:\CybersecTest\reports

# Abrir el reporte
Start-Process "C:\CybersecTest\reports\Security-Report\*.html"
```

---

## 8. Estructura del proyecto

```
Despliegue/
├── azure-pipelines.yml              ← Definición YAML del pipeline de 7 etapas
│     Stage Build:    dotnet build (Debug) × 3 proyectos + PublishBuildArtifacts
│     Stage SAST:     Roslyn Analyzers (CA2100, CA3001, CA3002, CA3061, CA5369…)
│     Stage 3A:       SecurityAsserts × 3 runs vs VulnerableApi     (puerto 5000, DB limpia c/run)
│     Stage 3B:       SecurityAsserts × 3 runs vs VulnerableApi_Patched (puerto 5002, continuo)
│     Stage Deploy:   deploy-iis.ps1 + health check (HTTP 200 en /health)
│     Stage DAST:     OWASP ZAP API Scan via Docker (openapi.json → zap-report.*)
│     Stage Report:   generate-report.ps1 → HTML consolidado (SAST + TRX + ZAP)
│
├── scripts/
│   ├── setup-environment.ps1        ← Preparación del servidor (IIS, .NET, Docker, firewall)
│   │     Ejecutar 1 vez como Admin antes de registrar el agente
│   │
│   ├── deploy-iis.ps1               ← Despliegue automático en IIS
│   │     Parámetros: -AppName, -Port, -SourcePath, [-PhysicalPath], [-AppPoolIdentity]
│   │
│   └── generate-report.ps1          ← Generador de reporte HTML consolidado
│         Parámetros: -BuildNumber, -ResultsPath, -OutputPath
│         Combina resultados: .trx (asserts) + zap-report.json (DAST)
│
└── config/
    └── web.config                   ← Configuración IIS para ASP.NET Core 8
          Módulo: AspNetCoreModuleV2
          hostingModel: inprocess
          processPath: dotnet + VulnerableApi.dll
          Variables: ASPNETCORE_ENVIRONMENT=Development, ASPNETCORE_URLS=http://localhost:5000
```

---

## 9. Variables de pipeline

Definidas al inicio de `azure-pipelines.yml` y sobreescribibles en el portal:

### Escenario A — API Vulnerable

| Variable | Valor por defecto | Descripción |
|----------|-------------------|-------------|
| `buildConfiguration` | `Debug` | Configuración de compilación (Debug activa Swagger y stack traces) |
| `apiProjectPath` | `$(Build.SourcesDirectory)/Desarrollo/VulnerableApi/VulnerableApi.csproj` | Proyecto VulnerableApi |
| `apiBaseUrl` | `http://localhost:5000` | URL leída por `TEST_API_URL` en `TestConfig.cs` |
| `apiPort` | `5000` | Puerto Kestrel — usado en `Get-NetTCPConnection` para liberar el puerto |
| `iisAppName` | `VulnerableApi` | Nombre del sitio IIS y Application Pool |
| `iisPort` | `5000` | Puerto de escucha de IIS (Etapa Deploy) |
| `vulnerableDbPath` | `$(Build.SourcesDirectory)/Desarrollo/VulnerableApi/vulnerable.db` | SQLite eliminado entre cada run de Escenario A |

### Escenario B — API Parcheada

| Variable | Valor por defecto | Descripción |
|----------|-------------------|-------------|
| `patchedApiProjectPath` | `$(Build.SourcesDirectory)/Desarrollo/VulnerableApi_Patched/VulnerableApi_Patched.csproj` | Proyecto VulnerableApi_Patched |
| `patchedApiBaseUrl` | `http://localhost:5002` | URL de la API parcheada |
| `patchedApiPort` | `5002` | Puerto Kestrel de la API parcheada |
| `patchedDbPath` | `$(Build.SourcesDirectory)/Desarrollo/VulnerableApi_Patched/patched.db` | SQLite de la API parcheada (no se elimina entre runs) |

### SecurityAsserts

| Variable | Valor por defecto | Descripción |
|----------|-------------------|-------------|
| `assertsBaseDir` | `$(Build.SourcesDirectory)/Inyector` | Directorio base para `Set-Location` — activa `global.json` SDK 8.0.319 |
| `assertsProjectPath` | `$(Build.SourcesDirectory)/Inyector/SecurityAsserts/SecurityAsserts.csproj` | Proyecto xUnit |
| `testResultsDir` | `$(Build.ArtifactStagingDirectory)/test-results` | Directorio de salida para archivos `.trx` |
| `numRuns` | `3` | Número de ejecuciones por escenario para estadísticas de promedio |

### Infraestructura

| Variable | Valor por defecto | Descripción |
|----------|-------------------|-------------|
| `dotnetVersion` | `8.x` | Versión del .NET SDK para la tarea `UseDotNet@2` |
| `zapImage` | `ghcr.io/zaproxy/zaproxy:stable` | Imagen Docker de OWASP ZAP |

> **Nota sobre `TEST_API_URL`:** Esta variable de entorno es la que realmente usa `TestConfig.cs`. En el pipeline se establece mediante `$env:TEST_API_URL` **antes** de `dotnet test` y también se pasa por `RunConfiguration.EnvironmentVariables.TEST_API_URL`. No usar el nombre `API_BASE_URL` — no es leído por el código.

Para sobreescribir una variable en una ejecución específica:

```
Pipelines → Run pipeline → Variables → Add variable
```

---

## 10. Solución de problemas

### El agente aparece como Offline en Azure DevOps

```powershell
# Verificar el servicio del agente
Get-Service -Name "vstsagent.*" | Select-Object Name, Status

# Reiniciar si está detenido
cd C:\agent
.\svc.cmd stop
.\svc.cmd start
.\svc.cmd status
```

### Etapa 1 falla: `MSB1003 Specify a project or solution file`

La variable `apiProjectPath` no corresponde a la ruta real en el agente. Verificar que el repositorio está en la misma estructura que el workspace local:

```powershell
# El agente clona el repo en _work\<N>\s\
Test-Path "C:\agent\_work\1\s\Desarrollo\VulnerableApi\VulnerableApi.csproj"
# Debe retornar True
```

### Etapa 3A/3B falla: `Connection refused` en todos los asserts

La API no arrancó antes de que los asserts empezaran. El pipeline ya implementa un health-check en loop de 15 reintentos × 2 segundos. Si el servidor es especialmente lento, aumentar el número de reintentos en el step correspondiente:

```powershell
# En azure-pipelines.yml, step "[A] Iniciar VulnerableApi" o "[B] Iniciar VulnerableApi_Patched"
# Cambiar -le 15 por -le 20 (40 segundos de espera)
for ($i = 1; $i -le 20; $i++) {    # era 15
    Start-Sleep -Seconds 2
    ...
}
```

Verificar manualmente que la API responde antes de correr los tests:

```powershell
# Escenario A
try { (Invoke-WebRequest "http://localhost:5000/health" -TimeoutSec 5).StatusCode } catch { "No disponible" }

# Escenario B
try { (Invoke-WebRequest "http://localhost:5002/health" -TimeoutSec 5).StatusCode } catch { "No disponible" }
# Respuesta esperada: 200 con body {"status":"healthy","version":"2.0"}
```

### Etapa 3A varía entre runs (25 vs 35 pasados)

Esto es esperado y está documentado. La primera corrida puede tener mayor latencia si la API no estaba completamente inicializada (efecto warm-up). Las corridas 2 y 3 son representativas del comportamiento estable. En los resultados locales validados: **Run 1: 25/99, Run 2: 35/99, Run 3: 35/99** — el promedio es 31.7/99.

Para forzar un estado más estable, aumentar el tiempo del health-check a 20 intentos o verificar que el endpoint `/health` responde antes de continuar.

### SecurityAsserts no compila: `CS1744` (named argument para parámetro posicional)

El SDK activo no es 8.0.x. Verificar que el `global.json` en `Inyector/` está siendo respetado:

```powershell
Set-Location "C:\Trabajo\Universidad\Inyector"
dotnet --version   # debe mostrar 8.0.319 o similar 8.0.x
# Si muestra 9.x, revisar que global.json existe en Inyector/
Get-Content "global.json"
# Esperado: { "sdk": { "version": "8.0.319", "rollForward": "latestPatch" } }
```

Si el SDK 8.0.319 no está instalado en el agente, instalar con:

```powershell
# Descargar e instalar .NET 8 SDK 8.0.319
Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile dotnet-install.ps1
.\dotnet-install.ps1 -Version 8.0.319 -InstallDir "C:\dotnet"
```

### Etapa 4 falla: `New-Website: El sitio ya existe`

El sitio IIS está bloqueado por un proceso previo. Limpiar manualmente:

```powershell
# Detener y eliminar el sitio
Import-Module WebAdministration
Stop-WebSite -Name "VulnerableApi" -ErrorAction SilentlyContinue
Remove-WebSite -Name "VulnerableApi" -ErrorAction SilentlyContinue
Stop-WebAppPool -Name "VulnerableApi" -ErrorAction SilentlyContinue
Remove-WebAppPool -Name "VulnerableApi" -ErrorAction SilentlyContinue

# Volver a ejecutar el pipeline o el script manual
.\scripts\deploy-iis.ps1 -AppName "VulnerableApi" -Port 5000 -SourcePath "..."
```

### Etapa 5 falla: `docker: command not found`

Docker Desktop no está corriendo o no está en el PATH del agente. El servicio del agente debe ejecutarse con una cuenta que tenga acceso a Docker:

```powershell
# Verificar que Docker está corriendo
Get-Service docker | Select-Object Status

# Si el agente corre como SYSTEM, cambiarlo a una cuenta con acceso a Docker
# En el portal de Azure DevOps: Agent → Capabilities
# Agregar: docker exists
```

### El reporte HTML no incluye alertas de ZAP

El archivo `zap-report.json` no se generó o está en una ruta distinta a la esperada por `generate-report.ps1`. Verificar:

```powershell
# Ruta donde ZAP escribe los reportes (dentro del volumen montado)
Test-Path "$(Build.ArtifactStagingDirectory)\zap-report.json"

# Si ZAP guardó en una subcarpeta dast-results/, buscar ahí:
Get-ChildItem "$(Build.ArtifactStagingDirectory)" -Filter "zap-report.json" -Recurse | Select-Object FullName

# Actualizar el parámetro -ResultsPath al directorio correcto
.\scripts\generate-report.ps1 -BuildNumber "..." -ResultsPath "C:\ruta\correcta" -OutputPath "..."
```

### El pipeline no se dispara automáticamente con git push

Verificar que el branch tiene un trigger configurado en `azure-pipelines.yml`:

```yaml
trigger:
  branches:
    include:
      - main
      - develop
```

Y que la conexión del servicio del repositorio tiene permisos para notificar al pipeline. En Azure DevOps: **Project Settings → Service connections → <repo connection> → Security → Grant access**.

