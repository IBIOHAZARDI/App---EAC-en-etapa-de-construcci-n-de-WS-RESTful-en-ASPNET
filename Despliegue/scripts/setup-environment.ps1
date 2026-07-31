# setup-environment.ps1
# Prepara el ambiente de pruebas en Windows Server con IIS para ejecutar la estrategia de asserts
# Ejecutar como Administrador

#Requires -RunAsAdministrator

param(
    [string]$DotNetVersion    = "8.0",
    [string]$ZapInstallerUrl  = "https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Windows.exe",
    [string]$WorkDir          = "C:\CybersecTest"
)

function Write-Step { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "    [OK] $msg" -ForegroundColor Green }
function Write-WARN { param($msg) Write-Host "    [WARN] $msg" -ForegroundColor Yellow }

Write-Host "=== Setup Ambiente Pruebas Ciberseguridad ===" -ForegroundColor Magenta

# --------------------------------------------------------
# 1. Instalar IIS con módulos necesarios
# --------------------------------------------------------
Write-Step "Habilitando IIS y módulos necesarios..."
$features = @(
    "Web-Server",
    "Web-WebServer",
    "Web-Common-Http",
    "Web-Asp-Net45",
    "Web-Net-Ext45",
    "Web-ISAPI-Ext",
    "Web-ISAPI-Filter",
    "Web-Mgmt-Console"
)
foreach ($f in $features) {
    $state = (Get-WindowsFeature $f).Installed
    if (-not $state) {
        Install-WindowsFeature $f -ErrorAction SilentlyContinue | Out-Null
        Write-OK "Habilitado: $f"
    } else {
        Write-OK "Ya instalado: $f"
    }
}

# --------------------------------------------------------
# 2. Instalar ASP.NET Core Hosting Bundle
# --------------------------------------------------------
Write-Step "Verificando ASP.NET Core Hosting Bundle $DotNetVersion..."
$dotnetCheck = dotnet --version 2>$null
if ($dotnetCheck -and $dotnetCheck.StartsWith($DotNetVersion)) {
    Write-OK ".NET $DotNetVersion ya instalado ($dotnetCheck)"
} else {
    Write-WARN ".NET $DotNetVersion no encontrado. Descargando Hosting Bundle..."
    $bundleUrl = "https://download.visualstudio.microsoft.com/download/pr/0cd5d8ab-8f9b-4cf1-bf93-a3f69ef52abd/a98fcce5c4a1e6e3ceac9d6c3c8acf19/dotnet-hosting-8.0.8-win.exe"
    $installer = "$env:TEMP\dotnet-hosting-$DotNetVersion.exe"
    Invoke-WebRequest -Uri $bundleUrl -OutFile $installer
    Start-Process -FilePath $installer -ArgumentList "/quiet /norestart" -Wait
    Write-OK "Hosting Bundle instalado. Reiniciar IIS con: iisreset"
}

# --------------------------------------------------------
# 3. Crear directorio de trabajo
# --------------------------------------------------------
Write-Step "Preparando directorio de trabajo: $WorkDir"
if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null }
@("artifacts", "reports", "logs") | ForEach-Object {
    $d = Join-Path $WorkDir $_
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d | Out-Null }
}
Write-OK "Directorios creados en $WorkDir"

# --------------------------------------------------------
# 4. Verificar Docker (para OWASP ZAP en contenedor)
# --------------------------------------------------------
Write-Step "Verificando Docker para OWASP ZAP..."
try {
    $dockerVersion = docker --version 2>$null
    if ($dockerVersion) {
        Write-OK "Docker disponible: $dockerVersion"
        docker pull ghcr.io/zaproxy/zaproxy:stable 2>&1 | Write-Host
        Write-OK "Imagen ZAP descargada"
    }
} catch {
    Write-WARN "Docker no disponible. ZAP se ejecutará como instalación local."
    Write-WARN "Descargar ZAP desde: $ZapInstallerUrl"
}

# --------------------------------------------------------
# 5. Configurar regla de firewall para puerto 5000
# --------------------------------------------------------
Write-Step "Configurando firewall para puerto 5000..."
$ruleName = "CybersecTest-API-5000"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName `
        -Direction Inbound -Protocol TCP -LocalPort 5000 `
        -Action Allow -Profile Domain,Private | Out-Null
    Write-OK "Regla de firewall creada: $ruleName"
} else {
    Write-OK "Regla de firewall ya existe"
}

# --------------------------------------------------------
# 6. Variables de entorno para el agente DevOps
# --------------------------------------------------------
Write-Step "Configurando variables de entorno..."
[System.Environment]::SetEnvironmentVariable("TEST_API_URL", "http://localhost:5000", "Machine")
[System.Environment]::SetEnvironmentVariable("CYBERSEC_WORK_DIR", $WorkDir, "Machine")
Write-OK "TEST_API_URL=http://localhost:5000 (Machine)"
Write-OK "CYBERSEC_WORK_DIR=$WorkDir (Machine)"

# --------------------------------------------------------
# Resumen
# --------------------------------------------------------
Write-Host "`n=== Configuración completada ===" -ForegroundColor Magenta
Write-Host "Próximos pasos:"
Write-Host "  1. Reiniciar IIS: iisreset"
Write-Host "  2. Registrar agente Azure DevOps self-hosted en este servidor"
Write-Host "  3. Ejecutar el pipeline desde Azure DevOps"
Write-Host "  4. Ver reportes en $WorkDir\reports"
