# deploy-iis.ps1
# Despliega VulnerableApi en IIS para el ambiente de pruebas controlado
# Uso: .\deploy-iis.ps1 -AppName "VulnerableApi" -Port 5000 -SourcePath "C:\artifacts\api"

param(
    [Parameter(Mandatory)][string]$AppName,
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][string]$SourcePath,
    [string]$PhysicalPath = "C:\inetpub\$AppName",
    [string]$AppPoolIdentity = "ApplicationPoolIdentity"
)

Import-Module WebAdministration -ErrorAction Stop

function Write-Step { param($msg) Write-Host "==> $msg" -ForegroundColor Cyan }

Write-Step "Desplegando $AppName en IIS (puerto $Port)"

# Detener sitio y app pool si existen
if (Test-Path "IIS:\Sites\$AppName") {
    Write-Step "Deteniendo sitio existente..."
    Stop-WebSite -Name $AppName -ErrorAction SilentlyContinue
}
if (Test-Path "IIS:\AppPools\$AppName") {
    Write-Step "Deteniendo application pool..."
    Stop-WebAppPool -Name $AppName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Crear directorio físico
Write-Step "Preparando directorio: $PhysicalPath"
if (-not (Test-Path $PhysicalPath)) { New-Item -ItemType Directory -Path $PhysicalPath -Force | Out-Null }

# Copiar artefactos
Write-Step "Copiando artefactos desde $SourcePath"
$zipFile = Get-ChildItem -Path $SourcePath -Filter "*.zip" | Select-Object -First 1
if ($zipFile) {
    Expand-Archive -Path $zipFile.FullName -DestinationPath $PhysicalPath -Force
} else {
    Copy-Item -Path "$SourcePath\*" -Destination $PhysicalPath -Recurse -Force
}

# Crear o actualizar Application Pool
Write-Step "Configurando Application Pool: $AppName"
if (-not (Test-Path "IIS:\AppPools\$AppName")) {
    New-WebAppPool -Name $AppName
}
Set-ItemProperty "IIS:\AppPools\$AppName" -Name processModel.identityType -Value $AppPoolIdentity
Set-ItemProperty "IIS:\AppPools\$AppName" -Name managedRuntimeVersion -Value ""  # Sin runtime (ASP.NET Core)
Set-ItemProperty "IIS:\AppPools\$AppName" -Name startMode -Value "AlwaysRunning"

# Crear o actualizar sitio web
Write-Step "Configurando sitio IIS: $AppName en puerto $Port"
if (Test-Path "IIS:\Sites\$AppName") {
    Set-ItemProperty "IIS:\Sites\$AppName" -Name physicalPath -Value $PhysicalPath
    Remove-WebBinding -Name $AppName -BindingInformation "*:${Port}:" -ErrorAction SilentlyContinue
} else {
    New-Website -Name $AppName -PhysicalPath $PhysicalPath -ApplicationPool $AppName `
        -Port $Port -IPAddress "*" -Force
}

# Asegurar que el web.config de ASP.NET Core esté presente
$webConfig = Join-Path $PhysicalPath "web.config"
if (-not (Test-Path $webConfig)) {
    Write-Step "Generando web.config para ASP.NET Core..."
    @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified"/>
    </handlers>
    <aspNetCore processPath="dotnet" arguments=".\VulnerableApi.dll"
                stdoutLogEnabled="true" stdoutLogFile=".\logs\stdout"
                hostingModel="inprocess"/>
  </system.webServer>
</configuration>
"@ | Out-File $webConfig -Encoding utf8
}

# Crear directorio de logs
$logsDir = Join-Path $PhysicalPath "logs"
if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }

# Iniciar app pool y sitio
Write-Step "Iniciando Application Pool y sitio..."
Start-WebAppPool -Name $AppName
Start-Sleep -Seconds 2
Start-WebSite -Name $AppName

Write-Step "Despliegue completado. API disponible en http://localhost:$Port"
