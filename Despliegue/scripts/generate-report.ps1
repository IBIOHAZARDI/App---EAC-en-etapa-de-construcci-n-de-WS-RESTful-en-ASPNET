# generate-report.ps1
# Genera reporte HTML consolidado de seguridad (SAST + Asserts + DAST)

param(
    [Parameter(Mandatory)][string]$BuildNumber,
    [Parameter(Mandatory)][string]$ResultsPath,
    [Parameter(Mandatory)][string]$OutputPath
)

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$fecha     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$trxFiles  = Get-ChildItem -Path $ResultsPath -Filter "*.trx" -Recurse
$zapJson   = Join-Path $ResultsPath "zap-report.json"

# Procesar resultados de asserts (.trx)
$totalPass = 0; $totalFail = 0; $totalSkip = 0
foreach ($trx in $trxFiles) {
    [xml]$xml = Get-Content $trx.FullName
    $counters = $xml.TestRun.ResultSummary.Counters
    $totalPass += [int]$counters.passed
    $totalFail += [int]$counters.failed
    $totalSkip += [int]$counters.notExecuted
}

# Procesar resultados ZAP
$zapAlerts = @()
if (Test-Path $zapJson) {
    $zap = Get-Content $zapJson | ConvertFrom-Json
    if ($zap.site) {
        $zapAlerts = $zap.site[0].alerts | Where-Object { $_.riskcode -ge 2 }
    }
}

$statusColor = if ($totalFail -eq 0) { "#28a745" } else { "#dc3545" }
$statusText  = if ($totalFail -eq 0) { "APROBADO" } else { "FALLIDO" }

$html = @"
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Reporte Seguridad — Build $BuildNumber</title>
<style>
  body { font-family: Segoe UI, sans-serif; margin: 32px; background: #f5f5f5; }
  h1 { color: #333; } h2 { color: #555; margin-top: 32px; }
  .badge { display: inline-block; padding: 8px 20px; border-radius: 4px; color: white;
           font-weight: bold; font-size: 1.2em; background: $statusColor; }
  table { border-collapse: collapse; width: 100%; margin-top: 16px; background: white; }
  th { background: #343a40; color: white; padding: 10px; text-align: left; }
  td { padding: 8px 10px; border-bottom: 1px solid #dee2e6; }
  tr:hover { background: #f8f9fa; }
  .pass { color: #28a745; font-weight: bold; }
  .fail { color: #dc3545; font-weight: bold; }
  .warn { color: #ffc107; font-weight: bold; }
  .summary-box { background: white; padding: 20px; border-radius: 6px;
                 box-shadow: 0 1px 4px rgba(0,0,0,0.1); display: inline-block; margin: 8px; }
  .num { font-size: 2em; font-weight: bold; }
</style>
</head>
<body>
<h1>Reporte de Aseguramiento Cibersegurético</h1>
<p>Build: <strong>$BuildNumber</strong> &nbsp;|&nbsp; Fecha: <strong>$fecha</strong></p>
<p>Estado: <span class="badge">$statusText</span></p>

<h2>Resumen de Asserts (xUnit)</h2>
<div>
  <div class="summary-box">
    <div class="num pass">$totalPass</div><div>Aprobados</div>
  </div>
  <div class="summary-box">
    <div class="num fail">$totalFail</div><div>Fallidos</div>
  </div>
  <div class="summary-box">
    <div class="num warn">$totalSkip</div><div>Omitidos</div>
  </div>
</div>

<h2>Alertas DAST — OWASP ZAP (Riesgo Alto/Crítico)</h2>
"@

if ($zapAlerts.Count -gt 0) {
    $html += "<table><tr><th>Riesgo</th><th>Alerta</th><th>URL</th><th>Solución</th></tr>"
    foreach ($a in $zapAlerts) {
        $risk = switch ($a.riskcode) { 3 {"<span class='fail'>CRÍTICO</span>"} 2 {"<span class='fail'>ALTO</span>"} default {"MEDIO"} }
        $html += "<tr><td>$risk</td><td>$($a.alert)</td><td>$($a.instances[0].uri)</td><td>$($a.solution.SubString(0, [Math]::Min(120, $a.solution.Length)))...</td></tr>"
    }
    $html += "</table>"
} else {
    $html += "<p>Sin alertas de riesgo Alto o Crítico (o reporte ZAP no disponible).</p>"
}

$html += @"
<h2>Referencias</h2>
<ul>
  <li>OWASP API Security Top 10 2023</li>
  <li>MITRE ATT&amp;CK v15</li>
  <li>Microsoft SDL</li>
</ul>
<hr><p style="color:#aaa; font-size:0.85em">Generado automáticamente por el pipeline de Azure DevOps — Tesis MSI</p>
</body></html>
"@

$outFile = Join-Path $OutputPath "security-report-$BuildNumber.html"
$html | Out-File $outFile -Encoding utf8
Write-Host "Reporte generado: $outFile"
