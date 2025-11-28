Param(
  [string]$BaseDir = (Get-Location)
)

Write-Host "Instalando herramientas..."
python -m pip install --quiet bandit safety || exit 1

Write-Host "Ejecutando bandit..."
bandit -r "$BaseDir\backend" -f html -o "$BaseDir\reports\bandit.html"

Write-Host "Auditoría de dependencias (safety)..."
safety check --full-report > "$BaseDir\reports\dependencies.txt"

Write-Host "ZAP (manual/baseline):" > "$BaseDir\reports\zap.md"
Add-Content "$BaseDir\reports\zap.md" "Ejecute OWASP ZAP Baseline Scan contra http://127.0.0.1:8000 y pegue el reporte aquí."

Write-Host "Reportes generados en $BaseDir\reports"
