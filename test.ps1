Write-Host "Building cicd-guard..." -ForegroundColor Green
go build -o cicd-guard.exe

Write-Host "`nTesting with sample workflow..." -ForegroundColor Yellow
.\cicd-guard.exe scan --path .github/workflows

Write-Host "`nTesting JSON output..." -ForegroundColor Yellow
.\cicd-guard.exe scan --path .github/workflows --json

Write-Host "`nTesting severity filter..." -ForegroundColor Yellow
.\cicd-guard.exe scan --path .github/workflows --severity HIGH

Write-Host "`nTest completed!" -ForegroundColor Green
Read-Host "Press Enter to continue"
