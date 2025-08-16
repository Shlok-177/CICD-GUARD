@echo off
echo Building cicd-guard...
go build -o cicd-guard.exe

echo.
echo Testing with sample workflow...
cicd-guard.exe scan --path .github/workflows

echo.
echo Testing JSON output...
cicd-guard.exe scan --path .github/workflows --json

echo.
echo Testing severity filter...
cicd-guard.exe scan --path .github/workflows --severity HIGH

echo.
echo Test completed!
pause
