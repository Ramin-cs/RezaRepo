# PowerShell script for Windows installation
Write-Host "🚀 Installing Image to HTML/CSS Converter for Windows..." -ForegroundColor Green
Write-Host ""

# Remove Sharp module
Write-Host "📦 Removing Sharp module..." -ForegroundColor Yellow
npm uninstall sharp

# Clean node_modules
Write-Host "🗑️ Cleaning node_modules..." -ForegroundColor Yellow
if (Test-Path "node_modules") {
    Remove-Item -Recurse -Force "node_modules"
}
if (Test-Path "package-lock.json") {
    Remove-Item -Force "package-lock.json"
}

# Install dependencies
Write-Host "📥 Installing dependencies..." -ForegroundColor Yellow
npm install

Write-Host ""
Write-Host "✅ Installation completed!" -ForegroundColor Green
Write-Host ""
Write-Host "🎉 You can now run: npm start" -ForegroundColor Cyan
Write-Host "🌐 Then open: http://localhost:3000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")