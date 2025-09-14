@echo off
echo 🚀 Installing Image to HTML/CSS Converter for Windows...
echo.

echo 📦 Removing Sharp module...
npm uninstall sharp

echo 🗑️ Cleaning node_modules...
if exist node_modules rmdir /s /q node_modules
if exist package-lock.json del package-lock.json

echo 📥 Installing dependencies...
npm install

echo ✅ Installation completed!
echo.
echo 🎉 You can now run: npm start
echo 🌐 Then open: http://localhost:3000
echo.
pause