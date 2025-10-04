@echo off
REM ARAT External Tools Installation Script for Windows
REM This script installs external tools for enhanced functionality

echo 🚀 Installing External Tools for ARAT on Windows...

REM Install Chocolatey if not already installed
echo 📦 Installing Chocolatey...
powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

REM Install Git
echo 🔧 Installing Git...
choco install git -y

REM Install Python
echo 🐍 Installing Python...
choco install python -y

REM Install Go
echo 🔧 Installing Go...
choco install golang -y

REM Install Node.js
echo 🔧 Installing Node.js...
choco install nodejs -y

REM Install Nmap
echo 🔍 Installing Nmap...
choco install nmap -y

REM Create tools directory
echo 📁 Creating tools directory...
mkdir C:\tools 2>nul
mkdir C:\wordlists 2>nul

REM Install Sublist3r
echo 🔍 Installing Sublist3r...
git clone https://github.com/aboul3la/Sublist3r.git C:\tools\sublist3r
cd C:\tools\sublist3r
pip install -r requirements.txt

REM Install Amass
echo 🔍 Installing Amass...
go install -v github.com/owasp-amass/amass/v4/...@master
copy %USERPROFILE%\go\bin\amass.exe C:\tools\

REM Install Findomain
echo 🔍 Installing Findomain...
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/Findomain/Findomain/releases/latest/download/findomain-windows.exe' -OutFile 'C:\tools\findomain.exe'"

REM Install Subfinder
echo 🔍 Installing Subfinder...
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
copy %USERPROFILE%\go\bin\subfinder.exe C:\tools\

REM Install Assetfinder
echo 🔍 Installing Assetfinder...
go install github.com/tomnomnom/assetfinder@latest
copy %USERPROFILE%\go\bin\assetfinder.exe C:\tools\

REM Install Gobuster
echo 🔍 Installing Gobuster...
go install github.com/OJ/gobuster/v3@latest
copy %USERPROFILE%\go\bin\gobuster.exe C:\tools\

REM Install Dirsearch
echo 🔍 Installing Dirsearch...
git clone https://github.com/maurosoria/dirsearch.git C:\tools\dirsearch

REM Install Feroxbuster
echo 🔍 Installing Feroxbuster...
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster-windows.zip' -OutFile 'C:\tools\feroxbuster.zip'"
powershell -Command "Expand-Archive -Path 'C:\tools\feroxbuster.zip' -DestinationPath 'C:\tools\feroxbuster'"

REM Install Katana
echo 🕷️ Installing Katana...
go install github.com/projectdiscovery/katana/cmd/katana@latest
copy %USERPROFILE%\go\bin\katana.exe C:\tools\

REM Install Gospider
echo 🕷️ Installing Gospider...
go install github.com/jaeles-project/gospider@latest
copy %USERPROFILE%\go\bin\gospider.exe C:\tools\

REM Install ParamSpider
echo 🔍 Installing ParamSpider...
git clone https://github.com/devanshbatham/ParamSpider.git C:\tools\paramspider
cd C:\tools\paramspider
pip install -r requirements.txt

REM Install x8
echo 🔍 Installing x8...
go install github.com/Sh1Yo/x8@latest
copy %USERPROFILE%\go\bin\x8.exe C:\tools\

REM Install xnLinkFinder
echo 🔍 Installing xnLinkFinder...
git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git C:\tools\xnLinkFinder
cd C:\tools\xnLinkFinder
pip install -r requirements.txt

REM Install Wappalyzer
echo 🔍 Installing Wappalyzer...
npm install -g wappalyzer

REM Install Whatweb
echo 🔍 Installing Whatweb...
choco install whatweb -y

REM Install Waybackurls
echo 🔍 Installing Waybackurls...
go install github.com/tomnomnom/waybackurls@latest
copy %USERPROFILE%\go\bin\waybackurls.exe C:\tools\

REM Install Gau
echo 🔍 Installing Gau...
go install github.com/lc/gau/v2/cmd/gau@latest
copy %USERPROFILE%\go\bin\gau.exe C:\tools\

REM Install HTTPx
echo 🔍 Installing HTTPx...
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
copy %USERPROFILE%\go\bin\httpx.exe C:\tools\

REM Install Nuclei
echo 🔍 Installing Nuclei...
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
copy %USERPROFILE%\go\bin\nuclei.exe C:\tools\

REM Install FFuF
echo 🔍 Installing FFuF...
go install github.com/ffuf/ffuf@latest
copy %USERPROFILE%\go\bin\ffuf.exe C:\tools\

REM Install Hakrawler
echo 🔍 Installing Hakrawler...
go install github.com/hakluke/hakrawler@latest
copy %USERPROFILE%\go\bin\hakrawler.exe C:\tools\

REM Download wordlists
echo 📚 Downloading wordlists...
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt' -OutFile 'C:\wordlists\common.txt'"
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/v0re/dirb/master/wordlists/big.txt' -OutFile 'C:\wordlists\big.txt'"
powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt' -OutFile 'C:\wordlists\seclists-common.txt'"

REM Add tools to PATH
echo 🔧 Adding tools to PATH...
setx PATH "%PATH%;C:\tools" /M

echo ✅ External tools installation completed!
echo 📋 Installed tools:
echo   - Sublist3r, Amass, Findomain, Subfinder, Assetfinder
echo   - Gobuster, Dirsearch, Feroxbuster, Katana, Gospider
echo   - ParamSpider, x8, xnLinkFinder
echo   - Wappalyzer, Whatweb, Nmap
echo   - Waybackurls, Gau, HTTPx, Nuclei, FFuF, Hakrawler
echo.
echo 🔧 You can now configure API keys in /workspace/config/api_keys.json
echo ⚙️ Settings can be modified in /workspace/config/settings.json
echo.
echo 🔄 Please restart your command prompt to use the new tools.

pause