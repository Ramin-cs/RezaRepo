#!/bin/bash
# ARAT External Tools Installation Script
# This script installs external tools for enhanced functionality

echo "🚀 Installing External Tools for ARAT..."

# Update package lists
echo "📦 Updating package lists..."
sudo apt update

# Install basic dependencies
echo "🔧 Installing basic dependencies..."
sudo apt install -y curl wget git python3-pip golang-go

# Create tools directory
echo "📁 Creating tools directory..."
mkdir -p /usr/local/bin
mkdir -p /usr/share/wordlists

# Install Sublist3r
echo "🔍 Installing Sublist3r..."
git clone https://github.com/aboul3la/Sublist3r.git /tmp/sublist3r
cd /tmp/sublist3r
pip3 install -r requirements.txt
sudo cp sublist3r.py /usr/local/bin/sublist3r
sudo chmod +x /usr/local/bin/sublist3r

# Install Amass
echo "🔍 Installing Amass..."
go install -v github.com/owasp-amass/amass/v4/...@master
sudo cp ~/go/bin/amass /usr/local/bin/

# Install Findomain
echo "🔍 Installing Findomain..."
wget https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux
sudo mv findomain-linux /usr/local/bin/findomain
sudo chmod +x /usr/local/bin/findomain

# Install Subfinder
echo "🔍 Installing Subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp ~/go/bin/subfinder /usr/local/bin/

# Install Assetfinder
echo "🔍 Installing Assetfinder..."
go install github.com/tomnomnom/assetfinder@latest
sudo cp ~/go/bin/assetfinder /usr/local/bin/

# Install Gobuster
echo "🔍 Installing Gobuster..."
go install github.com/OJ/gobuster/v3@latest
sudo cp ~/go/bin/gobuster /usr/local/bin/

# Install Dirsearch
echo "🔍 Installing Dirsearch..."
git clone https://github.com/maurosoria/dirsearch.git /opt/dirsearch
sudo ln -s /opt/dirsearch/dirsearch.py /usr/local/bin/dirsearch

# Install Feroxbuster
echo "🔍 Installing Feroxbuster..."
wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster-linux.tar.gz
tar -xzf feroxbuster-linux.tar.gz
sudo mv feroxbuster /usr/local/bin/

# Install Katana
echo "🕷️ Installing Katana..."
go install github.com/projectdiscovery/katana/cmd/katana@latest
sudo cp ~/go/bin/katana /usr/local/bin/

# Install Gospider
echo "🕷️ Installing Gospider..."
go install github.com/jaeles-project/gospider@latest
sudo cp ~/go/bin/gospider /usr/local/bin/

# Install ParamSpider
echo "🔍 Installing ParamSpider..."
git clone https://github.com/devanshbatham/ParamSpider.git /opt/paramspider
cd /opt/paramspider
pip3 install -r requirements.txt
sudo ln -s /opt/paramspider/paramspider.py /usr/local/bin/paramspider

# Install x8
echo "🔍 Installing x8..."
go install github.com/Sh1Yo/x8@latest
sudo cp ~/go/bin/x8 /usr/local/bin/

# Install xnLinkFinder
echo "🔍 Installing xnLinkFinder..."
git clone https://github.com/xnl-h4ck3r/xnLinkFinder.git /opt/xnLinkFinder
cd /opt/xnLinkFinder
pip3 install -r requirements.txt
sudo ln -s /opt/xnLinkFinder/xnLinkFinder.py /usr/local/bin/xnLinkFinder

# Install Wappalyzer
echo "🔍 Installing Wappalyzer..."
npm install -g wappalyzer

# Install Whatweb
echo "🔍 Installing Whatweb..."
sudo apt install -y whatweb

# Install Nmap
echo "🔍 Installing Nmap..."
sudo apt install -y nmap

# Install Waybackurls
echo "🔍 Installing Waybackurls..."
go install github.com/tomnomnom/waybackurls@latest
sudo cp ~/go/bin/waybackurls /usr/local/bin/

# Install Gau
echo "🔍 Installing Gau..."
go install github.com/lc/gau/v2/cmd/gau@latest
sudo cp ~/go/bin/gau /usr/local/bin/

# Install HTTPx
echo "🔍 Installing HTTPx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp ~/go/bin/httpx /usr/local/bin/

# Install Nuclei
echo "🔍 Installing Nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/

# Install FFuF
echo "🔍 Installing FFuF..."
go install github.com/ffuf/ffuf@latest
sudo cp ~/go/bin/ffuf /usr/local/bin/

# Install Hakrawler
echo "🔍 Installing Hakrawler..."
go install github.com/hakluke/hakrawler@latest
sudo cp ~/go/bin/hakrawler /usr/local/bin/

# Download wordlists
echo "📚 Downloading wordlists..."
sudo wget -O /usr/share/wordlists/dirb/common.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt
sudo wget -O /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/big.txt
sudo wget -O /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

# Set permissions
echo "🔐 Setting permissions..."
sudo chmod +x /usr/local/bin/*

# Cleanup
echo "🧹 Cleaning up..."
cd /
rm -rf /tmp/sublist3r
rm -f feroxbuster-linux.tar.gz

echo "✅ External tools installation completed!"
echo "📋 Installed tools:"
echo "  - Sublist3r, Amass, Findomain, Subfinder, Assetfinder"
echo "  - Gobuster, Dirsearch, Feroxbuster, Katana, Gospider"
echo "  - ParamSpider, x8, xnLinkFinder"
echo "  - Wappalyzer, Whatweb, Nmap"
echo "  - Waybackurls, Gau, HTTPx, Nuclei, FFuF, Hakrawler"
echo ""
echo "🔧 You can now configure API keys in /workspace/config/api_keys.json"
echo "⚙️ Settings can be modified in /workspace/config/settings.json"