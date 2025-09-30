#!/bin/bash

# ARAT Setup Script
echo "🚀 ARAT - Advanced Reconnaissance & Assessment Tool Setup"
echo "========================================================="

# بررسی Python
echo "📋 بررسی Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    echo "✅ Python $PYTHON_VERSION پیدا شد"
else
    echo "❌ Python3 نصب نیست. لطفاً Python 3.8+ نصب کنید."
    exit 1
fi

# بررسی pip
echo "📋 بررسی pip..."
if command -v pip3 &> /dev/null; then
    echo "✅ pip3 پیدا شد"
else
    echo "❌ pip3 نصب نیست. لطفاً pip نصب کنید."
    exit 1
fi

# ایجاد دایرکتوری‌ها
echo "📁 ایجاد دایرکتوری‌ها..."
mkdir -p data logs reports output wordlists config
echo "✅ دایرکتوری‌ها ایجاد شدند"

# نصب Python dependencies
echo "📦 نصب dependencies..."
pip3 install -r requirements.txt
if [ $? -eq 0 ]; then
    echo "✅ Dependencies نصب شدند"
else
    echo "❌ خطا در نصب dependencies"
    exit 1
fi

# بررسی ابزارهای خارجی
echo "🔧 بررسی ابزارهای خارجی..."

# Sublist3r
if command -v sublist3r &> /dev/null; then
    echo "✅ Sublist3r نصب است"
else
    echo "⚠️ Sublist3r نصب نیست. نصب کنید: pip install sublist3r"
fi

# Amass
if command -v amass &> /dev/null; then
    echo "✅ Amass نصب است"
else
    echo "⚠️ Amass نصب نیست. نصب کنید: go install -v github.com/owasp-amass/amass/v4/...@master"
fi

# Assetfinder
if command -v assetfinder &> /dev/null; then
    echo "✅ Assetfinder نصب است"
else
    echo "⚠️ Assetfinder نصب نیست. نصب کنید: go install github.com/tomnomnom/assetfinder@latest"
fi

# Subfinder
if command -v subfinder &> /dev/null; then
    echo "✅ Subfinder نصب است"
else
    echo "⚠️ Subfinder نصب نیست. نصب کنید: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
fi

# Findomain
if command -v findomain &> /dev/null; then
    echo "✅ Findomain نصب است"
else
    echo "⚠️ Findomain نصب نیست. نصب کنید: cargo install findomain"
fi

# httpx
if command -v httpx &> /dev/null; then
    echo "✅ httpx نصب است"
else
    echo "⚠️ httpx نصب نیست. نصب کنید: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
fi

# Nmap
if command -v nmap &> /dev/null; then
    echo "✅ Nmap نصب است"
else
    echo "⚠️ Nmap نصب نیست. نصب کنید: apt install nmap"
fi

# تنظیم مجوزها
echo "🔐 تنظیم مجوزها..."
chmod +x main.py
chmod +x test_arat.py
echo "✅ مجوزها تنظیم شدند"

# تست اولیه
echo "🧪 تست اولیه..."
python3 test_arat.py
if [ $? -eq 0 ]; then
    echo "✅ تست اولیه موفق بود"
else
    echo "⚠️ تست اولیه ناموفق بود"
fi

echo ""
echo "🎉 Setup تکمیل شد!"
echo ""
echo "📋 مراحل بعدی:"
echo "1. فایل config/config.yaml را ویرایش کنید"
echo "2. API keys خود را اضافه کنید"
echo "3. ابزار را اجرا کنید:"
echo "   python3 main.py --target example.com --all-phases"
echo "   یا"
echo "   python3 main.py --web-panel"
echo ""
echo "📖 برای اطلاعات بیشتر README.md را مطالعه کنید"
echo "🌐 پنل وب: http://localhost:8080"
echo ""
echo "⚠️ نکته امنیتی: این ابزار فقط برای تست نفوذ قانونی استفاده شود"