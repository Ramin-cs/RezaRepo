#!/bin/bash
# اسکریپت نصب ابزار Decrypt کانفیگ روتر

echo "🔧 در حال نصب ابزار Decrypt کانفیگ روتر..."
echo "================================================"

# بررسی Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 یافت نشد. لطفاً Python3 را نصب کنید."
    exit 1
fi

echo "✅ Python3 یافت شد"

# بررسی pip
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 یافت نشد. لطفاً pip را نصب کنید."
    exit 1
fi

echo "✅ pip3 یافت شد"

# نصب وابستگی‌ها
echo "📦 در حال نصب وابستگی‌ها..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✅ وابستگی‌ها با موفقیت نصب شدند"
else
    echo "❌ خطا در نصب وابستگی‌ها"
    exit 1
fi

# اجازه اجرا
chmod +x router_config_decryptor.py
chmod +x advanced_router_decryptor.py
chmod +x router_gui.py

echo "✅ مجوزهای اجرا تنظیم شدند"

# ایجاد فایل‌های نمونه
echo "📝 در حال ایجاد فایل‌های نمونه..."
python3 advanced_router_decryptor.py --create-samples

echo ""
echo "🎉 نصب کامل شد!"
echo "================================================"
echo "برای استفاده:"
echo "  نسخه ساده: python3 router_config_decryptor.py"
echo "  نسخه پیشرفته: python3 advanced_router_decryptor.py"
echo "  رابط گرافیکی: python3 router_gui.py"
echo ""
echo "برای مشاهده راهنما: python3 router_config_decryptor.py -h"
echo "================================================"