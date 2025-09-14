# 🖼️ تبدیل عکس به HTML/CSS

برنامه ساده و کاربردی برای تبدیل عکس‌های طراحی به کد HTML و CSS

## 🚀 نصب و راه‌اندازی

### پیش‌نیازها
- Node.js (نسخه 14 یا بالاتر)
- npm

### نصب
```bash
npm install
```

### اجرا
```bash
npm start
```

سپس به آدرس `http://localhost:3000` بروید.

## 📖 نحوه استفاده

1. **آپلود عکس**: عکس طراحی خود را آپلود کنید
2. **تبدیل**: روی دکمه "تبدیل به HTML/CSS" کلیک کنید
3. **دانلود**: فایل‌های HTML و CSS را دانلود کنید
4. **پیش‌نمایش**: نتیجه را در مرورگر مشاهده کنید

## 🎯 ویژگی‌ها

- ✅ تبدیل خودکار عکس به HTML/CSS
- ✅ تشخیص عناصر (متن، تصویر)
- ✅ استخراج رنگ‌های اصلی
- ✅ طراحی ریسپانسیو
- ✅ پشتیبانی از RTL
- ✅ رابط کاربری ساده و زیبا

## 📁 ساختار پروژه

```
📁 workspace/
   📁 public/          # فایل‌های فرانت‌اند
      📄 index.html    # صفحه اصلی
      📄 styles.css    # استایل‌های صفحه
      📄 script.js     # JavaScript
   📁 src/             # کدهای بک‌اند
      📄 imageToHTMLConverter.js
   📄 server.js        # سرور Express
   📄 package.json     # تنظیمات پروژه
```

## 🔧 API

### POST /api/convert
آپلود عکس و دریافت HTML/CSS

**پارامترها:**
- `image`: فایل عکس (multipart/form-data)

**پاسخ:**
```json
{
  "success": true,
  "html": "...",
  "css": "...",
  "analysis": {
    "width": 800,
    "height": 600,
    "colors": {...},
    "elements": [...]
  }
}
```

## 📝 فرمت‌های پشتیبانی شده

- JPG/JPEG
- PNG
- GIF
- WebP

## 🎨 مثال خروجی

```html
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>تبدیل شده از عکس</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="image-container">
        <div class="text-element">عنوان اصلی</div>
        <div class="image-element">🖼️ تصویر اصلی</div>
    </div>
</body>
</html>
```

## 📄 مجوز

MIT License

---

**ساخته شده با ❤️ برای تبدیل آسان عکس به کد**