# ARAT - Advanced Reconnaissance & Assessment Tool
FROM python:3.11-slim

# تنظیم متغیرهای محیطی
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# نصب dependencies سیستم
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    nmap \
    dnsutils \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# ایجاد کاربر غیر root
RUN useradd -m -s /bin/bash arat

# تنظیم دایرکتوری کار
WORKDIR /app

# کپی فایل‌های requirements
COPY requirements.txt .

# نصب Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# کپی کد منبع
COPY . .

# ایجاد دایرکتوری‌های مورد نیاز
RUN mkdir -p data logs reports output wordlists config

# تنظیم مجوزها
RUN chown -R arat:arat /app

# تغییر به کاربر غیر root
USER arat

# تنظیم port
EXPOSE 8080

# دستور پیش‌فرض
CMD ["python", "main.py", "--web-panel", "--host", "0.0.0.0", "--port", "8080"]