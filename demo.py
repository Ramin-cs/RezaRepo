#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Demo script for Advanced XSS Scanner
اسکریپت دمو برای ابزار پیشرفته تشخیص XSS
"""

import http.server
import socketserver
import threading
import time
import webbrowser
from urllib.parse import parse_qs, urlparse
import html

class VulnerableHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP Request Handler with intentional XSS vulnerabilities for demo"""
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        if path == '/':
            self.serve_main_page(query_params)
        elif path == '/search':
            self.serve_search_page(query_params)
        elif path == '/contact':
            self.serve_contact_page(query_params)
        elif path == '/profile':
            self.serve_profile_page(query_params)
        elif path == '/api/data':
            self.serve_api_endpoint(query_params)
        else:
            self.send_error(404, "Page not found")
    
    def do_POST(self):
        """Handle POST requests"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        parsed_data = parse_qs(post_data)
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/contact':
            self.serve_contact_form_response(parsed_data)
        elif path == '/login':
            self.serve_login_response(parsed_data)
        else:
            self.send_error(404, "Endpoint not found")
    
    def serve_main_page(self, params):
        """Serve main page with navigation"""
        name = params.get('name', [''])[0]
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Demo Vulnerable Site</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }}
        nav {{ margin: 20px 0; }}
        nav a {{ margin-right: 20px; color: #667eea; text-decoration: none; padding: 10px 15px; border: 1px solid #667eea; border-radius: 5px; }}
        nav a:hover {{ background: #667eea; color: white; }}
        .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        input[type="text"] {{ padding: 10px; border: 1px solid #ddd; border-radius: 5px; width: 200px; }}
        button {{ background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Demo Vulnerable Website</h1>
            <p>برای تست Advanced XSS Scanner</p>
        </div>
        
        <div class="warning">
            ⚠️ <strong>هشدار:</strong> این سایت عمداً آسیب‌پذیر طراحی شده و فقط برای تست ابزار XSS Scanner است.
        </div>
        
        <nav>
            <a href="/">🏠 خانه</a>
            <a href="/search">🔍 جستجو</a>
            <a href="/contact">📧 تماس</a>
            <a href="/profile">👤 پروفایل</a>
            <a href="/api/data">📊 API</a>
        </nav>
        
        <h2>خوش آمدید!</h2>
        {f'<p>سلام <strong>{name}</strong>! خوش آمدید.</p>' if name else ''}
        
        <h3>نقاط تست موجود:</h3>
        <ul>
            <li><strong>Reflected XSS در URL Parameter:</strong> <code>/?name=YOUR_PAYLOAD</code></li>
            <li><strong>Search Form:</strong> فرم جستجو در صفحه /search</li>
            <li><strong>Contact Form:</strong> فرم تماس در صفحه /contact</li>
            <li><strong>Header Reflection:</strong> تست هدرهای HTTP</li>
            <li><strong>API Endpoint:</strong> /api/data?callback=YOUR_PAYLOAD</li>
        </ul>
        
        <h3>تست سریع:</h3>
        <form>
            <input type="text" name="name" placeholder="نام خود را وارد کنید" value="{html.escape(name)}">
            <button type="submit">ارسال</button>
        </form>
    </div>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_search_page(self, params):
        """Serve search page with XSS vulnerability"""
        query = params.get('q', [''])[0]
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>جستجو - Demo Vulnerable Site</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }}
        nav {{ margin: 20px 0; }}
        nav a {{ margin-right: 20px; color: #667eea; text-decoration: none; }}
        input[type="text"] {{ padding: 10px; border: 1px solid #ddd; border-radius: 5px; width: 300px; }}
        button {{ background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }}
        .results {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 جستجو</h1>
        </div>
        
        <nav>
            <a href="/">← بازگشت به خانه</a>
        </nav>
        
        <form method="GET">
            <input type="text" name="q" placeholder="جستجو کنید..." value="{html.escape(query)}">
            <button type="submit">جستجو</button>
        </form>
        
        {f'''
        <div class="results">
            <h3>نتایج جستجو برای: {query}</h3>
            <p>متأسفانه هیچ نتیجه‌ای برای "{query}" یافت نشد.</p>
        </div>
        ''' if query else ''}
        
        <div style="margin-top: 30px; padding: 15px; background: #e3f2fd; border-radius: 5px;">
            <strong>🎯 نکته تست:</strong> این صفحه دارای آسیب‌پذیری Reflected XSS در پارامتر 'q' است.
        </div>
    </div>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_contact_page(self, params):
        """Serve contact form page"""
        html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>تماس با ما - Demo Vulnerable Site</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }
        nav { margin: 20px 0; }
        nav a { margin-right: 20px; color: #667eea; text-decoration: none; }
        .form-group { margin: 15px 0; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"], textarea { padding: 10px; border: 1px solid #ddd; border-radius: 5px; width: 100%; box-sizing: border-box; }
        textarea { height: 100px; resize: vertical; }
        button { background: #667eea; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📧 تماس با ما</h1>
        </div>
        
        <nav>
            <a href="/">← بازگشت به خانه</a>
        </nav>
        
        <form method="POST" action="/contact">
            <div class="form-group">
                <label for="name">نام:</label>
                <input type="text" id="name" name="name" required>
            </div>
            
            <div class="form-group">
                <label for="email">ایمیل:</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label for="subject">موضوع:</label>
                <input type="text" id="subject" name="subject" required>
            </div>
            
            <div class="form-group">
                <label for="message">پیام:</label>
                <textarea id="message" name="message" required></textarea>
            </div>
            
            <button type="submit">ارسال پیام</button>
        </form>
        
        <div style="margin-top: 30px; padding: 15px; background: #e3f2fd; border-radius: 5px;">
            <strong>🎯 نکته تست:</strong> این فرم دارای آسیب‌پذیری XSS در فیلدهای ورودی است.
        </div>
    </div>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_contact_form_response(self, data):
        """Handle contact form submission"""
        name = data.get('name', [''])[0]
        email = data.get('email', [''])[0]
        subject = data.get('subject', [''])[0]
        message = data.get('message', [''])[0]
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>پیام ارسال شد - Demo Vulnerable Site</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }}
        nav {{ margin: 20px 0; }}
        nav a {{ margin-right: 20px; color: #667eea; text-decoration: none; }}
        .success {{ background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✅ پیام ارسال شد</h1>
        </div>
        
        <nav>
            <a href="/">← بازگشت به خانه</a>
            <a href="/contact">ارسال پیام جدید</a>
        </nav>
        
        <div class="success">
            <strong>متشکریم!</strong> پیام شما با موفقیت ارسال شد.
        </div>
        
        <h3>اطلاعات دریافت شده:</h3>
        <p><strong>نام:</strong> {name}</p>
        <p><strong>ایمیل:</strong> {email}</p>
        <p><strong>موضوع:</strong> {subject}</p>
        <p><strong>پیام:</strong></p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0;">
            {message}
        </div>
    </div>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_profile_page(self, params):
        """Serve profile page with User-Agent reflection"""
        user_agent = self.headers.get('User-Agent', 'Unknown')
        user_id = params.get('id', ['1'])[0]
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>پروفایل کاربر - Demo Vulnerable Site</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; margin: -30px -30px 30px -30px; border-radius: 10px 10px 0 0; }}
        nav {{ margin: 20px 0; }}
        nav a {{ margin-right: 20px; color: #667eea; text-decoration: none; }}
        .info {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>👤 پروفایل کاربر</h1>
        </div>
        
        <nav>
            <a href="/">← بازگشت به خانه</a>
        </nav>
        
        <h2>اطلاعات کاربر #{user_id}</h2>
        
        <div class="info">
            <strong>شناسه کاربر:</strong> {user_id}
        </div>
        
        <div class="info">
            <strong>مرورگر شما:</strong> {user_agent}
        </div>
        
        <div class="info">
            <strong>IP Address:</strong> {self.client_address[0]}
        </div>
        
        <div style="margin-top: 30px; padding: 15px; background: #e3f2fd; border-radius: 5px;">
            <strong>🎯 نکته تست:</strong> این صفحه User-Agent را بدون فیلتر نمایش می‌دهد و دارای آسیب‌پذیری Header-based XSS است.
        </div>
    </div>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def serve_api_endpoint(self, params):
        """Serve API endpoint with JSONP vulnerability"""
        callback = params.get('callback', [''])[0]
        data = '{"users": [{"id": 1, "name": "احمد"}, {"id": 2, "name": "فاطمه"}]}'
        
        if callback:
            response = f"{callback}({data});"
            content_type = 'application/javascript'
        else:
            response = data
            content_type = 'application/json'
        
        self.send_response(200)
        self.send_header('Content-type', f'{content_type}; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response.encode('utf-8'))

def start_demo_server(port=8080):
    """Start the demo vulnerable server"""
    handler = VulnerableHTTPRequestHandler
    
    try:
        with socketserver.TCPServer(("", port), handler) as httpd:
            print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    Demo Vulnerable Server                    ║
║                   سرور آسیب‌پذیر تست                         ║
╠══════════════════════════════════════════════════════════════╣
║ Server started on: http://localhost:{port:<4}                   ║
║ Press Ctrl+C to stop the server                             ║
╚══════════════════════════════════════════════════════════════╝

🎯 Test URLs:
  • Main page: http://localhost:{port}/
  • Search: http://localhost:{port}/search?q=test
  • Contact: http://localhost:{port}/contact
  • Profile: http://localhost:{port}/profile?id=1
  • API: http://localhost:{port}/api/data?callback=test

🔍 XSS Test Examples:
  • Reflected XSS: http://localhost:{port}/?name=<script>alert('XSS')</script>
  • Search XSS: http://localhost:{port}/search?q=<img src=x onerror=alert('XSS')>
  • Header XSS: curl -H "User-Agent: <script>alert('XSS')</script>" http://localhost:{port}/profile
  • JSONP XSS: http://localhost:{port}/api/data?callback=alert('XSS');//

🚀 To test with XSS Scanner:
  python advanced_xss_scanner.py -u http://localhost:{port}
            """)
            
            # Open browser
            try:
                webbrowser.open(f'http://localhost:{port}')
            except:
                pass
            
            httpd.serve_forever()
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"❌ Port {port} is already in use. Trying port {port + 1}...")
            start_demo_server(port + 1)
        else:
            print(f"❌ Failed to start server: {e}")
    except KeyboardInterrupt:
        print("\n👋 Demo server stopped.")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Demo Vulnerable Server for XSS Testing')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to run the server on (default: 8080)')
    
    args = parser.parse_args()
    
    start_demo_server(args.port)