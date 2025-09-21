#!/usr/bin/env python3
"""
Test Vulnerable Web Application for XSS Scanner Testing
This creates a simple web application with various XSS vulnerabilities for testing
"""

from flask import Flask, request, render_template_string
import urllib.parse

app = Flask(__name__)

# HTML template with various XSS vulnerable endpoints
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>XSS Test Application</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .form-group { margin: 20px 0; }
        label { display: block; margin-bottom: 5px; }
        input, textarea, select { width: 100%; padding: 8px; margin-bottom: 10px; }
        button { background: #007cba; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .result { background: #f0f0f0; padding: 15px; margin: 20px 0; border-left: 4px solid #007cba; }
        .vulnerable { border-left-color: #ff0000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>XSS Test Application</h1>
        <p>This application contains various XSS vulnerabilities for testing purposes.</p>
        
        <h2>Test Forms</h2>
        
        <!-- Form 1: Basic HTML Context -->
        <form method="POST" action="/form1">
            <div class="form-group">
                <label for="name1">Name (HTML Context):</label>
                <input type="text" id="name1" name="name" placeholder="Enter your name">
            </div>
            <button type="submit">Submit</button>
        </form>
        
        <!-- Form 2: Attribute Context -->
        <form method="POST" action="/form2">
            <div class="form-group">
                <label for="search2">Search (Attribute Context):</label>
                <input type="text" id="search2" name="search" placeholder="Search term">
            </div>
            <button type="submit">Search</button>
        </form>
        
        <!-- Form 3: JavaScript Context -->
        <form method="POST" action="/form3">
            <div class="form-group">
                <label for="message3">Message (JavaScript Context):</label>
                <textarea id="message3" name="message" placeholder="Enter message"></textarea>
            </div>
            <button type="submit">Submit</button>
        </form>
        
        <!-- Form 4: CSS Context -->
        <form method="POST" action="/form4">
            <div class="form-group">
                <label for="color4">Color (CSS Context):</label>
                <input type="text" id="color4" name="color" placeholder="Enter color">
            </div>
            <button type="submit">Submit</button>
        </form>
        
        <!-- Form 5: URL Context -->
        <form method="GET" action="/form5">
            <div class="form-group">
                <label for="url5">URL (URL Context):</label>
                <input type="text" id="url5" name="url" placeholder="Enter URL">
            </div>
            <button type="submit">Submit</button>
        </form>
        
        <!-- Results will be displayed here -->
        {% if result %}
        <div class="result {{ 'vulnerable' if is_vulnerable else '' }}">
            <h3>Result:</h3>
            {{ result|safe }}
        </div>
        {% endif %}
        
        <h2>Direct URL Testing</h2>
        <p>You can also test direct URL parameters:</p>
        <ul>
            <li><a href="/?param1=test">/?param1=test</a></li>
            <li><a href="/?search=test">/?search=test</a></li>
            <li><a href="/?message=test">/?message=test</a></li>
        </ul>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """Main page with forms"""
    param1 = request.args.get('param1', '')
    search = request.args.get('search', '')
    message = request.args.get('message', '')
    
    result = ""
    is_vulnerable = False
    
    if param1:
        result = f"<p>Parameter 1: {param1}</p>"
        is_vulnerable = True
    elif search:
        result = f"<p>Search: {search}</p>"
        is_vulnerable = True
    elif message:
        result = f"<p>Message: {message}</p>"
        is_vulnerable = True
    
    return render_template_string(HTML_TEMPLATE, result=result, is_vulnerable=is_vulnerable)

@app.route('/form1', methods=['POST'])
def form1():
    """HTML Context XSS"""
    name = request.form.get('name', '')
    result = f"<h3>Hello, {name}!</h3><p>Welcome to our site.</p>"
    return render_template_string(HTML_TEMPLATE, result=result, is_vulnerable=True)

@app.route('/form2', methods=['POST'])
def form2():
    """Attribute Context XSS"""
    search = request.form.get('search', '')
    result = f'<h3>Search Results for: <span style="color: {search};">{search}</span></h3>'
    return render_template_string(HTML_TEMPLATE, result=result, is_vulnerable=True)

@app.route('/form3', methods=['POST'])
def form3():
    """JavaScript Context XSS"""
    message = request.form.get('message', '')
    result = f"""
    <h3>Message Processing</h3>
    <script>
        var userMessage = "{message}";
        document.write("<p>Your message: " + userMessage + "</p>");
    </script>
    """
    return render_template_string(HTML_TEMPLATE, result=result, is_vulnerable=True)

@app.route('/form4', methods=['POST'])
def form4():
    """CSS Context XSS"""
    color = request.form.get('color', '')
    result = f"""
    <h3>Color Selection</h3>
    <style>
        .user-color {{ color: {color}; }}
    </style>
    <p class="user-color">This text uses your selected color: {color}</p>
    """
    return render_template_string(HTML_TEMPLATE, result=result, is_vulnerable=True)

@app.route('/form5', methods=['GET'])
def form5():
    """URL Context XSS"""
    url = request.args.get('url', '')
    result = f"""
    <h3>URL Processing</h3>
    <p>You provided URL: <a href="{url}">{url}</a></p>
    <p>Redirecting to: {url}</p>
    """
    return render_template_string(HTML_TEMPLATE, result=result, is_vulnerable=True)

@app.route('/api/search')
def api_search():
    """API endpoint for testing"""
    query = request.args.get('q', '')
    return f'{{"query": "{query}", "results": []}}'

@app.route('/api/user')
def api_user():
    """API endpoint for user data"""
    user_id = request.args.get('id', '')
    return f'{{"id": "{user_id}", "name": "User {user_id}"}}'

if __name__ == '__main__':
    print("Starting XSS Test Application...")
    print("Access the application at: http://localhost:5000")
    print("This application contains various XSS vulnerabilities for testing.")
    print("Use Ctrl+C to stop the server.")
    app.run(debug=True, host='0.0.0.0', port=5000)