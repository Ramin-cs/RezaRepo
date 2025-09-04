# 📧 Professional Email Sender - Complete Usage Guide

## 🚀 Quick Start

The easiest way to get started is by running the quick start script:

```bash
python quick_start.py
```

This interactive script will:
1. Help you configure your SMTP server
2. Test the connection
3. Send a test email
4. Provide a menu for all features

## 📋 Table of Contents

1. [Installation & Setup](#installation--setup)
2. [SMTP Configuration](#smtp-configuration)
3. [Sending Single Emails](#sending-single-emails)
4. [Sending Bulk Emails](#sending-bulk-emails)
5. [Using Templates](#using-templates)
6. [Advanced Features](#advanced-features)
7. [Anti-Spam Best Practices](#anti-spam-best-practices)
8. [Troubleshooting](#troubleshooting)

## 🔧 Installation & Setup

### Requirements
- Python 3.6 or higher
- Internet connection for SMTP servers

### Installation
```bash
# Clone or download the project
# No additional packages needed - uses Python standard library only
```

### Quick Setup
```bash
python quick_start.py
```

## ⚙️ SMTP Configuration

### Supported Email Providers

#### Gmail
```python
smtp_config = {
    'server': 'smtp.gmail.com',
    'port': 587,
    'security': 'tls',
    'username': 'your_email@gmail.com',
    'password': 'your_app_password'  # Use App Password, not regular password
}
```

**Important for Gmail:**
1. Enable 2-Factor Authentication
2. Generate an App Password: Google Account → Security → App Passwords
3. Use the App Password instead of your regular password

#### Outlook/Hotmail
```python
smtp_config = {
    'server': 'smtp-mail.outlook.com',
    'port': 587,
    'security': 'tls',
    'username': 'your_email@outlook.com',
    'password': 'your_password'
}
```

#### Yahoo Mail
```python
smtp_config = {
    'server': 'smtp.mail.yahoo.com',
    'port': 587,
    'security': 'tls',
    'username': 'your_email@yahoo.com',
    'password': 'your_app_password'  # Generate App Password in Yahoo settings
}
```

#### Office 365
```python
smtp_config = {
    'server': 'smtp.office365.com',
    'port': 587,
    'security': 'tls',
    'username': 'your_email@yourdomain.com',
    'password': 'your_password'
}
```

#### Custom SMTP Server
```python
smtp_config = {
    'server': 'mail.yourdomain.com',
    'port': 587,  # or 465 for SSL, 25 for non-encrypted
    'security': 'tls',  # or 'ssl' or 'none'
    'username': 'your_username',
    'password': 'your_password'
}
```

## 📧 Sending Single Emails

### Basic Example

```python
from email_sender import ProfessionalEmailSender

# Initialize the email sender
email_sender = ProfessionalEmailSender()

# Configure SMTP
smtp_config = {
    'server': 'smtp.gmail.com',
    'port': 587,
    'security': 'tls',
    'username': 'your_email@gmail.com',
    'password': 'your_app_password'
}

# Simple HTML content
html_content = """
<html>
<body>
    <h2>Hello!</h2>
    <p>This is a test email from the Professional Email Sender.</p>
    <p>Best regards,<br>Your Team</p>
</body>
</html>
"""

# Send the email
success = email_sender.send_email(
    smtp_config=smtp_config,
    sender_email='your_email@gmail.com',
    sender_name='Your Name',
    recipient_email='recipient@example.com',
    recipient_name='Recipient Name',
    subject='Test Email',
    html_content=html_content,
    company_name='Your Company',
    department='IT Department'
)

if success:
    print("Email sent successfully!")
else:
    print("Failed to send email!")
```

### Advanced Single Email

```python
# Custom headers
custom_headers = {
    'X-Campaign-ID': 'newsletter-001',
    'X-Email-Type': 'marketing',
    'Reply-To': 'support@yourcompany.com'
}

# Send with all options
success = email_sender.send_email(
    smtp_config=smtp_config,
    sender_email='marketing@yourcompany.com',
    sender_name='Marketing Team',
    recipient_email='customer@example.com',
    recipient_name='John Smith',
    subject='Special Offer Just for You!',
    html_content=html_content,
    text_content='Plain text version of your email',  # Optional fallback
    custom_headers=custom_headers,
    company_name='Your Company Inc',
    department='Marketing Department',
    priority='high',  # 'low', 'normal', or 'high'
    attachments=['document.pdf', 'image.jpg']  # List of file paths
)
```

## 📮 Sending Bulk Emails

### Prepare Recipients File

Create a JSON file with recipient information:

```json
[
    {
        "email": "john@example.com",
        "name": "John Smith",
        "variables": {
            "first_name": "John",
            "company": "ABC Corp",
            "special_offer": "20% discount"
        }
    },
    {
        "email": "sarah@example.com",
        "name": "Sarah Johnson",
        "variables": {
            "first_name": "Sarah",
            "company": "XYZ Inc",
            "special_offer": "15% discount"
        }
    }
]
```

### Bulk Email Example

```python
import json
from email_sender import ProfessionalEmailSender

email_sender = ProfessionalEmailSender()

# Load recipients
with open('recipients.json', 'r') as f:
    recipients = json.load(f)

# HTML template with variables
html_template = """
<html>
<body>
    <h2>Hello {{first_name}}!</h2>
    <p>We have a special offer for {{company}}: {{special_offer}}</p>
    <p>This offer is exclusively for you!</p>
    <p>Best regards,<br>Sales Team</p>
</body>
</html>
"""

# Send bulk emails
stats = email_sender.bulk_send(
    smtp_config=smtp_config,
    sender_email='sales@yourcompany.com',
    sender_name='Sales Team',
    recipients=recipients,
    subject='Special Offer for {{first_name}}',
    html_template=html_template,
    delay=2,  # 2 seconds delay between emails
    company_name='Your Company',
    department='Sales'
)

print(f"Total: {stats['total']}, Sent: {stats['sent']}, Failed: {stats['failed']}")
```

## 🎨 Using Templates

### Load Template from File

```python
# Load template with variables
variables = {
    'recipient_name': 'John Smith',
    'company_name': 'Your Company',
    'main_message': 'Welcome to our service!',
    'button_text': 'Get Started',
    'button_link': 'https://yourwebsite.com/start'
}

html_content = email_sender.load_template('templates/professional.html', variables)
```

### Available Template Variables

The professional template supports these variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `{{subject}}` | Email subject | "Welcome to Our Service" |
| `{{company_name}}` | Company name | "Your Company Inc" |
| `{{department}}` | Department | "Customer Service" |
| `{{recipient_name}}` | Recipient's name | "John Smith" |
| `{{greeting}}` | Greeting text | "Hello" or "Dear" |
| `{{main_message}}` | Main content | "Welcome to our platform..." |
| `{{additional_info}}` | Extra information | "Please verify your email..." |
| `{{button_text}}` | Button text | "Verify Email" |
| `{{button_link}}` | Button URL | "https://example.com/verify" |
| `{{closing_message}}` | Closing text | "Thank you for joining us" |
| `{{sender_name}}` | Sender's name | "Support Team" |
| `{{sender_title}}` | Sender's title | "Customer Support Manager" |
| `{{sender_email}}` | Sender's email | "support@company.com" |
| `{{sender_phone}}` | Sender's phone | "+1-555-0123" |
| `{{company_website}}` | Company website | "https://company.com" |
| `{{company_address}}` | Company address | "123 Business St, City, State" |
| `{{company_phone}}` | Company phone | "+1-555-0100" |
| `{{company_email}}` | Company email | "info@company.com" |
| `{{unsubscribe_link}}` | Unsubscribe URL | "https://company.com/unsubscribe" |

### Creating Custom Templates

1. Create an HTML file in the `templates/` directory
2. Use `{{variable_name}}` syntax for substitutable content
3. Include responsive CSS for mobile compatibility
4. Test with different email clients

Example template structure:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{subject}}</title>
    <style>
        /* Responsive CSS styles */
        body { font-family: Arial, sans-serif; }
        .container { max-width: 600px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{company_name}}</h1>
        <p>Hello {{recipient_name}},</p>
        <p>{{main_message}}</p>
        <a href="{{button_link}}">{{button_text}}</a>
    </div>
</body>
</html>
```

## 🔧 Advanced Features

### Custom Headers

Add custom headers for tracking, authentication, or compliance:

```python
custom_headers = {
    'X-Campaign-ID': 'summer-sale-2024',
    'X-Email-Type': 'promotional',
    'X-Tracking-ID': 'track-12345',
    'List-ID': 'newsletter.yourcompany.com',
    'Reply-To': 'noreply@yourcompany.com'
}
```

### Email Priorities

Set email priority to influence delivery:

```python
# Priority levels: 'low', 'normal', 'high'
email_sender.send_email(
    # ... other parameters
    priority='high'  # Marks email as high priority
)
```

### File Attachments

Attach files to your emails:

```python
attachments = [
    'documents/report.pdf',
    'images/logo.png',
    'data/spreadsheet.xlsx'
]

email_sender.send_email(
    # ... other parameters
    attachments=attachments
)
```

### Bulk Send with Delays

Control sending rate to avoid being marked as spam:

```python
stats = email_sender.bulk_send(
    # ... other parameters
    delay=5  # 5 seconds between each email
)
```

## 🛡️ Anti-Spam Best Practices

### Automatic Anti-Spam Headers

The system automatically adds these headers to prevent spam detection:

- **Message-ID**: Unique identifier for each email
- **Date**: Proper timestamp in RFC format
- **MIME-Version**: Standard MIME version
- **X-Mailer**: Identifies the sending software
- **X-Priority**: Email priority level
- **Return-Path**: Return address for bounces
- **Reply-To**: Reply address
- **List-Unsubscribe**: Unsubscribe mechanism

### Content Best Practices

#### ✅ Do This:
- Use clear, relevant subject lines
- Include both HTML and text versions
- Maintain a good text-to-image ratio
- Use legitimate sender addresses
- Include unsubscribe links
- Keep content professional and relevant

#### ❌ Avoid This:
- ALL CAPS subject lines
- Excessive exclamation marks!!!
- Spam trigger words (FREE, URGENT, ACT NOW)
- Too many images without text
- Misleading subject lines
- No unsubscribe option

### Technical Best Practices

#### DNS Records Setup (Recommended)
Set up these DNS records for your domain:

**SPF Record:**
```
v=spf1 include:_spf.google.com ~all
```

**DKIM Record:**
Contact your email provider for DKIM setup instructions.

**DMARC Record:**
```
v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com
```

#### Sending Practices
- Start with small volumes and gradually increase
- Maintain consistent sending patterns
- Monitor bounce rates and remove invalid addresses
- Use dedicated IP addresses for high-volume sending
- Warm up new IP addresses gradually

## 🔍 Troubleshooting

### Common Issues and Solutions

#### Authentication Errors

**Error:** `SMTPAuthenticationError: (535, 'Authentication failed')`

**Solutions:**
- For Gmail: Use App Password instead of regular password
- Enable 2-Factor Authentication first
- Check username/password are correct
- Verify account settings allow SMTP access

#### Connection Issues

**Error:** `SMTPServerDisconnected: Connection unexpectedly closed`

**Solutions:**
- Check firewall settings
- Verify server address and port
- Try different security settings (TLS/SSL)
- Check if your ISP blocks SMTP ports

#### Emails Going to Spam

**Solutions:**
- Improve email content quality
- Set up SPF, DKIM, and DMARC records
- Use authenticated SMTP servers
- Avoid spam trigger words
- Include unsubscribe links
- Maintain good sender reputation

#### Template Loading Errors

**Error:** `Error loading template: [Errno 2] No such file or directory`

**Solutions:**
- Check file path is correct
- Ensure templates directory exists
- Verify file permissions
- Use absolute paths if needed

### Testing Your Setup

#### Test SMTP Connection
```python
# Use the built-in connection test
python quick_start.py
# Select option 5: "Test connection again"
```

#### Test Email Delivery
1. Send test emails to multiple providers (Gmail, Outlook, Yahoo)
2. Check spam folders
3. Verify all content displays correctly
4. Test on mobile devices

#### Monitor Email Headers
Use email header analysis tools to check:
- SPF/DKIM/DMARC status
- Spam score
- Routing information
- Authentication results

### Getting Help

If you encounter issues:

1. **Check the error message** - Most errors are self-explanatory
2. **Verify your configuration** - Double-check SMTP settings
3. **Test with simple content first** - Rule out template issues
4. **Check your email provider's documentation** - Each provider has specific requirements
5. **Monitor email logs** - Check for bounce messages and delivery reports

## 📊 Performance Tips

### For High-Volume Sending

1. **Use dedicated SMTP services** (SendGrid, Amazon SES, Mailgun)
2. **Implement proper delays** between emails
3. **Monitor bounce rates** and remove invalid addresses
4. **Segment your email lists** for better targeting
5. **Use connection pooling** for multiple sends
6. **Implement retry logic** for failed sends

### For Better Deliverability

1. **Authenticate your domain** with SPF, DKIM, DMARC
2. **Maintain list hygiene** - remove bounces and unsubscribes
3. **Monitor sender reputation** using tools like Sender Score
4. **Use consistent From addresses** and sending patterns
5. **Provide clear unsubscribe options**
6. **Monitor feedback loops** from major email providers

---

## 🎯 Quick Reference

### Basic Send
```python
email_sender.send_email(smtp_config, sender_email, sender_name, 
                       recipient_email, recipient_name, subject, html_content)
```

### Bulk Send
```python
email_sender.bulk_send(smtp_config, sender_email, sender_name, 
                      recipients, subject, html_template, delay=2)
```

### Load Template
```python
html_content = email_sender.load_template('template.html', variables)
```

### Test Connection
```python
python quick_start.py  # Interactive testing
```

This guide covers all major features and use cases. For specific questions or advanced configurations, refer to the source code comments or create custom implementations based on the provided examples.