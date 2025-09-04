# 🚀 Professional Email Sender System

A complete and professional system for sending single or bulk emails with advanced features to prevent emails from going to spam folders.

## ✨ Key Features

### 🎯 Core Features
- **Single and bulk email sending** with configurable delays
- **Beautiful HTML templates** with variable substitution
- **Advanced professional headers** to prevent spam
- **Multiple SMTP server support** (Gmail, Outlook, Yahoo, Office365, Zoho, Custom)
- **Email address validation** before sending
- **Complete reporting** of sending statistics

### 🔒 Security & Reliability
- **Secure SSL/TLS connections**
- **Advanced authentication**
- **Anti-phishing headers**
- **Unique Message-ID generation**
- **SPF and DKIM ready**

### 🎨 Template System
- **Responsive HTML templates**
- **Variable substitution system**
- **Pre-designed professional templates**
- **Advanced CSS support**

## 📦 Installation & Setup

### Prerequisites
- Python 3.6 or higher
- SMTP server access

### Installation
```bash
git clone <repository-url>
cd professional-email-sender
pip install -r requirements.txt
```

### Quick Start
```bash
python quick_start.py
```

## 🚀 Usage Examples

### 1. Send Single Email

```python
from email_sender import ProfessionalEmailSender

# Create instance
email_sender = ProfessionalEmailSender()

# SMTP configuration
smtp_config = {
    'server': 'smtp.gmail.com',
    'port': 587,
    'security': 'tls',
    'username': 'your_email@gmail.com',
    'password': 'your_app_password'
}

# Send email
success = email_sender.send_email(
    smtp_config=smtp_config,
    sender_email='your_email@gmail.com',
    sender_name='Your Name',
    recipient_email='recipient@example.com',
    recipient_name='Recipient Name',
    subject='Email Subject',
    html_content='<h1>Hello!</h1><p>This is a test email.</p>',
    company_name='Your Company',
    department='IT Department'
)
```

### 2. Use Templates

```python
# Load template with variables
html_content = email_sender.load_template(
    'templates/professional.html',
    variables={
        'recipient_name': 'John Smith',
        'company_name': 'Your Company',
        'main_message': 'Welcome to our service!',
        'sender_name': 'Support Team'
    }
)

# Send with template
email_sender.send_email(
    smtp_config=smtp_config,
    sender_email='sender@example.com',
    sender_name='Sender Name',
    recipient_email='recipient@example.com',
    recipient_name='Recipient Name',
    subject='Subject',
    html_content=html_content
)
```

### 3. Bulk Email Sending

```python
# Recipients list
recipients = [
    {
        'email': 'user1@example.com',
        'name': 'User One',
        'variables': {
            'first_name': 'John',
            'special_offer': '20% discount'
        }
    },
    {
        'email': 'user2@example.com',
        'name': 'User Two',
        'variables': {
            'first_name': 'Sarah',
            'special_offer': '15% discount'
        }
    }
]

# Template with variables
html_template = '''
<h1>Hello {{first_name}}!</h1>
<p>Special offer: {{special_offer}}</p>
'''

# Send bulk emails
stats = email_sender.bulk_send(
    smtp_config=smtp_config,
    sender_email='sender@example.com',
    sender_name='Marketing Team',
    recipients=recipients,
    subject='Special Offer for {{first_name}}',
    html_template=html_template,
    delay=2  # 2 seconds delay between sends
)

print(f"Sent: {stats['sent']}, Failed: {stats['failed']}")
```

## 📁 Project Structure

```
professional-email-sender/
├── email_sender.py          # Main system file
├── quick_start.py           # Interactive quick start script
├── email_config.json        # Configuration file
├── requirements.txt         # Dependencies
├── README.md               # This file
├── USAGE_GUIDE.md          # Complete usage guide
├── templates/              # Email templates
│   ├── professional.html   # Professional template
│   └── newsletter.html     # Newsletter template
└── examples/               # Usage examples
    ├── single_email_example.py
    ├── bulk_email_example.py
    └── recipients.json
```

## ⚙️ SMTP Configuration

### Gmail
```json
{
    "server": "smtp.gmail.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@gmail.com",
    "password": "your_app_password"
}
```

**Note:** For Gmail, you must use App Password, not your regular password.

### Outlook/Hotmail
```json
{
    "server": "smtp-mail.outlook.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@outlook.com",
    "password": "your_password"
}
```

### Yahoo Mail
```json
{
    "server": "smtp.mail.yahoo.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@yahoo.com",
    "password": "your_app_password"
}
```

### Office 365
```json
{
    "server": "smtp.office365.com",
    "port": 587,
    "security": "tls",
    "username": "your_email@yourdomain.com",
    "password": "your_password"
}
```

## 🎨 Template System

### Available Template Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `{{recipient_name}}` | Recipient's name | John Smith |
| `{{sender_name}}` | Sender's name | Support Team |
| `{{company_name}}` | Company name | Your Company |
| `{{subject}}` | Email subject | Important Notice |
| `{{main_message}}` | Main message content | Your main email content |
| `{{button_text}}` | Button text | Click Here |
| `{{button_link}}` | Button URL | https://example.com |

### Creating Custom Templates

1. Create new HTML file in `templates/` directory
2. Use `{{variable_name}}` syntax for substitutable content
3. Include inline CSS or `<style>` tags
4. Load template with `load_template()` method

## 🛡️ Anti-Spam Features

### Automatic Headers
- Unique `Message-ID` for each email
- Standard `Date` and `MIME-Version` headers
- `X-Mailer` and `X-Priority` headers
- `List-Unsubscribe` for easy unsubscribing
- `Return-Path` and `Reply-To` headers

### Best Practices
1. **Quality Content:** Avoid spam trigger words
2. **Text/Image Balance:** Include sufficient text content
3. **Legitimate Links:** Avoid shortened URLs
4. **DNS Setup:** Configure SPF, DKIM, and DMARC records
5. **Sending Frequency:** Use appropriate delays between emails

## 📊 Reporting

The system provides comprehensive sending statistics:

```python
stats = {
    'total': 100,      # Total emails
    'sent': 95,        # Successfully sent
    'failed': 5,       # Failed to send
    'errors': [...]    # List of errors
}
```

## 🔧 Troubleshooting

### Common Issues

#### Authentication Error
```
SMTPAuthenticationError: (535, 'Authentication failed')
```
**Solution:** 
- For Gmail: Use App Password instead of regular password
- Enable 2FA and generate App Password

#### Connection Error
```
SMTPServerDisconnected: Connection unexpectedly closed
```
**Solution:**
- Check firewall settings
- Verify server address and port
- Try different security settings

#### Emails Going to Spam
**Solution:**
- Improve email content
- Set up SPF/DKIM records
- Use authenticated servers
- Include unsubscribe links

## 🚀 Getting Started

### Method 1: Quick Start (Recommended)
```bash
python quick_start.py
```
This interactive script guides you through setup and testing.

### Method 2: Direct Usage
```python
from email_sender import ProfessionalEmailSender

email_sender = ProfessionalEmailSender()
# Configure and send emails...
```

### Method 3: Use Examples
```bash
python examples/single_email_example.py
python examples/bulk_email_example.py
```

## 📖 Documentation

- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Complete usage guide with examples
- **[examples/](examples/)** - Practical usage examples
- **Source code comments** - Detailed inline documentation

## 🤝 Contributing

To contribute to this project:

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is released under the MIT License.

## 📞 Support

For questions and support:
- Create an issue on GitHub
- Check the troubleshooting section
- Review the usage guide

---

**Important:** This system is designed for legitimate and legal purposes. Do not use it for sending spam or phishing emails.

## 🎯 Quick Commands

```bash
# Quick start
python quick_start.py

# Run examples
python examples/single_email_example.py
python examples/bulk_email_example.py

# Test connection
python -c "from email_sender import ProfessionalEmailSender; print('System ready!')"
```

Start with `python quick_start.py` for the best experience! 🚀