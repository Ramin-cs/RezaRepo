#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Quick Start Email Sender System
Professional email sending system with easy setup

Just run this file and follow the steps to get started quickly.
"""

from email_sender import ProfessionalEmailSender
import os
import json

def quick_setup():
    """Quick system setup"""
    print("🚀 Welcome to Professional Email Sender System!")
    print("=" * 60)
    
    # Create instance
    email_sender = ProfessionalEmailSender()
    
    print("\n📧 Please enter the following information:")
    
    # Server selection
    print("\n🌐 Select email server:")
    print("1. Gmail")
    print("2. Outlook/Hotmail") 
    print("3. Yahoo")
    print("4. Office 365")
    print("5. Custom server")
    
    choice = input("\nSelect (1-5): ").strip()
    
    smtp_configs = {
        '1': {'server': 'smtp.gmail.com', 'port': 587, 'security': 'tls', 'name': 'Gmail'},
        '2': {'server': 'smtp-mail.outlook.com', 'port': 587, 'security': 'tls', 'name': 'Outlook'},
        '3': {'server': 'smtp.mail.yahoo.com', 'port': 587, 'security': 'tls', 'name': 'Yahoo'},
        '4': {'server': 'smtp.office365.com', 'port': 587, 'security': 'tls', 'name': 'Office 365'},
    }
    
    if choice in smtp_configs:
        smtp_config = smtp_configs[choice]
        print(f"✅ {smtp_config['name']} selected")
    else:
        smtp_config = {
            'server': input("SMTP server address: "),
            'port': int(input("Port (usually 587): ") or "587"),
            'security': 'tls',
            'name': 'Custom'
        }
    
    # Authentication information
    print(f"\n🔐 Authentication information for {smtp_config['name']}:")
    smtp_config['username'] = input("Email address: ")
    smtp_config['password'] = input("Password (or App Password): ")
    
    # Test connection
    print("\n🔍 Testing connection...")
    try:
        import smtplib
        import ssl
        
        if smtp_config.get('security') == 'ssl':
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
        else:
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            if smtp_config.get('security') == 'tls':
                context = ssl.create_default_context()
                server.starttls(context=context)
        
        server.login(smtp_config['username'], smtp_config['password'])
        server.quit()
        print("✅ Connection successful!")
        
    except Exception as e:
        print(f"❌ Connection error: {e}")
        print("Please check your credentials.")
        return None
    
    # Save settings
    config = {
        'smtp_config': smtp_config,
        'setup_completed': True
    }
    
    with open('quick_config.json', 'w', encoding='utf-8') as f:
        json.dump(config, f, ensure_ascii=False, indent=4)
    
    print("💾 Configuration saved!")
    return smtp_config

def send_test_email(smtp_config):
    """Send test email"""
    email_sender = ProfessionalEmailSender()
    
    print("\n📧 Send test email:")
    
    sender_email = smtp_config['username']
    sender_name = input("Sender name: ") or "Test"
    recipient_email = input("Recipient address (for testing): ")
    
    if not recipient_email:
        print("❌ Recipient address is required!")
        return
    
    # Simple test email
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            body {{
                font-family: Arial, Helvetica, sans-serif;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f4f4f4;
            }}
            .container {{
                background-color: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            .success {{
                background-color: #d4edda;
                color: #155724;
                padding: 15px;
                border-radius: 5px;
                border: 1px solid #c3e6cb;
                text-align: center;
                margin: 20px 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎉 Congratulations!</h1>
            <div class="success">
                <strong>Email system successfully configured!</strong>
            </div>
            <p>This is a test email showing that your system is working correctly.</p>
            <h3>System Features:</h3>
            <ul>
                <li>✅ Single and bulk email sending</li>
                <li>✅ Beautiful HTML templates</li>
                <li>✅ Anti-spam headers</li>
                <li>✅ Multiple server support</li>
                <li>✅ Complete reporting</li>
            </ul>
            <p><strong>You can now use the system!</strong></p>
            <hr>
            <p style="font-size: 12px; color: #666;">
                Sent by Professional Email Sender System<br>
                Date: {email_sender._get_current_date()}
            </p>
        </div>
    </body>
    </html>
    """
    
    print("\n🚀 Sending test email...")
    
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name="Test User",
        subject="🎉 Email System Test Successful",
        html_content=html_content,
        company_name="Email System",
        department="Test",
        priority="normal"
    )
    
    if success:
        print("✅ Test email sent successfully!")
        print(f"📬 Check your inbox at {recipient_email}.")
    else:
        print("❌ Error sending test email!")

def main_menu(smtp_config):
    """Main menu"""
    email_sender = ProfessionalEmailSender()
    
    while True:
        print("\n" + "="*50)
        print("📧 Professional Email Sender System")
        print("="*50)
        print("1. Send single email")
        print("2. Send bulk emails") 
        print("3. Create new template")
        print("4. View available templates")
        print("5. Test connection again")
        print("6. Change settings")
        print("0. Exit")
        
        choice = input("\nSelect option (0-6): ").strip()
        
        if choice == '1':
            send_single_email_simple(email_sender, smtp_config)
        elif choice == '2':
            send_bulk_email_simple(email_sender, smtp_config)
        elif choice == '3':
            create_template_simple()
        elif choice == '4':
            show_templates()
        elif choice == '5':
            test_connection(smtp_config)
        elif choice == '6':
            smtp_config = quick_setup()
            if not smtp_config:
                break
        elif choice == '0':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid selection!")

def send_single_email_simple(email_sender, smtp_config):
    """Send simple single email"""
    print("\n📧 Send Single Email")
    print("-" * 30)
    
    sender_email = smtp_config['username']
    sender_name = input("Sender name: ") or "Sender"
    recipient_email = input("Recipient address: ")
    recipient_name = input("Recipient name (optional): ") or "Recipient"
    subject = input("Email subject: ")
    
    print("\nMessage type:")
    print("1. Plain text")
    print("2. Use template")
    
    msg_type = input("Select (1-2): ").strip()
    
    if msg_type == '1':
        message = input("Message text: ")
        html_content = f"""
        <html><body style="font-family: Arial, Helvetica; max-width: 600px; margin: 0 auto;">
        <h2>Hello {recipient_name}!</h2>
        <p>{message}</p>
        <hr>
        <p style="font-size: 12px; color: #666;">Sent by {sender_name}</p>
        </body></html>
        """
    else:
        templates = ['templates/professional.html', 'templates/newsletter.html']
        print("\nAvailable templates:")
        for i, template in enumerate(templates, 1):
            if os.path.exists(template):
                print(f"{i}. {os.path.basename(template)}")
        
        template_choice = input("Select template (number): ").strip()
        if template_choice == '1' and os.path.exists('templates/professional.html'):
            variables = {
                'recipient_name': recipient_name,
                'sender_name': sender_name,
                'company_name': input("Company name: ") or "Company",
                'main_message': input("Main message: ") or "Test message",
                'button_text': input("Button text (optional): ") or "Click Here",
                'button_link': input("Button link (optional): ") or "#"
            }
            html_content = email_sender.load_template('templates/professional.html', variables)
        else:
            print("❌ Template not found! Using plain text.")
            html_content = f"<html><body><h2>Hello!</h2><p>Test message</p></body></html>"
    
    print("\n🚀 Sending...")
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name=recipient_name,
        subject=subject,
        html_content=html_content
    )
    
    if success:
        print("✅ Email sent successfully!")
    else:
        print("❌ Error sending email!")

def send_bulk_email_simple(email_sender, smtp_config):
    """Send simple bulk emails"""
    print("\n📧 Send Bulk Emails")
    print("-" * 30)
    
    if not os.path.exists('examples/recipients.json'):
        print("❌ Recipients file not found!")
        print("Please check examples/recipients.json file.")
        return
    
    try:
        with open('examples/recipients.json', 'r', encoding='utf-8') as f:
            recipients = json.load(f)
        
        print(f"📊 Found {len(recipients)} recipients.")
        
        sender_email = smtp_config['username']
        sender_name = input("Sender name: ") or "Sender"
        subject = input("Email subject: ")
        
        # Simple template
        html_template = """
        <html>
        <body style="font-family: Arial, Helvetica; max-width: 600px; margin: 0 auto;">
            <div style="background: white; padding: 30px; border-radius: 10px;">
                <h2>Hello {{first_name}}!</h2>
                <p>{{custom_message}}</p>
                <div style="background: #f0f8ff; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0;">
                    <strong>Special Offer: {{special_offer}}</strong>
                </div>
                <p>This offer is valid until {{expiry_date}}.</p>
                <p>Best regards,<br>{{sender_name}}</p>
            </div>
        </body>
        </html>
        """
        
        delay = int(input("Delay between sends (seconds) [2]: ") or "2")
        
        print(f"\n🚀 Starting bulk send to {len(recipients)} recipients...")
        
        stats = email_sender.bulk_send(
            smtp_config=smtp_config,
            sender_email=sender_email,
            sender_name=sender_name,
            recipients=recipients,
            subject=subject,
            html_template=html_template,
            delay=delay
        )
        
        print(f"\n📊 Results:")
        print(f"✅ Successful: {stats['sent']}")
        print(f"❌ Failed: {stats['failed']}")
        
    except Exception as e:
        print(f"❌ Error: {e}")

def show_templates():
    """Show available templates"""
    print("\n🎨 Available Templates:")
    print("-" * 30)
    
    template_dir = 'templates'
    if os.path.exists(template_dir):
        templates = [f for f in os.listdir(template_dir) if f.endswith('.html')]
        if templates:
            for i, template in enumerate(templates, 1):
                print(f"{i}. {template}")
        else:
            print("No templates found.")
    else:
        print("Templates folder not found.")

def create_template_simple():
    """Create simple template"""
    print("\n🎨 Create New Template")
    print("-" * 30)
    
    name = input("Template name: ")
    if not name:
        print("❌ Template name is required!")
        return
    
    # Base template
    template_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{{{subject}}}}</title>
    <style>
        body {{
            font-family: Arial, Helvetica, sans-serif;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{{{company_name}}}}</h1>
        </div>
        <h2>Hello {{{{recipient_name}}}}!</h2>
        <p>{{{{main_message}}}}</p>
        <p>Best regards,<br>{{{{sender_name}}}}</p>
    </div>
</body>
</html>"""
    
    os.makedirs('templates', exist_ok=True)
    template_path = f'templates/{name}.html'
    
    try:
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        print(f"✅ Template {name} created!")
        print(f"📁 Path: {template_path}")
    except Exception as e:
        print(f"❌ Error creating template: {e}")

def test_connection(smtp_config):
    """Test connection"""
    print("\n🔍 Testing connection...")
    try:
        import smtplib
        import ssl
        
        if smtp_config.get('security') == 'ssl':
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
        else:
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            if smtp_config.get('security') == 'tls':
                context = ssl.create_default_context()
                server.starttls(context=context)
        
        server.login(smtp_config['username'], smtp_config['password'])
        server.quit()
        print("✅ Connection successful!")
        
    except Exception as e:
        print(f"❌ Connection error: {e}")

def main():
    """Main function"""
    print("🚀 Professional Email Sender System")
    print("Quick Start")
    print("=" * 50)
    
    # Check existing configuration
    if os.path.exists('quick_config.json'):
        try:
            with open('quick_config.json', 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            if config.get('setup_completed'):
                print("✅ Found existing configuration!")
                use_existing = input("Use existing settings? (y/n) [y]: ").lower()
                
                if use_existing != 'n':
                    smtp_config = config['smtp_config']
                    print(f"📧 Using: {smtp_config.get('name', 'Custom')}")
                    
                    # Test email
                    test_email = input("Send test email? (y/n) [n]: ").lower()
                    if test_email == 'y':
                        send_test_email(smtp_config)
                    
                    main_menu(smtp_config)
                    return
        except:
            pass
    
    # New setup
    smtp_config = quick_setup()
    if not smtp_config:
        print("❌ Setup failed!")
        return
    
    # Test email
    test_email = input("\nSend test email? (y/n) [y]: ").lower()
    if test_email != 'n':
        send_test_email(smtp_config)
    
    # Enter main menu
    main_menu(smtp_config)

if __name__ == "__main__":
    main()