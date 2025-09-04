#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional Email Sender System
Advanced email sending system with anti-spam headers and professional templates

This system provides the ability to send professional single or bulk emails 
with advanced features to prevent emails from going to spam folders.

Author: Assistant
Date: 2024
"""

import smtplib
import ssl
import json
import os
import sys
import time
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
from typing import Dict, List, Optional, Union
import re
from pathlib import Path

class ProfessionalEmailSender:
    """
    Main class for sending professional emails
    """
    
    def __init__(self, config_file: str = "email_config.json"):
        """
        Initialize the email sending system
        
        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file
        self.config = self.load_config()
        self.smtp_servers = self.get_smtp_servers()
        
    def load_config(self) -> Dict:
        """Load configuration from JSON file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading configuration: {e}")
                return {}
        return {}
    
    def save_config(self, config: Dict) -> bool:
        """Save configuration to JSON file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=4)
            return True
        except Exception as e:
            print(f"Error saving configuration: {e}")
            return False
    
    def get_smtp_servers(self) -> Dict:
        """List of popular SMTP servers"""
        return {
            'gmail': {
                'server': 'smtp.gmail.com',
                'port': 587,
                'security': 'tls',
                'name': 'Gmail'
            },
            'outlook': {
                'server': 'smtp-mail.outlook.com',
                'port': 587,
                'security': 'tls',
                'name': 'Outlook/Hotmail'
            },
            'yahoo': {
                'server': 'smtp.mail.yahoo.com',
                'port': 587,
                'security': 'tls',
                'name': 'Yahoo Mail'
            },
            'office365': {
                'server': 'smtp.office365.com',
                'port': 587,
                'security': 'tls',
                'name': 'Office 365'
            },
            'zoho': {
                'server': 'smtp.zoho.com',
                'port': 587,
                'security': 'tls',
                'name': 'Zoho Mail'
            },
            'custom': {
                'server': '',
                'port': 587,
                'security': 'tls',
                'name': 'Custom SMTP'
            }
        }
    
    def generate_professional_headers(self, 
                                    sender_email: str,
                                    recipient_email: str,
                                    subject: str,
                                    company_name: str = None,
                                    department: str = None,
                                    priority: str = "normal") -> Dict:
        """
        Generate professional headers to prevent spam
        
        Args:
            sender_email: Sender's email address
            recipient_email: Recipient's email address
            subject: Email subject
            company_name: Company name
            department: Department name
            priority: Email priority (low, normal, high)
        
        Returns:
            Dictionary containing email headers
        """
        
        # Generate unique Message-ID
        timestamp = str(int(time.time()))
        random_num = str(random.randint(100000, 999999))
        domain = sender_email.split('@')[1] if '@' in sender_email else 'localhost'
        message_id = f"<{timestamp}.{random_num}@{domain}>"
        
        # Basic headers
        headers = {
            'Message-ID': message_id,
            'Date': datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z'),
            'MIME-Version': '1.0',
            'Content-Type': 'multipart/alternative',
            'X-Mailer': 'Professional Email Sender v1.0',
            'X-Priority': self._get_priority_value(priority),
            'Importance': priority.title(),
        }
        
        # Company headers
        if company_name:
            headers['X-Organization'] = company_name
            headers['Organization'] = company_name
            
        if department:
            headers['X-Department'] = department
            
        # Security and authentication headers
        headers.update({
            'X-Auto-Response-Suppress': 'OOF, DR, RN, NRN',
            'X-MSMail-Priority': priority.title(),
            'X-Originating-IP': '[127.0.0.1]',  # Internal IP
            'X-Spam-Status': 'No',
            'X-Spam-Score': '0.0',
            'List-Unsubscribe': f'<mailto:{sender_email}?subject=Unsubscribe>',
            'Precedence': 'bulk' if priority == 'low' else 'normal',
        })
        
        # Return path headers
        headers['Return-Path'] = f'<{sender_email}>'
        headers['Reply-To'] = sender_email
        
        return headers
    
    def _get_priority_value(self, priority: str) -> str:
        """Convert priority to numeric value"""
        priority_map = {
            'high': '1',
            'normal': '3',
            'low': '5'
        }
        return priority_map.get(priority.lower(), '3')
    
    def load_template(self, template_path: str, variables: Dict = None) -> str:
        """
        Load HTML template and substitute variables
        
        Args:
            template_path: Path to template file
            variables: Variables for substitution
        
        Returns:
            Final HTML content
        """
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            if variables:
                for key, value in variables.items():
                    placeholder = f"{{{{{key}}}}}"
                    template_content = template_content.replace(placeholder, str(value))
            
            return template_content
        except Exception as e:
            print(f"Error loading template: {e}")
            return ""
    
    def validate_email(self, email: str) -> bool:
        """Validate email address"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def create_professional_message(self,
                                  sender_email: str,
                                  sender_name: str,
                                  recipient_email: str,
                                  recipient_name: str,
                                  subject: str,
                                  html_content: str,
                                  text_content: str = None,
                                  custom_headers: Dict = None,
                                  company_name: str = None,
                                  department: str = None,
                                  priority: str = "normal") -> MIMEMultipart:
        """
        Create professional email message
        
        Args:
            sender_email: Sender's email address
            sender_name: Sender's name
            recipient_email: Recipient's email address
            recipient_name: Recipient's name
            subject: Email subject
            html_content: HTML content
            text_content: Text content (optional)
            custom_headers: Custom headers
            company_name: Company name
            department: Department name
            priority: Email priority
        
        Returns:
            MIMEMultipart object ready to send
        """
        
        # Create main message
        msg = MIMEMultipart('alternative')
        
        # Set main headers
        msg['From'] = f"{sender_name} <{sender_email}>" if sender_name else sender_email
        msg['To'] = f"{recipient_name} <{recipient_email}>" if recipient_name else recipient_email
        msg['Subject'] = subject
        
        # Add professional headers
        professional_headers = self.generate_professional_headers(
            sender_email, recipient_email, subject, company_name, department, priority
        )
        
        for key, value in professional_headers.items():
            if key not in ['From', 'To', 'Subject']:  # Prevent duplication
                msg[key] = value
        
        # Add custom headers
        if custom_headers:
            for key, value in custom_headers.items():
                msg[key] = value
        
        # Add text content (fallback)
        if text_content:
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            msg.attach(text_part)
        else:
            # Generate text content from HTML
            text_content = self._html_to_text(html_content)
            text_part = MIMEText(text_content, 'plain', 'utf-8')
            msg.attach(text_part)
        
        # Add HTML content
        html_part = MIMEText(html_content, 'html', 'utf-8')
        msg.attach(html_part)
        
        return msg
    
    def _html_to_text(self, html_content: str) -> str:
        """Simple HTML to text conversion"""
        # Remove HTML tags
        import re
        text = re.sub(r'<[^>]+>', '', html_content)
        # Clean extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def _get_current_date(self) -> str:
        """Get current date"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def send_email(self,
                   smtp_config: Dict,
                   sender_email: str,
                   sender_name: str,
                   recipient_email: str,
                   recipient_name: str,
                   subject: str,
                   html_content: str,
                   text_content: str = None,
                   custom_headers: Dict = None,
                   company_name: str = None,
                   department: str = None,
                   priority: str = "normal",
                   attachments: List[str] = None) -> bool:
        """
        Send email with complete configuration
        
        Args:
            smtp_config: SMTP server configuration
            sender_email: Sender's address
            sender_name: Sender's name
            recipient_email: Recipient's address
            recipient_name: Recipient's name
            subject: Email subject
            html_content: HTML content
            text_content: Text content
            custom_headers: Custom headers
            company_name: Company name
            department: Department name
            priority: Priority level
            attachments: List of attachment files
        
        Returns:
            True if successful, False if error
        """
        
        try:
            # Validate email addresses
            if not self.validate_email(sender_email):
                print(f"Invalid sender email: {sender_email}")
                return False
                
            if not self.validate_email(recipient_email):
                print(f"Invalid recipient email: {recipient_email}")
                return False
            
            # Create message
            msg = self.create_professional_message(
                sender_email, sender_name, recipient_email, recipient_name,
                subject, html_content, text_content, custom_headers,
                company_name, department, priority
            )
            
            # Add attachments
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        self._add_attachment(msg, file_path)
                    else:
                        print(f"Attachment file not found: {file_path}")
            
            # Connect to SMTP server
            print(f"Connecting to SMTP server: {smtp_config['server']}:{smtp_config['port']}")
            
            if smtp_config.get('security') == 'ssl':
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
            else:
                server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
                if smtp_config.get('security') == 'tls':
                    context = ssl.create_default_context()
                    server.starttls(context=context)
            
            # Authentication
            if smtp_config.get('username') and smtp_config.get('password'):
                print("Authenticating...")
                server.login(smtp_config['username'], smtp_config['password'])
            
            # Send email
            print(f"Sending email to {recipient_email}...")
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()
            
            print("✅ Email sent successfully!")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"❌ Authentication error: {e}")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            print(f"❌ Recipient refused: {e}")
            return False
        except smtplib.SMTPServerDisconnected as e:
            print(f"❌ Server disconnected: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            return False
    
    def _add_attachment(self, msg: MIMEMultipart, file_path: str):
        """Add file attachment"""
        try:
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(file_path)}'
            )
            msg.attach(part)
            print(f"Attachment added: {file_path}")
        except Exception as e:
            print(f"Error adding attachment {file_path}: {e}")
    
    def bulk_send(self,
                  smtp_config: Dict,
                  sender_email: str,
                  sender_name: str,
                  recipients: List[Dict],
                  subject: str,
                  html_template: str,
                  delay: int = 1,
                  **kwargs) -> Dict:
        """
        Send bulk emails
        
        Args:
            smtp_config: SMTP configuration
            sender_email: Sender's address
            sender_name: Sender's name
            recipients: List of recipients
            subject: Email subject
            html_template: HTML template
            delay: Delay between sends (seconds)
            **kwargs: Other parameters
        
        Returns:
            Sending statistics
        """
        
        stats = {
            'total': len(recipients),
            'sent': 0,
            'failed': 0,
            'errors': []
        }
        
        for i, recipient in enumerate(recipients):
            try:
                print(f"\nSending email {i+1} of {len(recipients)}...")
                
                # Substitute variables in template
                html_content = html_template
                for key, value in recipient.get('variables', {}).items():
                    html_content = html_content.replace(f"{{{{{key}}}}}", str(value))
                
                # Send email
                success = self.send_email(
                    smtp_config=smtp_config,
                    sender_email=sender_email,
                    sender_name=sender_name,
                    recipient_email=recipient['email'],
                    recipient_name=recipient.get('name', ''),
                    subject=subject,
                    html_content=html_content,
                    **kwargs
                )
                
                if success:
                    stats['sent'] += 1
                else:
                    stats['failed'] += 1
                    stats['errors'].append(f"Failed to send to {recipient['email']}")
                
                # Delay between sends
                if i < len(recipients) - 1 and delay > 0:
                    print(f"Waiting {delay} seconds...")
                    time.sleep(delay)
                    
            except Exception as e:
                stats['failed'] += 1
                stats['errors'].append(f"Error sending to {recipient.get('email', 'unknown')}: {e}")
        
        print(f"\n📊 Final Statistics:")
        print(f"Total: {stats['total']}")
        print(f"Sent: {stats['sent']}")
        print(f"Failed: {stats['failed']}")
        
        return stats


def main():
    """Main program function"""
    print("🚀 Professional Email Sender System")
    print("=" * 50)
    
    # Create instance of the class
    email_sender = ProfessionalEmailSender()
    
    # Main menu
    while True:
        print("\n📧 Main Menu:")
        print("1. Send single email")
        print("2. Send bulk emails")
        print("3. Configure SMTP server")
        print("4. Create email template")
        print("5. Test SMTP connection")
        print("0. Exit")
        
        choice = input("\nSelect option (0-5): ").strip()
        
        if choice == '1':
            send_single_email(email_sender)
        elif choice == '2':
            send_bulk_email(email_sender)
        elif choice == '3':
            setup_smtp(email_sender)
        elif choice == '4':
            create_template()
        elif choice == '5':
            test_smtp_connection(email_sender)
        elif choice == '0':
            print("Goodbye! 👋")
            break
        else:
            print("❌ Invalid selection!")


def send_single_email(email_sender: ProfessionalEmailSender):
    """Send single email"""
    print("\n📧 Send Single Email")
    print("-" * 30)
    
    # Get SMTP information
    smtp_config = get_smtp_config(email_sender)
    if not smtp_config:
        return
    
    # Get email information
    sender_email = input("Sender email address: ").strip()
    sender_name = input("Sender name (optional): ").strip()
    recipient_email = input("Recipient email address: ").strip()
    recipient_name = input("Recipient name (optional): ").strip()
    subject = input("Email subject: ").strip()
    
    # Select content type
    print("\nContent type:")
    print("1. Plain text")
    print("2. HTML")
    print("3. Load from file")
    
    content_type = input("Select (1-3): ").strip()
    
    html_content = ""
    if content_type == '1':
        text = input("Email text: ")
        html_content = f"<html><body><p>{text}</p></body></html>"
    elif content_type == '2':
        html_content = input("HTML code: ")
    elif content_type == '3':
        file_path = input("HTML file path: ").strip()
        if os.path.exists(file_path):
            html_content = email_sender.load_template(file_path)
        else:
            print("❌ File not found!")
            return
    
    # Additional information
    company_name = input("Company name (optional): ").strip()
    department = input("Department name (optional): ").strip()
    
    # Send email
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name=recipient_name,
        subject=subject,
        html_content=html_content,
        company_name=company_name,
        department=department
    )
    
    if success:
        print("✅ Email sent successfully!")
    else:
        print("❌ Error sending email!")


def send_bulk_email(email_sender: ProfessionalEmailSender):
    """Send bulk emails"""
    print("\n📧 Send Bulk Emails")
    print("-" * 30)
    
    # Get SMTP information
    smtp_config = get_smtp_config(email_sender)
    if not smtp_config:
        return
    
    # Get sender information
    sender_email = input("Sender email address: ").strip()
    sender_name = input("Sender name: ").strip()
    subject = input("Email subject: ").strip()
    
    # Load template
    template_path = input("HTML template file path: ").strip()
    if not os.path.exists(template_path):
        print("❌ Template file not found!")
        return
    
    html_template = email_sender.load_template(template_path)
    
    # Load recipients list
    recipients_file = input("Recipients list file path (JSON): ").strip()
    if not os.path.exists(recipients_file):
        print("❌ Recipients file not found!")
        return
    
    try:
        with open(recipients_file, 'r', encoding='utf-8') as f:
            recipients = json.load(f)
    except Exception as e:
        print(f"❌ Error loading recipients file: {e}")
        return
    
    # Delay between sends
    delay = int(input("Delay between sends (seconds) [1]: ").strip() or "1")
    
    # Send bulk
    stats = email_sender.bulk_send(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipients=recipients,
        subject=subject,
        html_template=html_template,
        delay=delay
    )


def get_smtp_config(email_sender: ProfessionalEmailSender) -> Dict:
    """Get SMTP configuration from user"""
    print("\n⚙️ SMTP Configuration:")
    
    # Show predefined servers
    servers = email_sender.get_smtp_servers()
    print("\nAvailable servers:")
    for key, server in servers.items():
        print(f"{key}: {server['name']}")
    
    server_choice = input("\nSelect server (or 'custom' for custom): ").strip().lower()
    
    if server_choice in servers and server_choice != 'custom':
        smtp_config = servers[server_choice].copy()
    else:
        smtp_config = {
            'server': input("SMTP server address: ").strip(),
            'port': int(input("Port [587]: ").strip() or "587"),
            'security': input("Security type (tls/ssl/none) [tls]: ").strip().lower() or "tls"
        }
    
    smtp_config['username'] = input("Username: ").strip()
    smtp_config['password'] = input("Password: ").strip()
    
    return smtp_config


def setup_smtp(email_sender: ProfessionalEmailSender):
    """Setup and save SMTP configuration"""
    print("\n⚙️ Configure SMTP Server")
    print("-" * 30)
    
    smtp_config = get_smtp_config(email_sender)
    config_name = input("Configuration name: ").strip()
    
    # Save to configuration file
    current_config = email_sender.load_config()
    if 'smtp_configs' not in current_config:
        current_config['smtp_configs'] = {}
    
    current_config['smtp_configs'][config_name] = smtp_config
    
    if email_sender.save_config(current_config):
        print(f"✅ Configuration '{config_name}' saved!")
    else:
        print("❌ Error saving configuration!")


def create_template():
    """Create email template"""
    print("\n🎨 Create Email Template")
    print("-" * 30)
    
    template_name = input("Template name: ").strip()
    
    # Professional base template
    template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{subject}}</title>
    <style>
        body {
            font-family: 'Arial', 'Helvetica', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background-color: #ffffff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 2px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #007bff;
            margin: 0;
        }
        .content {
            text-align: left;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 12px;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            background-color: #007bff;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
        }
        .button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{company_name}}</h1>
        </div>
        
        <div class="content">
            <h2>Hello {{recipient_name}},</h2>
            
            <p>{{main_message}}</p>
            
            <a href="{{button_link}}" class="button">{{button_text}}</a>
            
            <p>{{closing_message}}</p>
            
            <p>Best regards,<br>
            {{sender_name}}<br>
            {{sender_title}}</p>
        </div>
        
        <div class="footer">
            <p>This email was sent by {{company_name}}.</p>
            <p>{{company_address}}</p>
        </div>
    </div>
</body>
</html>"""
    
    # Save template
    template_path = f"templates/{template_name}.html"
    os.makedirs("templates", exist_ok=True)
    
    try:
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content)
        print(f"✅ Template saved at {template_path}!")
        
        # Create variables example file
        variables_example = {
            "subject": "Email Subject",
            "company_name": "Your Company Name",
            "recipient_name": "Recipient Name",
            "main_message": "Your main message content",
            "button_text": "Click Here",
            "button_link": "https://example.com",
            "closing_message": "Thank you for your attention",
            "sender_name": "Sender Name",
            "sender_title": "Sender Title",
            "company_address": "Company Address"
        }
        
        variables_path = f"templates/{template_name}_variables.json"
        with open(variables_path, 'w', encoding='utf-8') as f:
            json.dump(variables_example, f, ensure_ascii=False, indent=4)
        
        print(f"✅ Variables file saved at {variables_path}!")
        
    except Exception as e:
        print(f"❌ Error saving template: {e}")


def test_smtp_connection(email_sender: ProfessionalEmailSender):
    """Test SMTP connection"""
    print("\n🔍 Test SMTP Connection")
    print("-" * 30)
    
    smtp_config = get_smtp_config(email_sender)
    
    try:
        if smtp_config.get('security') == 'ssl':
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(smtp_config['server'], smtp_config['port'], context=context)
        else:
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            if smtp_config.get('security') == 'tls':
                context = ssl.create_default_context()
                server.starttls(context=context)
        
        if smtp_config.get('username') and smtp_config.get('password'):
            server.login(smtp_config['username'], smtp_config['password'])
        
        server.quit()
        print("✅ SMTP connection successful!")
        
    except Exception as e:
        print(f"❌ Connection error: {e}")


if __name__ == "__main__":
    main()