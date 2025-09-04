#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Single Email Sending Example

This example demonstrates how to use the email sending system to send a single email.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_sender import ProfessionalEmailSender

def main():
    # ایجاد نمونه از سیستم ارسال ایمیل
    email_sender = ProfessionalEmailSender()
    
    # SMTP Configuration (Gmail)
    smtp_config = {
        'server': 'smtp.gmail.com',
        'port': 587,
        'security': 'tls',
        'username': 'your_email@gmail.com',  # Enter your email address
        'password': 'your_app_password'      # Enter your App Password
    }
    
    # Email Information
    sender_email = 'your_email@gmail.com'
    sender_name = 'Your Name'
    recipient_email = 'recipient@example.com'
    recipient_name = 'Recipient Name'
    subject = 'Professional Email System Test'
    
    # HTML Email Content
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <style>
            body {
                font-family: Arial, Helvetica, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 600px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f4f4f4;
            }
            .container {
                background-color: white;
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
            .button {
                display: inline-block;
                padding: 12px 24px;
                background-color: #007bff;
                color: white;
                text-decoration: none;
                border-radius: 5px;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Email System Test</h1>
            </div>
            <h2>Hello!</h2>
            <p>This is a test email sent using the Professional Email Sending System.</p>
            <p>System Features:</p>
            <ul>
                <li>Support for beautiful HTML templates</li>
                <li>Advanced anti-spam headers</li>
                <li>Support for multiple SMTP servers</li>
                <li>Bulk email sending capability</li>
                <li>File attachment support</li>
            </ul>
            <div style="text-align: center;">
                <a href="https://github.com" class="button">View Project</a>
            </div>
            <p>Best regards,<br>Development Team</p>
        </div>
    </body>
    </html>
    """
    
    # Custom Headers
    custom_headers = {
        'X-Campaign-ID': 'test-campaign-001',
        'X-Email-Type': 'transactional'
    }
    
    # Send Email
    print("🚀 Starting email send...")
    
    success = email_sender.send_email(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipient_email=recipient_email,
        recipient_name=recipient_name,
        subject=subject,
        html_content=html_content,
        custom_headers=custom_headers,
        company_name="Test Company",
        department="IT Department",
        priority="normal"
    )
    
    if success:
        print("✅ Email sent successfully!")
    else:
        print("❌ Error sending email!")

if __name__ == "__main__":
    main()