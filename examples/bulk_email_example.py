#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bulk Email Sending Example

This example demonstrates how to use the system to send bulk emails with custom templates.
"""

import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from email_sender import ProfessionalEmailSender

def create_sample_recipients():
    """Create sample recipients file"""
    recipients = [
        {
            "email": "user1@example.com",
            "name": "John Smith",
            "variables": {
                "first_name": "John",
                "last_name": "Smith",
                "company": "Alpha Company",
                "position": "Sales Manager",
                "special_offer": "20% Discount",
                "expiry_date": "December 31, 2024"
            }
        },
        {
            "email": "user2@example.com",
            "name": "Sarah Johnson",
            "variables": {
                "first_name": "Sarah",
                "last_name": "Johnson", 
                "company": "Beta Corporation",
                "position": "Marketing Manager",
                "special_offer": "15% Discount",
                "expiry_date": "December 31, 2024"
            }
        },
        {
            "email": "user3@example.com",
            "name": "Michael Brown",
            "variables": {
                "first_name": "Michael",
                "last_name": "Brown",
                "company": "Gamma Inc",
                "position": "IT Manager",
                "special_offer": "25% Discount",
                "expiry_date": "December 31, 2024"
            }
        }
    ]
    
    with open('recipients.json', 'w', encoding='utf-8') as f:
        json.dump(recipients, f, ensure_ascii=False, indent=4)
    
    print("✅ recipients.json file created!")
    return recipients

def main():
    # Create email sender instance
    email_sender = ProfessionalEmailSender()
    
    # SMTP Configuration
    smtp_config = {
        'server': 'smtp.gmail.com',
        'port': 587,
        'security': 'tls',
        'username': 'your_email@gmail.com',  # Enter your email address
        'password': 'your_app_password'      # Enter your App Password
    }
    
    # Sender information
    sender_email = 'your_email@gmail.com'
    sender_name = 'Marketing Team'
    subject = 'Special Offer for {{first_name}}'
    
    # HTML template with substitutable variables
    html_template = """
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
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
            }
            .offer-box {
                background: linear-gradient(135deg, #ffeaa7, #fdcb6e);
                padding: 20px;
                border-radius: 10px;
                text-align: center;
                margin: 20px 0;
            }
            .offer-box h2 {
                color: #2d3436;
                font-size: 24px;
                margin: 0;
            }
            .button {
                display: inline-block;
                padding: 15px 30px;
                background: linear-gradient(135deg, #00b894, #00cec9);
                color: white;
                text-decoration: none;
                border-radius: 25px;
                font-weight: bold;
                margin: 20px 0;
                transition: transform 0.3s ease;
            }
            .button:hover {
                transform: translateY(-2px);
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding-top: 20px;
                border-top: 1px solid #eee;
                color: #666;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Special Offer</h1>
                <p>Exclusively for Our Valued Customers</p>
            </div>
            
            <h2>Hello {{first_name}},</h2>
            
            <p>We hope you're doing well at {{company}}.</p>
            
            <p>As our respected {{position}}, we have a special offer for you:</p>
            
            <div class="offer-box">
                <h2>{{special_offer}}</h2>
                <p>On All Our Products</p>
                <p><strong>Valid Until: {{expiry_date}}</strong></p>
            </div>
            
            <p>This limited-time offer is exclusively designed for valued customers like you.</p>
            
            <div style="text-align: center;">
                <a href="https://example.com/offer" class="button">Claim Your Offer</a>
            </div>
            
            <p>If you have any questions, please don't hesitate to contact us.</p>
            
            <p>Best regards,<br>
            Sales Team<br>
            Example Company</p>
            
            <div class="footer">
                <p>This email was sent to {{email}}.</p>
                <p>To unsubscribe, <a href="#">click here</a>.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Create sample recipients file
    recipients = create_sample_recipients()
    
    print("🚀 Starting bulk email send...")
    
    # Send bulk emails
    stats = email_sender.bulk_send(
        smtp_config=smtp_config,
        sender_email=sender_email,
        sender_name=sender_name,
        recipients=recipients,
        subject=subject,
        html_template=html_template,
        delay=2,  # 2 second delay between each send
        company_name="Example Company",
        department="Marketing Department",
        priority="normal"
    )
    
    print("\n📊 Final Report:")
    print(f"Total emails: {stats['total']}")
    print(f"Successful sends: {stats['sent']}")
    print(f"Failed sends: {stats['failed']}")
    
    if stats['errors']:
        print("\n❌ Errors:")
        for error in stats['errors']:
            print(f"  - {error}")

if __name__ == "__main__":
    main()