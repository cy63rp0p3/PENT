#!/usr/bin/env python
"""
Script to populate sample audit logs for testing
Run this after setting up the database and running migrations
"""

import os
import sys
import django
from datetime import datetime, timedelta
import random

# Add the project directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from api.models import AuditLog, UserProfile
from django.contrib.auth.models import User
from django.utils import timezone

def create_sample_audit_logs():
    """Create sample audit logs for testing"""
    
    # Sample users
    users = [
        {'email': 'admin@pent.com', 'role': 'admin'},
        {'email': 'john.doe@company.com', 'role': 'pentester'},
        {'email': 'jane.smith@company.com', 'role': 'pentester'},
        {'email': 'sarah.wilson@company.com', 'role': 'viewer'},
        {'email': 'mike.johnson@company.com', 'role': 'viewer'},
    ]
    
    # Sample actions for different modules
    sample_actions = {
        'scanning': [
            ('Port scan initiated', '192.168.1.0/24', 'success', 'low'),
            ('Vulnerability scan completed', 'web.example.com', 'success', 'low'),
            ('Port scan failed', 'invalid-target.com', 'failed', 'medium'),
            ('Nmap scan started', '10.0.0.1', 'success', 'low'),
            ('ZAP scan initiated', 'https://test.com', 'success', 'low'),
        ],
        'reconnaissance': [
            ('WHOIS lookup performed', 'example.com', 'success', 'low'),
            ('DNS enumeration completed', 'target.org', 'success', 'low'),
            ('Subdomain enumeration started', 'company.com', 'success', 'low'),
            ('SSL certificate check', 'secure-site.com', 'success', 'low'),
            ('Search engine indexing check', 'public-site.net', 'success', 'low'),
        ],
        'exploitation': [
            ('Exploit module accessed', 'MS17-010 EternalBlue', 'warning', 'high'),
            ('Payload generated', 'reverse_shell', 'success', 'medium'),
            ('Exploit execution attempted', 'CVE-2021-44228', 'failed', 'high'),
            ('Metasploit console opened', 'msfconsole', 'success', 'medium'),
            ('Exploit module loaded', 'exploit/windows/smb/ms17_010_eternalblue', 'warning', 'high'),
        ],
        'reporting': [
            ('Report generated', 'Security Assessment #001', 'success', 'low'),
            ('PDF report created', 'Vulnerability Report', 'success', 'low'),
            ('Comprehensive report started', 'Full Security Audit', 'success', 'low'),
            ('Report exported', 'Executive Summary', 'success', 'low'),
            ('Report deleted', 'Old Assessment Report', 'success', 'low'),
        ],
        'administration': [
            ('User role modified', 'mike.johnson@company.com', 'success', 'medium'),
            ('System configuration changed', 'Scan Rate Limits', 'success', 'medium'),
            ('User account created', 'new.user@company.com', 'success', 'medium'),
            ('User account deleted', 'old.user@company.com', 'success', 'medium'),
            ('System backup performed', 'Database Backup', 'success', 'low'),
        ],
        'authentication': [
            ('User login successful', 'admin@pent.com', 'success', 'low'),
            ('Failed login attempt', 'unknown@external.com', 'failed', 'medium'),
            ('User logout', 'john.doe@company.com', 'success', 'low'),
            ('Password reset requested', 'jane.smith@company.com', 'success', 'low'),
            ('Session expired', 'sarah.wilson@company.com', 'warning', 'low'),
        ],
        'user_management': [
            ('User profile updated', 'john.doe@company.com', 'success', 'medium'),
            ('User permissions modified', 'jane.smith@company.com', 'success', 'medium'),
            ('User account locked', 'suspicious.user@company.com', 'warning', 'high'),
            ('User account unlocked', 'suspicious.user@company.com', 'success', 'medium'),
            ('User session terminated', 'inactive.user@company.com', 'success', 'medium'),
        ],
        'system': [
            ('System maintenance started', 'Database Optimization', 'success', 'low'),
            ('System backup completed', 'Full System Backup', 'success', 'low'),
            ('System update installed', 'Security Patch v2.1', 'success', 'low'),
            ('System restart initiated', 'Scheduled Maintenance', 'success', 'low'),
            ('System error occurred', 'Database Connection Error', 'failed', 'high'),
        ]
    }
    
    # Sample IP addresses
    sample_ips = [
        '10.0.0.15', '10.0.0.22', '10.0.0.1', '10.0.0.18',
        '192.168.1.100', '192.168.1.101', '192.168.1.102',
        '203.0.113.45', '198.51.100.123', '172.16.0.50'
    ]
    
    # Sample details
    sample_details = [
        'Nmap TCP SYN scan on 1000 ports',
        '15 vulnerabilities found, 3 critical',
        'Role changed from Viewer to Pentester',
        'PDF report generated successfully',
        'Invalid credentials provided',
        '25 subdomains discovered',
        'Max concurrent scans increased to 10',
        'Exploit module loaded for testing',
        'SSL certificate validation completed',
        'DNS records retrieved successfully',
        'User session created successfully',
        'System configuration updated',
        'Backup completed successfully',
        'Security patch applied',
        'Database connection restored'
    ]
    
    # Create audit logs for the past 30 days
    end_date = timezone.now()
    start_date = end_date - timedelta(days=30)
    
    logs_created = 0
    
    for i in range(100):  # Create 100 sample logs
        # Random timestamp within the last 30 days
        random_days = random.randint(0, 30)
        random_hours = random.randint(0, 23)
        random_minutes = random.randint(0, 59)
        random_seconds = random.randint(0, 59)
        
        timestamp = end_date - timedelta(
            days=random_days,
            hours=random_hours,
            minutes=random_minutes,
            seconds=random_seconds
        )
        
        # Random user
        user_data = random.choice(users)
        user_email = user_data['email']
        
        # Random module and action
        module = random.choice(list(sample_actions.keys()))
        action, target, status, severity = random.choice(sample_actions[module])
        
        # Random IP address
        ip_address = random.choice(sample_ips)
        
        # Random details
        details = random.choice(sample_details)
        
        # Create the audit log
        try:
            AuditLog.objects.create(
                timestamp=timestamp,
                user_email=user_email,
                action=action,
                target=target,
                module=module,
                status=status,
                severity=severity,
                ip_address=ip_address,
                details=details,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                metadata={
                    'browser': 'Chrome',
                    'os': 'Windows 10',
                    'session_id': f'session_{random.randint(1000, 9999)}'
                }
            )
            logs_created += 1
        except Exception as e:
            print(f"Error creating log: {e}")
    
    print(f"✅ Successfully created {logs_created} sample audit logs")
    print(f"📊 Logs span from {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
    print(f"👥 Users: {', '.join([u['email'] for u in users])}")
    print(f"🔧 Modules: {', '.join(sample_actions.keys())}")

if __name__ == '__main__':
    print("🐍 Populating sample audit logs...")
    create_sample_audit_logs()
    print("🎉 Sample audit logs population completed!") 