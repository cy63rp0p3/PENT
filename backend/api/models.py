from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

# Create your models here.

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[('admin', 'Admin'), ('pentester', 'Pentester'), ('viewer', 'Viewer'), ('guest', 'Guest')])
    
    class Meta:
        indexes = [
            models.Index(fields=['role']),
            models.Index(fields=['user']),
        ]

class AuditLog(models.Model):
    MODULE_CHOICES = [
        ('scanning', 'Scanning'),
        ('reconnaissance', 'Reconnaissance'),
        ('exploitation', 'Exploitation'),
        ('reporting', 'Reporting'),
        ('administration', 'Administration'),
        ('authentication', 'Authentication'),
        ('user_management', 'User Management'),
        ('system', 'System'),
    ]
    
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('warning', 'Warning'),
        ('info', 'Info'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    id = models.AutoField(primary_key=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    user_email = models.CharField(max_length=255, null=True, blank=True)  # Store email even if user is deleted
    action = models.CharField(max_length=255)
    target = models.CharField(max_length=500, null=True, blank=True)
    module = models.CharField(max_length=50, choices=MODULE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='info')
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='low')
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)  # Store additional data as JSON
    session_id = models.CharField(max_length=255, null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['user']),
            models.Index(fields=['module']),
            models.Index(fields=['status']),
            models.Index(fields=['severity']),
            models.Index(fields=['ip_address']),
        ]
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.timestamp} - {self.user_email or 'Unknown'} - {self.action}"
    
    def save(self, *args, **kwargs):
        # Auto-populate user_email if user is provided
        if self.user and not self.user_email:
            self.user_email = self.user.email
        super().save(*args, **kwargs)