from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[('admin', 'Admin'), ('pentester', 'Pentester'), ('viewer', 'Viewer'), ('guest', 'Guest')])
    
    class Meta:
        indexes = [
            models.Index(fields=['role']),
            models.Index(fields=['user']),
        ]