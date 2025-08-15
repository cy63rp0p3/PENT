# Generated manually for AuditLog model

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('api', '0002_userprofile_api_userpro_role_9579a2_idx_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('timestamp', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('user_email', models.CharField(blank=True, max_length=255, null=True)),
                ('action', models.CharField(max_length=255)),
                ('target', models.CharField(blank=True, max_length=500, null=True)),
                ('module', models.CharField(choices=[('scanning', 'Scanning'), ('reconnaissance', 'Reconnaissance'), ('exploitation', 'Exploitation'), ('reporting', 'Reporting'), ('administration', 'Administration'), ('authentication', 'Authentication'), ('user_management', 'User Management'), ('system', 'System')], max_length=50)),
                ('status', models.CharField(choices=[('success', 'Success'), ('failed', 'Failed'), ('warning', 'Warning'), ('info', 'Info')], default='info', max_length=20)),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='low', max_length=20)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('user_agent', models.TextField(blank=True, null=True)),
                ('details', models.TextField(blank=True, null=True)),
                ('metadata', models.JSONField(blank=True, null=True)),
                ('session_id', models.CharField(blank=True, max_length=255, null=True)),
                ('user', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='audit_logs', to='auth.user')),
            ],
            options={
                'ordering': ['-timestamp'],
                'indexes': [
                    models.Index(fields=['timestamp'], name='api_auditlo_timesta_123456_idx'),
                    models.Index(fields=['user'], name='api_auditlo_user_id_123456_idx'),
                    models.Index(fields=['module'], name='api_auditlo_module_123456_idx'),
                    models.Index(fields=['status'], name='api_auditlo_status_123456_idx'),
                    models.Index(fields=['severity'], name='api_auditlo_severit_123456_idx'),
                    models.Index(fields=['ip_address'], name='api_auditlo_ip_addr_123456_idx'),
                ],
            },
        ),
    ] 