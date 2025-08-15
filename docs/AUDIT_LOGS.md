# Audit Logs System

The Audit Logs system provides comprehensive tracking and monitoring of all system activities and user actions within the Pentesting Framework. This system is essential for security compliance, incident response, and operational monitoring.

## 🎯 Overview

The audit logs system captures:
- **User Authentication Events**: Login attempts, successful logins, failed logins, logouts
- **System Activities**: Port scans, vulnerability scans, reconnaissance activities
- **Administrative Actions**: User management, system configuration changes
- **Security Events**: Failed operations, suspicious activities, high-severity actions
- **Reporting Activities**: Report generation, exports, deletions

## 🏗️ Architecture

### Backend Components

#### 1. Database Model (`AuditLog`)
```python
class AuditLog(models.Model):
    id = models.AutoField(primary_key=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    user_email = models.CharField(max_length=255, null=True, blank=True)
    action = models.CharField(max_length=255)
    target = models.CharField(max_length=500, null=True, blank=True)
    module = models.CharField(max_length=50, choices=MODULE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)
    session_id = models.CharField(max_length=255, null=True, blank=True)
```

#### 2. Module Categories
- **scanning**: Port scans, vulnerability scans, NMAP/ZAP operations
- **reconnaissance**: WHOIS, DNS, subdomain enumeration
- **exploitation**: Metasploit operations, exploit attempts
- **reporting**: Report generation, exports, PDF creation
- **administration**: System configuration, user management
- **authentication**: Login/logout events, session management
- **user_management**: User profile updates, role changes
- **system**: System maintenance, backups, updates

#### 3. Status Levels
- **success**: Successful operations
- **failed**: Failed operations
- **warning**: Operations with warnings
- **info**: Informational events

#### 4. Severity Levels
- **low**: Routine operations
- **medium**: Important operations
- **high**: Critical operations
- **critical**: Security-critical events

### Frontend Components

#### 1. Audit Logs Page (`/dashboard/audit-logs`)
- Real-time log display with pagination
- Advanced filtering and search capabilities
- Export functionality (JSON/CSV)
- Statistics dashboard
- Log management tools

#### 2. API Integration
- RESTful API endpoints for log retrieval
- Real-time data fetching
- Filter and search capabilities
- Export and management functions

## 🔧 Setup and Installation

### 1. Database Migration
```bash
cd backend
python manage.py makemigrations
python manage.py migrate
```

### 2. Populate Sample Data (Optional)
```bash
cd backend
python populate_audit_logs.py
```

### 3. Verify Installation
```bash
# Check if audit logs table exists
python manage.py shell
>>> from api.models import AuditLog
>>> AuditLog.objects.count()
```

## 📊 API Endpoints

### 1. Get Audit Logs
```http
GET /api/audit-logs/
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `page_size`: Items per page (default: 50)
- `search`: Search term for action, user, target, or details
- `module`: Filter by module (scanning, reconnaissance, etc.)
- `status`: Filter by status (success, failed, warning, info)
- `user`: Filter by user email
- `severity`: Filter by severity (low, medium, high, critical)
- `start_date`: Filter by start date (YYYY-MM-DD)
- `end_date`: Filter by end date (YYYY-MM-DD)

**Response:**
```json
{
  "success": true,
  "logs": [...],
  "pagination": {
    "current_page": 1,
    "total_pages": 5,
    "total_count": 250,
    "has_next": true,
    "has_previous": false
  },
  "statistics": {
    "total_actions": 250,
    "failed_actions": 15,
    "active_users": 8,
    "security_events": 25
  },
  "filters": {
    "available_modules": [...],
    "available_statuses": [...],
    "available_severities": [...],
    "available_users": [...]
  }
}
```

### 2. Get Audit Statistics
```http
GET /api/audit-logs/statistics/
```

**Query Parameters:**
- `days`: Number of days to analyze (default: 30)

**Response:**
```json
{
  "success": true,
  "statistics": {
    "total_events": 1500,
    "security_events": 45,
    "unique_users": 12,
    "failed_actions": 23
  },
  "analytics": {
    "module_stats": [...],
    "status_stats": [...],
    "severity_stats": [...],
    "user_stats": [...],
    "daily_stats": [...],
    "top_actions": [...]
  }
}
```

### 3. Export Audit Logs
```http
POST /api/audit-logs/export/
```

**Request Body:**
```json
{
  "action": "export",
  "format": "json|csv",
  "filters": {
    "search": "port scan",
    "module": "scanning",
    "start_date": "2024-01-01",
    "end_date": "2024-01-31"
  }
}
```

### 4. Clear Old Logs
```http
POST /api/audit-logs/clear/
```

**Request Body:**
```json
{
  "action": "clear",
  "days_to_keep": 90
}
```

## 🛠️ Usage

### 1. Logging Events in Code

Use the `log_audit_event` utility function:

```python
from api.views import log_audit_event

# Log a successful operation
log_audit_event(
    request=request,
    action="Port scan initiated",
    target="192.168.1.0/24",
    module="scanning",
    status="success",
    severity="low",
    details="Nmap TCP SYN scan on 1000 ports"
)

# Log a failed operation
log_audit_event(
    request=request,
    action="Failed login attempt",
    target="unknown@external.com",
    module="authentication",
    status="failed",
    severity="medium",
    details="Invalid credentials provided"
)

# Log a security event
log_audit_event(
    request=request,
    action="Exploit module accessed",
    target="MS17-010 EternalBlue",
    module="exploitation",
    status="warning",
    severity="high",
    details="Exploit module loaded for testing"
)
```

### 2. Frontend Integration

The audit logs page automatically:
- Fetches logs from the API
- Provides real-time filtering and search
- Displays statistics and analytics
- Supports export functionality
- Handles pagination

### 3. Monitoring and Alerts

Set up monitoring for:
- **High-severity events**: Critical security events
- **Failed operations**: System failures or security issues
- **Authentication failures**: Potential security threats
- **Unusual activity patterns**: Anomaly detection

## 🔍 Filtering and Search

### Search Capabilities
- **Text Search**: Search across action, user, target, and details fields
- **Module Filter**: Filter by specific modules (scanning, reconnaissance, etc.)
- **Status Filter**: Filter by operation status
- **Severity Filter**: Filter by event severity
- **User Filter**: Filter by specific users
- **Date Range**: Filter by date range
- **IP Address**: Filter by source IP address

### Advanced Filtering
```javascript
// Example: Filter for high-severity security events
const filters = {
  severity: 'high',
  module: 'authentication',
  status: 'failed',
  start_date: '2024-01-01',
  end_date: '2024-01-31'
}
```

## 📈 Analytics and Reporting

### 1. Real-time Statistics
- Total actions performed
- Failed operations count
- Active users
- Security events

### 2. Trend Analysis
- Activity by module
- Status distribution
- Severity breakdown
- User activity patterns
- Daily activity trends

### 3. Security Metrics
- Authentication failures
- High-severity events
- Suspicious IP addresses
- Unusual user behavior

## 🔒 Security Considerations

### 1. Data Protection
- Audit logs contain sensitive information
- Implement proper access controls
- Encrypt log data at rest
- Regular backup and retention policies

### 2. Privacy Compliance
- Ensure GDPR compliance for user data
- Implement data retention policies
- Provide data export/deletion capabilities
- Anonymize sensitive information when needed

### 3. Access Control
- Restrict audit log access to administrators
- Implement role-based access control
- Log access to audit logs themselves
- Monitor for unauthorized access attempts

## 🚀 Performance Optimization

### 1. Database Optimization
- Indexed fields for fast queries
- Partitioning for large datasets
- Regular cleanup of old logs
- Efficient query patterns

### 2. Caching Strategy
- Cache frequently accessed statistics
- Implement query result caching
- Use Redis for session data
- Optimize API response times

### 3. Scalability
- Horizontal scaling for high-volume environments
- Load balancing for API endpoints
- Database sharding for large datasets
- CDN for static assets

## 🛠️ Troubleshooting

### Common Issues

#### 1. Migration Errors
```bash
# Reset migrations if needed
python manage.py migrate api zero
python manage.py makemigrations
python manage.py migrate
```

#### 2. Performance Issues
- Check database indexes
- Monitor query performance
- Implement pagination
- Use caching where appropriate

#### 3. Missing Logs
- Verify audit logging is enabled
- Check for exceptions in log creation
- Ensure proper user authentication
- Validate API endpoints

### Debug Commands
```bash
# Check audit log count
python manage.py shell
>>> from api.models import AuditLog
>>> AuditLog.objects.count()

# Check recent logs
>>> AuditLog.objects.order_by('-timestamp')[:5]

# Check logs by module
>>> AuditLog.objects.filter(module='authentication').count()
```

## 📚 Best Practices

### 1. Logging Guidelines
- Log all security-relevant events
- Include sufficient context in details
- Use appropriate severity levels
- Maintain consistent naming conventions

### 2. Monitoring Setup
- Set up alerts for critical events
- Monitor log volume and performance
- Regular review of security events
- Automated anomaly detection

### 3. Maintenance
- Regular cleanup of old logs
- Monitor database size
- Update retention policies
- Review and update logging rules

## 🔮 Future Enhancements

### Planned Features
- **Real-time Notifications**: WebSocket-based real-time updates
- **Advanced Analytics**: Machine learning for anomaly detection
- **Integration**: SIEM system integration
- **Compliance**: Automated compliance reporting
- **Visualization**: Advanced charts and graphs
- **API Rate Limiting**: Protect against abuse
- **Audit Trail**: Track changes to audit logs themselves

### Customization Options
- **Custom Fields**: Add organization-specific fields
- **Workflow Integration**: Connect with incident response workflows
- **Third-party Integrations**: Slack, email, SMS notifications
- **Custom Dashboards**: Organization-specific views
- **Advanced Filtering**: Saved filters and queries

## 📞 Support

For issues or questions regarding the audit logs system:
1. Check the troubleshooting section
2. Review the API documentation
3. Check the Django logs for errors
4. Contact the development team

---

**Note**: This audit logs system is designed for security and compliance purposes. Ensure proper access controls and data protection measures are in place before deployment in production environments. 