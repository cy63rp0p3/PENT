from django.urls import path
from . import views

urlpatterns = [
    # User management
    path('user/stats/', views.user_stats, name='user_stats'),
    path('user/list/', views.list_users, name='list_users'),
    path('user/create/', views.create_user, name='create_user'),
    path('user/login/', views.login, name='login'),
    path('user/logout/', views.logout, name='logout'),
    path('user/delete/<int:user_id>/', views.delete_user, name='delete_user'),
    
    # Reconnaissance
    path('recon/whois/', views.whois_lookup, name='whois_lookup'),
    path('recon/dns/', views.dns_lookup, name='dns_lookup'),
    path('recon/subdomain/', views.subdomain_enum, name='subdomain_enum'),
    path('recon/progress/<str:scan_id>/', views.scan_progress, name='scan_progress'),
    path('recon/cancel/<str:scan_id>/', views.cancel_scan, name='cancel_scan'),
    
                 # Scanning
             path('scan/port/', views.port_scan, name='port_scan'),
             path('scan/vulnerability/', views.vulnerability_scan, name='vulnerability_scan'),
             path('scan/nmap/status/<str:scan_id>/', views.nmap_scan_status, name='nmap_scan_status'),
             path('scan/tools/availability/', views.check_tools_availability, name='check_tools_availability'),
             path('scan/nmap/all/', views.get_all_nmap_scans, name='get_all_nmap_scans'),
             path('scan/nmap/performance/', views.test_nmap_performance, name='test_nmap_performance'),
    
    # Metasploit
    path('metasploit/modules/', views.metasploit_modules, name='metasploit_modules'),
    path('metasploit/payloads/', views.metasploit_payloads, name='metasploit_payloads'),
    path('metasploit/run_exploit/', views.run_exploit, name='run_exploit'),
    path('metasploit/console/', views.metasploit_console, name='metasploit_console'),
    
    # Reports
    path('reports/scan-results/', views.get_scan_results, name='get_scan_results'),
    path('reports/generate/', views.generate_report, name='generate_report'),
    path('reports/list/', views.get_reports, name='get_reports'),
    path('reports/detail/<str:report_id>/', views.get_report_detail, name='get_report_detail'),
] 