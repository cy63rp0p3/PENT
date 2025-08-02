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
             path('scan/comprehensive/', views.comprehensive_scan, name='comprehensive_scan'),
             path('scan/nmap/status/<str:scan_id>/', views.python_scan_status, name='nmap_scan_status'),
             path('scan/nmap/cancel/<str:scan_id>/', views.cancel_nmap_scan, name='cancel_nmap_scan'),
             path('scan/zap/status/<str:scan_id>/', views.zap_scan_status, name='zap_scan_status'),
             path('scan/zap/cancel/<str:scan_id>/', views.cancel_zap_scan, name='cancel_zap_scan'),
             path('scan/tools/availability/', views.check_tools_availability, name='check_tools_availability'),
             path('scan/nmap/all/', views.get_all_nmap_scans, name='get_all_nmap_scans'),
             path('scan/zap/all/', views.get_all_zap_scans, name='get_all_zap_scans'),
    
    # Metasploit
    path('metasploit/modules/', views.metasploit_modules, name='metasploit_modules'),
    path('metasploit/payloads/', views.metasploit_payloads, name='metasploit_payloads'),
    path('metasploit/run_exploit/', views.run_exploit, name='run_exploit'),
    path('metasploit/console/', views.metasploit_console, name='metasploit_console'),
    
    # Reports
    path('reports/scan-results/', views.get_scan_results, name='get_scan_results'),
    path('reports/generate/', views.generate_report, name='generate_report'),
    path('reports/generate-enhanced/', views.generate_enhanced_report, name='generate_enhanced_report'),
    path('reports/list/', views.get_reports, name='get_reports'),
    path('reports/detail/<str:report_id>/', views.get_report_detail, name='get_report_detail'),
    path('reports/statistics/', views.get_scan_statistics, name='get_scan_statistics'),
    path('reports/detailed-results/', views.get_detailed_scan_results, name='get_detailed_scan_results'),
    
    # Proactive Reporting System
    path('reports/individual/', views.get_individual_reports, name='get_individual_reports'),
    path('reports/comprehensive/', views.get_comprehensive_reports, name='get_comprehensive_reports'),
    path('reports/individual/<str:report_id>/', views.get_individual_report_detail, name='get_individual_report_detail'),
    path('reports/save-individual/', views.save_individual_report, name='save_individual_report'),
    path('reports/comprehensive/generate/', views.generate_comprehensive_report, name='generate_comprehensive_report'),
    path('reports/<str:report_type>/<str:report_id>/download/', views.download_report_pdf, name='download_report_pdf'),
    path('reports/<str:report_type>/<str:report_id>/', views.delete_report, name='delete_report'),
    
    # Nmap Detection
    path('scan/check-nmap/', views.check_nmap_availability, name='check_nmap_availability'),
    
    # Real Basic Port Scanner
    path('scan/basic-port-scan/', views.basic_port_scan, name='basic_port_scan'),
] 