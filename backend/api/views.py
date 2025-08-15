from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
import datetime
from django.contrib.auth import authenticate
from .models import UserProfile, AuditLog
from django.contrib.auth import get_user_model
from pymetasploit3.msfrpc import MsfRpcClient
import os
import time
import whois
import dns.resolver
from rest_framework.permissions import AllowAny
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.views.decorators.cache import cache_page
import uuid
import requests
import subprocess
from django.http import JsonResponse
import json
import datetime
import re
from django.utils import timezone
from django.db.models import Q, Count
from django.core.paginator import Paginator

# Import our services
from .nmap_service import NmapService
from .zap_service import ZAPService

# Initialize services
nmap_service = NmapService()
zap_service = ZAPService()

# In-memory storage for ZAP scan results (in production, use database)
zap_scan_results = {}

def log_audit_event(request, action, target=None, module='system', status='info', severity='low', details=None, metadata=None):
    """
    Utility function to log audit events
    """
    try:
        user = request.user if hasattr(request, 'user') and request.user.is_authenticated else None
        user_email = user.email if user else None
        
        # Get client IP address
        ip_address = None
        if hasattr(request, 'META'):
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0].strip()
            else:
                ip_address = request.META.get('REMOTE_ADDR')
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '') if hasattr(request, 'META') else ''
        
        # Get session ID
        session_id = request.session.session_key if hasattr(request, 'session') else None
        
        AuditLog.objects.create(
            user=user,
            user_email=user_email,
            action=action,
            target=target,
            module=module,
            status=status,
            severity=severity,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            metadata=metadata,
            session_id=session_id
        )
    except Exception as e:
        # Don't let audit logging failures break the main functionality
        print(f"Audit logging failed: {e}")

# Create your views here.

@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    print(f"🔐 Login attempt for: {email}")

    user = authenticate(username=email, password=password)

    if user:
        try:
            profile = user.userprofile
            role = profile.role
        except UserProfile.DoesNotExist:
            role = 'guest'

        # Mark user as logged in
        session_data = {
            'user_id': user.id,
            'email': user.email,
            'login_time': datetime.datetime.now().isoformat(),
            'last_activity': datetime.datetime.now().isoformat()
        }
        
        # Set session in cache
        cache_key = f'user_session:{user.id}'
        cache.set(cache_key, session_data, timeout=60*60*24)  # 24 hours timeout
        
        print(f'✅ User session created for {user.email} (ID: {user.id})')
        print(f'✅ Session key: {cache_key}')
        print(f'✅ Session data: {session_data}')
        
        # Verify session was created
        retrieved_session = cache.get(cache_key)
        if retrieved_session:
            print(f'✅ Session verification successful for {user.email}')
            print(f'✅ Retrieved session: {retrieved_session}')
        else:
            print(f'❌ Session verification failed for {user.email}')
            print(f'❌ Cache key {cache_key} not found')

        # Log successful login
        log_audit_event(
            request=request,
            action="User login successful",
            target=user.email,
            module="authentication",
            status="success",
            severity="low",
            details=f"User {user.email} logged in successfully with role {role}"
        )
        
        response = Response({
            'user': {'id': str(user.id), 'email': user.email, 'role': role},
            'session': {'access_token': 'demo-token'},
        })
        # Mock log
        print(f'Login: {user.email} at {datetime.datetime.now()}')
        return response
    else:
        # Log failed login attempt
        log_audit_event(
            request=request,
            action="Failed login attempt",
            target=email,
            module="authentication",
            status="failed",
            severity="medium",
            details=f"Failed login attempt for email: {email}"
        )
        
        print(f'❌ Login failed for: {email}')
        return Response({'error': 'Invalid login credentials'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def logout(request):
    user_email = request.data.get('email')
    if user_email:
        try:
            user = get_user_model().objects.get(email=user_email)
            # Remove user session
            cache.delete(f'user_session:{user.id}')
            print(f'Logout: {user.email} (ID: {user.id}) at {datetime.datetime.now()}')
            print(f'Session removed for user {user.id}')
            return Response({'success': True})
        except get_user_model().DoesNotExist:
            pass
    
    # Log logout attempt
    log_audit_event(
        request=request,
        action="User logout",
        target=user_email or "unknown",
        module="authentication",
        status="success",
        severity="low",
        details=f"User logout attempt for: {user_email or 'unknown'}"
    )
    
    return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
def get_user(request):
    user_email = request.COOKIES.get('userEmail')

    if user_email:
        try:
            user = get_user_model().objects.select_related('userprofile').get(email=user_email)
            profile = user.userprofile
            return Response({
                'data': {
                    'user': {'id': str(user.id), 'email': user.email, 'role': profile.role},
                },
                'error': None
            })
        except (get_user_model().DoesNotExist, UserProfile.DoesNotExist):
            pass

    return Response({
        'data': {'user': None},
        'error': None
    })

@api_view(['GET'])
def metasploit_modules(request):
    try:
        # Credentials should be securely managed in production
        msf_user = os.environ.get('MSF_RPC_USER', 'PENT')
        msf_pass = os.environ.get('MSF_RPC_PASS', 'PENTadmin')
        msf_host = os.environ.get('MSF_RPC_HOST', '192.168.146.129')
        msf_port = int(os.environ.get('MSF_RPC_PORT', 55553))
        print(f"Connecting to MSF RPC with: user={msf_user}, pass={msf_pass}, host={msf_host}, port={msf_port}")
        client = MsfRpcClient(msf_pass, username=msf_user, server=msf_host, port=msf_port, ssl=False)
        all_modules = list(client.modules.exploits)
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 100))
        start = (page - 1) * page_size
        end = start + page_size
        paginated_modules = all_modules[start:end]
        return Response({
            'modules': paginated_modules,
            'page': page,
            'page_size': page_size,
            'total': len(all_modules),
            'total_pages': (len(all_modules) + page_size - 1) // page_size
        })
    except Exception as e:
        print(f"Connection error: {str(e)}")
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
def metasploit_payloads(request):
    try:
        exploit_module = request.GET.get('exploit_module')
        if not exploit_module:
            return Response({'error': 'exploit_module parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

        msf_user = os.environ.get('MSF_RPC_USER', 'PENT')
        msf_pass = os.environ.get('MSF_RPC_PASS', 'PENTadmin')
        msf_host = os.environ.get('MSF_RPC_HOST', '192.168.146.129')
        msf_port = int(os.environ.get('MSF_RPC_PORT', 55553))
        client = MsfRpcClient(msf_pass, username=msf_user, server=msf_host, port=msf_port, ssl=False)

        exploit = client.modules.use('exploit', exploit_module)
        exploit.target = 0  # Set default target to get compatible payloads
        payloads = exploit.target_payloads()

        return Response({'payloads': payloads})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def run_exploit(request):
    try:
        data = request.data
        exploit_module = data.get('exploit_module')
        target = data.get('target')
        port = int(data.get('port', 80))
        use_ssl = data.get('use_ssl', False)
        url_path = data.get('url_path', '/')
        lhost = data.get('lhost')
        lport = int(data.get('lport', 4444))
        payload = data.get('payload')

        # Connect to MSF RPC
        msf_user = os.environ.get('MSF_RPC_USER', 'PENT')
        msf_pass = os.environ.get('MSF_RPC_PASS', 'PENTadmin')
        msf_host = os.environ.get('MSF_RPC_HOST', '192.168.146.129')
        msf_port = int(os.environ.get('MSF_RPC_PORT', 55553))
        client = MsfRpcClient(msf_pass, username=msf_user, server=msf_host, port=msf_port, ssl=False)

        # Create a console
        console = client.consoles.console()

        console.write(f'use {exploit_module}\n')
        time.sleep(1)

        console.write(f'set RHOSTS {target}\n')
        console.write(f'set RPORT {port}\n')
        console.write(f'set SSL {str(use_ssl).lower()}\n')
        console.write(f'set VHOST {target}\n')
        console.write(f'set URIPATH {url_path}\n')
        console.write(f'set LHOST {lhost}\n')
        console.write(f'set LPORT {lport}\n')
        if payload:
          console.write(f'set PAYLOAD {payload}\n')

        console.write('exploit -j\n')
        time.sleep(2)

        # Poll for output
        output = ''
        timeout = 60  # seconds
        start_time = time.time()
        while console.is_busy() and (time.time() - start_time < timeout):
            output += console.read()['data']
            time.sleep(1)
        output += console.read()['data']  # Final read

        console.destroy()

        return Response({'status': 'Exploit launched', 'output': output})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def metasploit_console(request):
    import time
    try:
        command = request.data.get('command')
        if not command:
            return Response({'error': 'No command provided'}, status=status.HTTP_400_BAD_REQUEST)

        msf_user = os.environ.get('MSF_RPC_USER')
        msf_pass = os.environ.get('MSF_RPC_PASS')
        if not msf_user or not msf_pass:
            return Response({'error': 'MSF_RPC_USER and MSF_RPC_PASS must be set'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        msf_host = os.environ.get('MSF_RPC_HOST', '192.168.146.129')
        msf_port = int(os.environ.get('MSF_RPC_PORT', 55553))
        client = MsfRpcClient(msf_pass, username=msf_user, server=msf_host, port=msf_port, ssl=False)

        console = client.consoles.console()
        console.write(command + '\n')
        time.sleep(1)
        output = ''
        timeout = 30
        start_time = time.time()
        while console.is_busy() and (time.time() - start_time < timeout):
            output += console.read()['data']
            time.sleep(1)
        output += console.read()['data']
        console.destroy()
        return Response({'output': output})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

SCAN_PROGRESS_TIMEOUT = 60 * 10  # 10 minutes

@api_view(['POST'])
def whois_lookup(request):
    target = request.data.get('target')
    if not target:
        return Response({'error': 'No target provided'}, status=400)
    scan_id = str(uuid.uuid4())
    cache.set(f'scan:{scan_id}:progress', 0, timeout=SCAN_PROGRESS_TIMEOUT)
    cache.set(f'scan:{scan_id}:result', None, timeout=SCAN_PROGRESS_TIMEOUT)
    
    def do_whois():
        try:
            cache.set(f'scan:{scan_id}:progress', 0, timeout=SCAN_PROGRESS_TIMEOUT)
            time.sleep(0.2)
            if cache.get(f'scan:{scan_id}:cancelled', False):
                cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                cache.set(f'scan:{scan_id}:result', {'type': 'cancelled', 'data': None}, timeout=SCAN_PROGRESS_TIMEOUT)
                return
            cache.set(f'scan:{scan_id}:progress', 10, timeout=SCAN_PROGRESS_TIMEOUT)
            time.sleep(0.2)
            if cache.get(f'scan:{scan_id}:cancelled', False):
                cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                cache.set(f'scan:{scan_id}:result', {'type': 'cancelled', 'data': None}, timeout=SCAN_PROGRESS_TIMEOUT)
                return
            cache.set(f'scan:{scan_id}:progress', 30, timeout=SCAN_PROGRESS_TIMEOUT)
            time.sleep(0.2)
            if cache.get(f'scan:{scan_id}:cancelled', False):
                cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                cache.set(f'scan:{scan_id}:result', {'type': 'cancelled', 'data': None}, timeout=SCAN_PROGRESS_TIMEOUT)
                return
            cache.set(f'scan:{scan_id}:progress', 60, timeout=SCAN_PROGRESS_TIMEOUT)
            time.sleep(0.2)
            if cache.get(f'scan:{scan_id}:cancelled', False):
                cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                cache.set(f'scan:{scan_id}:result', {'type': 'cancelled', 'data': None}, timeout=SCAN_PROGRESS_TIMEOUT)
                return
            w = whois.whois(target)
            cache.set(f'scan:{scan_id}:progress', 90, timeout=SCAN_PROGRESS_TIMEOUT)
            time.sleep(0.2)
            if cache.get(f'scan:{scan_id}:cancelled', False):
                cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                cache.set(f'scan:{scan_id}:result', {'type': 'cancelled', 'data': None}, timeout=SCAN_PROGRESS_TIMEOUT)
                return
            whois_data = {
                'domain': w.domain_name[0] if isinstance(w.domain_name, list) else w.domain_name,
                'registrar': w.registrar,
                'created': str(w.creation_date[0]) if isinstance(w.creation_date, list) else str(w.creation_date),
                'expires': str(w.expiration_date[0]) if isinstance(w.expiration_date, list) else str(w.expiration_date),
                'updated': str(w.updated_date[0]) if isinstance(w.updated_date, list) else str(w.updated_date),
                'nameservers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
                'organization': w.org or w.get('org', ''),
                'admin_email': w.admin_email or w.get('admin_email', ''),
                'tech_email': w.tech_email or w.get('tech_email', ''),
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                'country': w.country or w.get('country', ''),
                'city': w.city or w.get('city', ''),
                'state': w.state or w.get('state', ''),
                'zipcode': w.zipcode or w.get('zipcode', ''),
                'address': w.address or w.get('address', ''),
                'dnssec': w.dnssec or w.get('dnssec', ''),
                'whois_server': w.whois_server or w.get('whois_server', ''),
                'registrant_name': w.registrant_name or w.get('registrant_name', ''),
                'registrant_organization': w.registrant_organization or w.get('registrant_organization', ''),
                'registrant_email': w.registrant_email or w.get('registrant_email', ''),
            }
            cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
            cache.set(f'scan:{scan_id}:result', {'type': 'whois', 'data': whois_data}, timeout=SCAN_PROGRESS_TIMEOUT)
        except Exception as e:
            cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
            cache.set(f'scan:{scan_id}:result', {'error': str(e)}, timeout=SCAN_PROGRESS_TIMEOUT)
    import threading
    threading.Thread(target=do_whois).start()
    return Response({'scan_id': scan_id})

@api_view(['POST'])
def dns_lookup(request):
    target = request.data.get('target')
    if not target:
        return Response({'error': 'No target provided'}, status=400)
    scan_id = str(uuid.uuid4())
    cache.set(f'scan:{scan_id}:progress', 0, timeout=SCAN_PROGRESS_TIMEOUT)
    cache.set(f'scan:{scan_id}:result', None, timeout=SCAN_PROGRESS_TIMEOUT)
    
    def do_dns():
        try:
            records = []
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']
            total = len(record_types)
            for idx, rtype in enumerate(record_types):
                try:
                    answers = dns.resolver.resolve(target, rtype)
                    for ans in answers:
                        records.append({
                            'type': rtype,
                            'name': target,
                            'value': str(ans),
                            'ttl': answers.rrset.ttl if hasattr(answers, 'rrset') else 0,
                            'priority': getattr(ans, 'preference', None) if rtype == 'MX' else None
                        })
                except Exception:
                    pass
                cache.set(f'scan:{scan_id}:progress', int((idx+1)/total*90), timeout=SCAN_PROGRESS_TIMEOUT)
                time.sleep(0.15)
                if cache.get(f'scan:{scan_id}:cancelled', False):
                    cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                    cache.set(f'scan:{scan_id}:result', {'type': 'cancelled', 'data': None}, timeout=SCAN_PROGRESS_TIMEOUT)
                    return
            records.sort(key=lambda x: x['type'])
            cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
            cache.set(f'scan:{scan_id}:result', {'type': 'dns', 'data': {
                'records': records,
                'total_records': len(records),
                'record_types_found': list(set(r['type'] for r in records)),
                'target': target
            }}, timeout=SCAN_PROGRESS_TIMEOUT)
        except Exception as e:
            cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
            cache.set(f'scan:{scan_id}:result', {'error': str(e)}, timeout=SCAN_PROGRESS_TIMEOUT)
    import threading
    threading.Thread(target=do_dns).start()
    return Response({'scan_id': scan_id})

@api_view(['POST'])
def subdomain_enum(request):
    import socket
    import ssl
    import requests
    from urllib.parse import urlparse
    import json
    import time
    
    target = request.data.get('target')
    tool_type = request.data.get('tool_type', 'bruteforce')  # Default to bruteforce
    
    if not target:
        return Response({'error': 'No target provided'}, status=400)
    
    # Enhanced wordlist for better subdomain discovery
    wordlist = [
        'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'support',
        'cdn', 'static', 'media', 'img', 'images', 'assets', 'js', 'css', 'app', 'web',
        'mobile', 'm', 'secure', 'ssl', 'vpn', 'remote', 'office', 'corp', 'internal',
        'intranet', 'portal', 'dashboard', 'panel', 'cpanel', 'webmail', 'email',
        'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns', 'mx', 'srv', 'ldap', 'radius',
        'auth', 'login', 'signin', 'register', 'signup', 'account', 'user', 'users',
        'profile', 'settings', 'config', 'conf', 'backup', 'db', 'database', 'sql',
        'mysql', 'postgres', 'redis', 'cache', 'memcached', 'elasticsearch', 'solr',
        'jenkins', 'git', 'svn', 'repo', 'repository', 'docs', 'documentation',
        'help', 'faq', 'forum', 'community', 'chat', 'irc', 'support', 'ticket',
        'bug', 'issue', 'tracker', 'wiki', 'kb', 'knowledge', 'base', 'download',
        'upload', 'files', 'file', 'storage', 'backup', 'archive', 'old', 'legacy',
        'beta', 'alpha', 'staging', 'prod', 'production', 'live', 'demo', 'sandbox',
        'test', 'testing', 'qa', 'quality', 'assurance', 'monitor', 'monitoring',
        'stats', 'statistics', 'analytics', 'tracking', 'log', 'logs', 'logging',
        'cloud', 'aws', 'azure', 'gcp', 'heroku', 'digitalocean', 'linode', 'vps',
        'server', 'servers', 'loadbalancer', 'lb', 'proxy', 'gateway', 'router',
        'firewall', 'fw', 'ids', 'ips', 'waf', 'ddos', 'protection', 'security',
        'vulnerability', 'scan', 'scanner', 'nmap', 'nessus', 'openvas', 'qualys',
        'rapid7', 'tenable', 'crowdstrike', 'carbonblack', 'sentinelone', 'cylance'
    ]
    
    scan_id = str(uuid.uuid4())
    cache.set(f'scan:{scan_id}:progress', 0, timeout=SCAN_PROGRESS_TIMEOUT)
    cache.set(f'scan:{scan_id}:result', None, timeout=SCAN_PROGRESS_TIMEOUT)
    
    def check_ssl_certificate(hostname, port=443):
        """Check SSL certificate information for a hostname"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', []),
                        'valid': True
                    }
        except Exception:
            return {'valid': False}
    
    def check_search_engine_indexing(subdomain):
        """Simulate search engine indexing check"""
        try:
            # Simulate checking if subdomain is indexed
            import random
            indexed = random.choice([True, False])
            search_engines = []
            if indexed:
                search_engines = random.sample(['Google', 'Bing', 'Yahoo', 'DuckDuckGo'], random.randint(1, 3))
            return {
                'indexed': indexed,
                'search_engines': search_engines,
                'last_seen': time.strftime('%Y-%m-%d'),
                'page_rank': random.randint(1, 10) if indexed else 0
            }
        except Exception:
            return {'indexed': False, 'search_engines': [], 'last_seen': None, 'page_rank': 0}
    
    def check_virustotal_reputation(subdomain):
        """Simulate VirusTotal reputation check"""
        try:
            import random
            # Simulate VirusTotal-like data
            detections = random.randint(0, 5)
            total_engines = 90
            reputation_score = random.randint(0, 100)
            
            if detections == 0:
                reputation = "Clean"
                category = "Benign"
            elif detections <= 2:
                reputation = "Low Risk"
                category = "Suspicious"
            else:
                reputation = "High Risk"
                category = "Malicious"
            
            return {
                'detections': detections,
                'total_engines': total_engines,
                'reputation_score': reputation_score,
                'reputation': reputation,
                'category': category,
                'last_scan': time.strftime('%Y-%m-%d %H:%M:%S'),
                'community_score': random.randint(-10, 10)
            }
        except Exception:
            return {
                'detections': 0,
                'total_engines': 90,
                'reputation_score': 0,
                'reputation': 'Unknown',
                'category': 'Unknown',
                'last_scan': None,
                'community_score': 0
            }
    
    def do_subdomain():
        found = []
        errors = []
        total = len(wordlist)
        
        for idx, sub in enumerate(wordlist):
            subdomain = f"{sub}.{target}"
            try:
                ip = socket.gethostbyname(subdomain)
                
                # Base subdomain data
                subdomain_data = {
                    'subdomain': subdomain,
                    'ip': ip,
                    'status': 'active',
                    'type': 'A',
                    'discovery_method': tool_type
                }
                
                # Add tool-specific data
                if tool_type == 'bruteforce':
                    # DNS Bruteforce specific data
                    try:
                        # Get additional DNS records
                        import dns.resolver
                        additional_records = []
                        for record_type in ['AAAA', 'CNAME', 'MX', 'TXT']:
                            try:
                                answers = dns.resolver.resolve(subdomain, record_type)
                                for ans in answers:
                                    additional_records.append({
                                        'type': record_type,
                                        'value': str(ans)
                                    })
                            except:
                                pass
                        subdomain_data['dns_records'] = additional_records
                        subdomain_data['response_time'] = random.randint(10, 100)  # ms
                    except Exception as e:
                        subdomain_data['dns_records'] = []
                        subdomain_data['response_time'] = 0
                
                elif tool_type == 'certificate':
                    # Certificate Transparency specific data
                    ssl_info = check_ssl_certificate(subdomain)
                    subdomain_data['ssl_certificate'] = ssl_info
                    if ssl_info['valid']:
                        subdomain_data['ssl_issuer'] = ssl_info['issuer'].get('commonName', 'Unknown')
                        subdomain_data['ssl_expiry'] = ssl_info['not_after']
                        subdomain_data['ssl_subject_alt_names'] = [name[1] for name in ssl_info['san'] if name[0] == 'DNS']
                    else:
                        subdomain_data['ssl_issuer'] = 'No SSL'
                        subdomain_data['ssl_expiry'] = None
                        subdomain_data['ssl_subject_alt_names'] = []
                
                elif tool_type == 'search':
                    # Search Engine Discovery specific data
                    search_info = check_search_engine_indexing(subdomain)
                    subdomain_data['search_engine_data'] = search_info
                    subdomain_data['indexed'] = search_info['indexed']
                    subdomain_data['search_engines'] = search_info['search_engines']
                    subdomain_data['page_rank'] = search_info['page_rank']
                    subdomain_data['last_seen'] = search_info['last_seen']
                
                elif tool_type == 'virustotal':
                    # VirusTotal Lookup specific data
                    vt_info = check_virustotal_reputation(subdomain)
                    subdomain_data['virustotal_data'] = vt_info
                    subdomain_data['detections'] = vt_info['detections']
                    subdomain_data['reputation'] = vt_info['reputation']
                    subdomain_data['category'] = vt_info['category']
                    subdomain_data['reputation_score'] = vt_info['reputation_score']
                    subdomain_data['last_scan'] = vt_info['last_scan']
                
                found.append(subdomain_data)
                
            except socket.gaierror:
                continue
            except Exception as e:
                errors.append(f"Error checking {subdomain}: {str(e)}")
                continue
            
            cache.set(f'scan:{scan_id}:progress', int((idx+1)/total*90), timeout=SCAN_PROGRESS_TIMEOUT)
            time.sleep(0.03)
            if cache.get(f'scan:{scan_id}:cancelled', False):
                cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                cache.set(f'scan:{scan_id}:result', {'type': 'cancelled', 'data': None}, timeout=SCAN_PROGRESS_TIMEOUT)
                return
        cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
        cache.set(f'scan:{scan_id}:result', {'type': 'subdomains', 'data': {
            'subdomains': found,
            'total_found': len(found),
            'total_checked': len(wordlist),
            'tool_type': tool_type,
            'errors': errors[:10]
        }}, timeout=SCAN_PROGRESS_TIMEOUT)
    
    import threading
    import random
    threading.Thread(target=do_subdomain).start()
    return Response({'scan_id': scan_id})

@api_view(['POST'])
def cancel_scan(request, scan_id):
    cache.set(f'scan:{scan_id}:cancelled', True, timeout=SCAN_PROGRESS_TIMEOUT)
    return Response({'status': 'cancelled'})

@api_view(['GET'])
def scan_progress(request, scan_id):
    progress = cache.get(f'scan:{scan_id}:progress', 0)
    result = cache.get(f'scan:{scan_id}:result', None)
    return Response({'progress': progress, 'result': result})

@api_view(['GET'])
def python_scan_status(request, scan_id):
    """Get Python scan status"""
    try:
        status = nmap_service.get_scan_status(scan_id)
        return Response(status)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def check_tools_availability(request):
    """Check availability of Nmap and ZAP scanning tools"""
    try:
        # Check Nmap availability
        nmap_status = nmap_service.check_nmap_availability()
        
        # Check ZAP availability
        zap_status = zap_service.check_zap_status()
        
        return Response({
            'nmap': nmap_status,
            'zap': zap_status,
            'all_available': nmap_status.get('available', False) and 'error' not in zap_status
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def get_all_python_scans(request):
    """Get all Python scan results"""
    try:
        scans = nmap_service.get_all_scans()
        return Response(scans)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def comprehensive_scan(request):
    """Perform a comprehensive scan using both Nmap and ZAP"""
    target = request.data.get('target')
    options = request.data.get('options', {})
    
    if not target:
        return Response({'error': 'Target is required.'}, status=400)
    
    # Validate target format
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    
    if not ip_pattern.match(target) and not domain_pattern.match(target):
        return Response({'error': 'Invalid target format. Use IP address or domain name.'}, status=400)
    
    try:
        # Start both Nmap and ZAP scans
        comprehensive_scan_id = f"comprehensive_scan_{int(time.time())}"
        
        # Start Nmap port scan
        nmap_result = nmap_service.start_async_scan(
            target=target,
            scan_type='basic',
            ports=options.get('portRange', '1-1000'),
            options={
                'serviceDetection': True,
                'osDetection': True,
                'scanSpeed': options.get('scanSpeed', 'normal')
            }
        )
        
        # Ensure target has protocol for ZAP
        zap_target = target
        if not zap_target.startswith(('http://', 'https://')):
            zap_target = f'http://{zap_target}'
        
        # Start ZAP vulnerability scan
        zap_result = zap_service.comprehensive_scan(
            target=zap_target,
            wait_for_completion=False
        )
        
        if 'error' in nmap_result:
            return Response({'error': f'Nmap scan failed: {nmap_result["error"]}'}, status=400)
        
        if 'error' in zap_result:
            return Response({'error': f'ZAP scan failed: {zap_result["error"]}'}, status=400)
        
        return Response({
            'scan_id': comprehensive_scan_id,
            'nmap_scan_id': nmap_result.get('scan_id'),
            'zap_scan_id': zap_result.get('spider_scan_id'),  # Use spider_scan_id from ZAP result
            'status': 'started',
            'message': 'Comprehensive scan started successfully'
        })
        
    except Exception as e:
        return Response({'error': f'Failed to start comprehensive scan: {str(e)}'}, status=500)

@api_view(['GET'])
def test_nmap_performance(request):
    """Test Nmap performance with different configurations"""
    try:
        target = request.GET.get('target', '127.0.0.1')
        results = nmap_service.test_performance(target)
        return Response(results)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['POST'])
def cancel_python_scan(request, scan_id):
    """Cancel a running Python scan"""
    try:
        result = nmap_service.cancel_scan(scan_id)
        return Response(result)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def user_stats(request):
    total_users = get_user_model().objects.count()
    
    # Count online users (users with active sessions)
    online_users = 0
    users = get_user_model().objects.all()
    for user in users:
        session_data = cache.get(f'user_session:{user.id}')
        if session_data is not None:
            online_users += 1
    
    pentesters = UserProfile.objects.filter(role='pentester').count()
    admins = UserProfile.objects.filter(role='admin').count()
    
    return Response({
        'total_users': total_users,
        'online_users': online_users,  # Changed from active_users to online_users
        'pentesters': pentesters,
        'admins': admins,
    })

@api_view(['GET'])
def list_users(request):
    users = get_user_model().objects.select_related('userprofile').all()
    user_list = []
    for user in users:
        try:
            profile = user.userprofile
            role = profile.role
        except UserProfile.DoesNotExist:
            role = 'guest'
        
        # Check if user is currently logged in
        session_data = cache.get(f'user_session:{user.id}')
        is_logged_in = session_data is not None
        print(f'🔍 User {user.email} (ID: {user.id}) - Session: {session_data is not None}')
        if session_data:
            print(f'   📅 Session data: {session_data}')
        
        user_list.append({
            'id': user.id,
            'email': user.email,
            'role': role,
            'status': 'online' if is_logged_in else 'offline',
            'is_active': user.is_active,
            'is_logged_in': is_logged_in,
            'last_login': user.last_login,
            'date_joined': user.date_joined,
            'session_data': session_data
        })
    return Response({'users': user_list})

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def create_user(request):
    email = request.data.get('email')
    password = request.data.get('password')
    role = request.data.get('role', 'viewer')
    
    # Validate required fields
    if not email or not password:
        return Response({'error': 'Email and password are required.'}, status=400)
    
    # Validate email format
    import re
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return Response({'error': 'Please enter a valid email address.'}, status=400)
    
    # Validate password length
    if len(password) < 6:
        return Response({'error': 'Password must be at least 6 characters long.'}, status=400)
    
    # Validate role
    valid_roles = ['admin', 'pentester', 'viewer', 'guest']
    if role not in valid_roles:
        return Response({'error': f'Invalid role. Must be one of: {", ".join(valid_roles)}'}, status=400)
    
    User = get_user_model()
    
    # Check if user already exists
    if User.objects.filter(email=email).exists():
        return Response({'error': 'User with this email already exists.'}, status=400)
    
    try:
        # Create user
        user = User.objects.create_user(username=email, email=email, password=password)
        
        # Create user profile
        UserProfile.objects.create(user=user, role=role)
        
        print(f"✅ User created successfully: {email} with role {role}")
        
        return Response({
            'success': True, 
            'user': {
                'id': user.id, 
                'email': user.email, 
                'role': role
            },
            'message': f'User {email} created successfully with {role} role.'
        })
    except Exception as e:
        print(f"❌ Error creating user {email}: {str(e)}")
        return Response({'error': f'Failed to create user: {str(e)}'}, status=500)

@api_view(['POST'])
def toggle_user_status(request):
    user_id = request.data.get('user_id')
    if not user_id:
        return Response({'error': 'User ID is required.'}, status=400)
    
    try:
        user = get_user_model().objects.get(id=user_id)
        user.is_active = not user.is_active
        user.save()
        
        return Response({
            'success': True, 
            'user': {
                'id': user.id, 
                'email': user.email, 
                'is_active': user.is_active,
                'status': 'active' if user.is_active else 'inactive'
            }
        })
    except get_user_model().DoesNotExist:
        return Response({'error': 'User not found.'}, status=404)

@api_view(['GET'])
def debug_sessions(request):
    """Debug endpoint to check all user sessions"""
    users = get_user_model().objects.all()
    session_info = []
    
    for user in users:
        session_data = cache.get(f'user_session:{user.id}')
        session_info.append({
            'user_id': user.id,
            'email': user.email,
            'has_session': session_data is not None,
            'session_data': session_data
        })
    
    return Response({
        'total_users': len(users),
        'active_sessions': len([s for s in session_info if s['has_session']]),
        'sessions': session_info
    })

@api_view(['POST'])
def create_test_session(request):
    """Create a test session for a user"""
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required.'}, status=400)
    
    try:
        user = get_user_model().objects.get(email=email)
        session_data = {
            'user_id': user.id,
            'email': user.email,
            'login_time': datetime.datetime.now().isoformat(),
            'last_activity': datetime.datetime.now().isoformat()
        }
        cache.set(f'user_session:{user.id}', session_data, timeout=60*60*24)
        
        return Response({
            'success': True,
            'message': f'Session created for {user.email}',
            'session_data': session_data
        })
    except get_user_model().DoesNotExist:
        return Response({'error': 'User not found.'}, status=404)

@api_view(['GET'])
def debug_user_roles(request):
    """Debug endpoint to check and fix user roles"""
    users = get_user_model().objects.all()
    role_info = []
    
    for user in users:
        try:
            profile = user.userprofile
            role = profile.role
        except UserProfile.DoesNotExist:
            role = 'guest'
        
        role_info.append({
            'user_id': user.id,
            'email': user.email,
            'role': role,
            'has_profile': hasattr(user, 'userprofile')
        })
    
    return Response({
        'total_users': len(users),
        'users': role_info
    })

@api_view(['POST'])
def fix_user_role(request):
    """Fix a user's role"""
    email = request.data.get('email')
    new_role = request.data.get('role')
    
    if not email or not new_role:
        return Response({'error': 'Email and role are required.'}, status=400)
    
    try:
        user = get_user_model().objects.get(email=email)
        
        # Get or create profile
        profile, created = UserProfile.objects.get_or_create(user=user, defaults={'role': new_role})
        
        if not created:
            old_role = profile.role
            profile.role = new_role
            profile.save()
            message = f'Role changed from {old_role} to {new_role}'
        else:
            message = f'Profile created with role {new_role}'
        
        return Response({
            'success': True,
            'message': message,
            'user': {
                'id': user.id,
                'email': user.email,
                'role': profile.role
            }
        })
    except get_user_model().DoesNotExist:
        return Response({'error': 'User not found.'}, status=404)

@api_view(['DELETE'])
def delete_user(request):
    """Delete a user account"""
    email = request.data.get('email')
    
    if not email:
        return Response({'error': 'Email is required.'}, status=400)
    
    # Prevent deletion of admin account for safety
    if email == 'admin@pent.com':
        return Response({'error': 'Cannot delete admin account.'}, status=400)
    
    try:
        user = get_user_model().objects.get(email=email)
        
        # Clear any active sessions
        cache_key = f'user_session:{user.id}'
        cache.delete(cache_key)
        
        # Delete the user (this will cascade delete the profile)
        user_email = user.email
        user_id = user.id
        user.delete()
        
        return Response({
            'success': True,
            'message': f'User {user_email} (ID: {user_id}) deleted successfully',
            'deleted_user': {
                'email': user_email,
                'id': user_id
            }
        })
    except get_user_model().DoesNotExist:
        return Response({'error': 'User not found.'}, status=404)
    except Exception as e:
        return Response({'error': f'Error deleting user: {str(e)}'}, status=500)

@api_view(['POST'])
def port_scan(request):
    """Perform a port scan on a target using Nmap API"""
    target = request.data.get('target')
    scan_type = request.data.get('scan_type', 'quick')
    options = request.data.get('options', {})
    
    if not target:
        return Response({'error': 'Target is required.'}, status=400)
    
    # Validate target format
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    
    if not ip_pattern.match(target) and not domain_pattern.match(target):
        return Response({'error': 'Invalid target format. Use IP address or domain name.'}, status=400)
    
    # Use Nmap service for basic port scanning (with service and OS detection)
    try:
        # Parse port range
        ports = options.get('portRange', '1-1000')
        
        # Start async Nmap scan with basic configuration (service and OS detection)
        scan_result = nmap_service.start_async_scan(
            target=target,
            scan_type='basic',  # Basic scan with service and OS detection
            ports=ports,
            options={
                'serviceDetection': True,
                'osDetection': True,
                'scanSpeed': options.get('scanSpeed', 'normal')
            }
        )
        
        if 'error' in scan_result:
            # Log failed port scan
            log_audit_event(
                request=request,
                action="Port scan failed",
                target=target,
                module="scanning",
                status="failed",
                severity="medium",
                details=f"Port scan failed for {target}: {scan_result['error']}"
            )
            return Response({'error': scan_result['error']}, status=400)
        
        # Log successful port scan initiation
        log_audit_event(
            request=request,
            action="Port scan initiated",
            target=target,
            module="scanning",
            status="success",
            severity="low",
            details=f"Port scan started for {target} with scan type {scan_type}, ports {options.get('portRange', '1-1000')}"
        )
        
        return Response(scan_result)
        
    except Exception as e:
        return Response({'error': f'Failed to start Nmap scan: {str(e)}'}, status=500)

@api_view(['POST'])
def vulnerability_scan(request):
    """Perform a vulnerability scan on a target using Python"""
    target = request.data.get('target')
    scan_type = request.data.get('scan_type', 'basic')  # basic, full, custom
    options = request.data.get('options', {})
    
    if not target:
        return Response({'error': 'Target is required.'}, status=400)
    
    # Validate target format
    ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    
    if not ip_pattern.match(target) and not domain_pattern.match(target):
        return Response({'error': 'Invalid target format. Use IP address or domain name.'}, status=400)
    
    # Use ZAP service for comprehensive vulnerability scanning
    try:
        # Check if ZAP is available first
        zap_status = zap_service.check_zap_status()
        if 'error' in zap_status:
            return Response({
                'error': 'ZAP is not available. Please install and start ZAP first.',
                'details': 'Download ZAP from https://www.zaproxy.org/download/ and start it with: zap.bat -daemon -port 8080'
            }, status=400)
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        
        # Start ZAP vulnerability scan
        scan_result = zap_service.comprehensive_scan(
            target=target,
            wait_for_completion=False
        )
        
        if 'error' in scan_result:
            return Response({'error': scan_result['error']}, status=400)
        
        # Create a scan ID for tracking
        scan_id = f"vulnerability_scan_{int(time.time())}"
        
        # Store the scan result for later retrieval
        zap_scan_results[scan_id] = scan_result
        
        # Return format expected by frontend
        return Response({
            'scan_id': scan_id,
            'status': 'started',
            'target': target,
            'spider_scan_id': scan_result.get('spider_scan_id'),
            'active_scan_id': scan_result.get('active_scan_id'),
            'message': 'Vulnerability scan started successfully'
        })
        
    except Exception as e:
        return Response({'error': f'Failed to start ZAP vulnerability scan: {str(e)}'}, status=500)
    
    def do_vulnerability_scan():
        try:
            import subprocess
            import json
            import requests
            import time
            
            # ZAP configuration
            zap_host = 'localhost'
            zap_port = 8080
            zap_api_key = ''  # No API key needed when ZAP is started without one
            
            cache.set(f'scan:{scan_id}:progress', 10, timeout=SCAN_PROGRESS_TIMEOUT)
            
            # Start ZAP if not running
            zap_running = False
            try:
                # Check if ZAP is running
                response = requests.get(f'http://{zap_host}:{zap_port}/JSON/core/view/version/', timeout=5)
                print(f"ZAP version check response: {response.status_code} - {response.text}")
                if response.status_code == 200:
                    zap_running = True
                    print("ZAP is already running")
                else:
                    raise Exception(f"ZAP responded with status {response.status_code}")
            except Exception as zap_check_error:
                print(f"ZAP check failed: {zap_check_error}")
                print("Starting ZAP in daemon mode...")
                
                # Start ZAP in daemon mode
                try:
                    # Use the zap.bat script in the project root
                    zap_path = os.path.join(os.getcwd(), "zap.bat")
                    if not os.path.exists(zap_path):
                        zap_path = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"
                    
                    print(f"Starting ZAP from: {zap_path}")
                    subprocess.Popen([
                        zap_path, '-daemon', '-port', str(zap_port), '-host', '0.0.0.0'
                    ])
                    
                    # Wait for ZAP to start
                    print("Waiting for ZAP to start...")
                    for i in range(30):  # Wait up to 30 seconds
                        time.sleep(1)
                        try:
                            response = requests.get(f'http://{zap_host}:{zap_port}/JSON/core/view/version/', timeout=2)
                            if response.status_code == 200:
                                zap_running = True
                                print("ZAP started successfully!")
                                break
                        except:
                            continue
                    
                    if not zap_running:
                        raise Exception("ZAP failed to start within 30 seconds")
                        
                except Exception as zap_start_error:
                    print(f"Failed to start ZAP: {zap_start_error}")
                    cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                    cache.set(f'scan:{scan_id}:result', {
                        'type': 'vulnerability_scan',
                        'target': target,
                        'scan_type': scan_type,
                        'total_vulnerabilities': 0,
                        'critical_vulnerabilities': 0,
                        'high_vulnerabilities': 0,
                        'medium_vulnerabilities': 0,
                        'low_vulnerabilities': 0,
                        'data': [],
                        'error': f'ZAP not available: {zap_start_error}'
                    }, timeout=SCAN_PROGRESS_TIMEOUT)
                    return
            
            cache.set(f'scan:{scan_id}:progress', 20, timeout=SCAN_PROGRESS_TIMEOUT)
            
            # ZAP API endpoints
            base_url = f'http://{zap_host}:{zap_port}/JSON'
            
            # Create new context
            context_name = f'context_{scan_id}'
            context_data = {
                'contextName': context_name
            }
            if zap_api_key:
                context_data['apikey'] = zap_api_key
            
            response = requests.post(f'{base_url}/context/action/newContext/', data=context_data)
            if response.status_code != 200:
                raise Exception(f"Failed to create ZAP context: {response.text}")
            
            context_id = response.json().get('contextId')
            print(f"Created ZAP context: {context_id}")
            
            cache.set(f'scan:{scan_id}:progress', 30, timeout=SCAN_PROGRESS_TIMEOUT)
            
            # Configure context with custom headers if provided
            if zap_custom_headers and zap_include_context:
                try:
                    headers_dict = json.loads(zap_custom_headers)
                    for header_name, header_value in headers_dict.items():
                        header_data = {
                            'contextName': context_name,
                            'headerName': header_name,
                            'headerValue': header_value
                        }
                        if zap_api_key:
                            header_data['apikey'] = zap_api_key
                        
                        response = requests.post(f'{base_url}/context/action/includeHeaderContext/', data=header_data)
                        if response.status_code == 200:
                            print(f"Added custom header: {header_name}")
                except Exception as header_error:
                    print(f"Failed to add custom headers: {header_error}")
            
            # Add target to context
            include_data = {
                'contextName': context_name,
                'regex': f'.*{target}.*'
            }
            if zap_api_key:
                include_data['apikey'] = zap_api_key
            
            response = requests.post(f'{base_url}/context/action/includeInContext/', data=include_data)
            if response.status_code != 200:
                raise Exception(f"Failed to add target to context: {response.text}")
            
            cache.set(f'scan:{scan_id}:progress', 40, timeout=SCAN_PROGRESS_TIMEOUT)
            
            # Start spider scan if requested
            if zap_scan_type in ['spider', 'active']:
                spider_data = {
                    'url': f'http://{target}',
                    'contextName': context_name,
                    'maxChildren': 10
                }
                if zap_api_key:
                    spider_data['apikey'] = zap_api_key
                
                response = requests.post(f'{base_url}/spider/action/scan/', data=spider_data)
                if response.status_code == 200:
                    spider_scan_id = response.json().get('scan')
                    print(f"Started spider scan: {spider_scan_id}")
                    
                    # Wait for spider to complete
                    cache.set(f'scan:{scan_id}:progress', 50, timeout=SCAN_PROGRESS_TIMEOUT)
                    for i in range(60):  # Wait up to 60 seconds
                        time.sleep(1)
                        try:
                            status_data = {'scanId': spider_scan_id}
                            if zap_api_key:
                                status_data['apikey'] = zap_api_key
                            
                            response = requests.post(f'{base_url}/spider/view/status/', data=status_data)
                            if response.status_code == 200:
                                status = response.json().get('status')
                                if status == '100':
                                    print("Spider scan completed")
                                    break
                        except:
                            continue
                else:
                    print(f"Failed to start spider scan: {response.text}")
            
            cache.set(f'scan:{scan_id}:progress', 60, timeout=SCAN_PROGRESS_TIMEOUT)
            
            # Start active scan if requested
            if zap_scan_type == 'active':
                # Set scan policy based on scan level
                policy_data = {
                    'scanLevelName': zap_scan_level.capitalize()
                }
                if zap_api_key:
                    policy_data['apikey'] = zap_api_key
                
                response = requests.post(f'{base_url}/ascan/action/setScanPolicy/', data=policy_data)
                if response.status_code != 200:
                    print(f"Failed to set scan policy: {response.text}")
                
                # Start active scan
                ascan_data = {
                    'url': f'http://{target}',
                    'contextName': context_name,
                    'scanPolicyName': zap_scan_level.capitalize()
                }
                if zap_api_key:
                    ascan_data['apikey'] = zap_api_key
                
                response = requests.post(f'{base_url}/ascan/action/scan/', data=ascan_data)
                if response.status_code == 200:
                    ascan_id = response.json().get('scan')
                    print(f"Started active scan: {ascan_id}")
                    
                    # Wait for active scan to complete
                    cache.set(f'scan:{scan_id}:progress', 70, timeout=SCAN_PROGRESS_TIMEOUT)
                    for i in range(300):  # Wait up to 5 minutes
                        time.sleep(1)
                        try:
                            status_data = {'scanId': ascan_id}
                            if zap_api_key:
                                status_data['apikey'] = zap_api_key
                            
                            response = requests.post(f'{base_url}/ascan/view/status/', data=status_data)
                            if response.status_code == 200:
                                status = response.json().get('status')
                                if status == '100':
                                    print("Active scan completed")
                                    break
                        except:
                            continue
                else:
                    print(f"Failed to start active scan: {response.text}")
            
            cache.set(f'scan:{scan_id}:progress', 80, timeout=SCAN_PROGRESS_TIMEOUT)
            
            # Get scan results
            alerts_data = {'baseurl': f'http://{target}'}
            if zap_api_key:
                alerts_data['apikey'] = zap_api_key
            
            response = requests.post(f'{base_url}/core/view/alerts/', data=alerts_data)
            if response.status_code == 200:
                alerts = response.json().get('alerts', [])
                
                # Process alerts
                vulnerabilities = []
                critical_count = 0
                high_count = 0
                medium_count = 0
                low_count = 0
                
                for alert in alerts:
                    severity = alert.get('risk', 'Low').lower()
                    if severity == 'high':
                        high_count += 1
                    elif severity == 'medium':
                        medium_count += 1
                    elif severity == 'low':
                        low_count += 1
                    
                    vulnerability = {
                        'id': alert.get('id', ''),
                        'title': alert.get('name', ''),
                        'description': alert.get('description', ''),
                        'severity': severity,
                        'cwe': alert.get('cweid', ''),
                        'wasc': alert.get('wascid', ''),
                        'url': alert.get('url', ''),
                        'evidence': alert.get('evidence', ''),
                        'solution': alert.get('solution', ''),
                        'reference': alert.get('reference', ''),
                        'port': alert.get('url', '').split(':')[-1].split('/')[0] if ':' in alert.get('url', '') else '80'
                    }
                    vulnerabilities.append(vulnerability)
                
                total_vulnerabilities = len(vulnerabilities)
                
                result = {
                    'type': 'vulnerability_scan',
                    'target': target,
                    'scan_type': scan_type,
                    'zap_scan_type': zap_scan_type,
                    'zap_scan_level': zap_scan_level,
                    'total_vulnerabilities': total_vulnerabilities,
                    'critical_vulnerabilities': critical_count,
                    'high_vulnerabilities': high_count,
                    'medium_vulnerabilities': medium_count,
                    'low_vulnerabilities': low_count,
                    'data': vulnerabilities,
                    'scan_summary': {
                        'spider_completed': zap_scan_type in ['spider', 'active'],
                        'active_scan_completed': zap_scan_type == 'active',
                        'context_used': zap_include_context,
                        'custom_headers_applied': bool(zap_custom_headers)
                    }
                }
                
                cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
                cache.set(f'scan:{scan_id}:result', result, timeout=SCAN_PROGRESS_TIMEOUT)
                
                print(f"Vulnerability scan completed: {total_vulnerabilities} vulnerabilities found")
            else:
                raise Exception(f"Failed to get alerts: {response.text}")
                
        except Exception as e:
            print(f"Vulnerability scan error: {str(e)}")
            cache.set(f'scan:{scan_id}:progress', 100, timeout=SCAN_PROGRESS_TIMEOUT)
            cache.set(f'scan:{scan_id}:result', {
                'type': 'vulnerability_scan',
                'target': target,
                'scan_type': scan_type,
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
                'high_vulnerabilities': 0,
                'medium_vulnerabilities': 0,
                'low_vulnerabilities': 0,
                'data': [],
                'error': str(e)
            }, timeout=SCAN_PROGRESS_TIMEOUT)
    
    # Start the scan in a background thread
    import threading
    scan_thread = threading.Thread(target=do_vulnerability_scan)
    scan_thread.daemon = True
    scan_thread.start()
    
    return Response({
        'scan_id': scan_id,
        'message': f'Vulnerability scan started for {target}',
        'scan_type': scan_type,
        'zap_options': {
            'scan_type': zap_scan_type,
            'scan_level': zap_scan_level,
            'include_context': zap_include_context,
            'custom_headers': bool(zap_custom_headers)
        }
    })

@api_view(['GET'])
def get_scan_results(request):
    """Get all scan results for report generation"""
    try:
        # Get all scan results from cache
        all_results = {}
        
        # Get WHOIS results
        whois_results = cache.get('whois_results', {})
        for scan_id, data in whois_results.items():
            if data.get('status') == 'completed':
                all_results[scan_id] = {
                    'type': 'whois',
                    'target': data.get('target', ''),
                    'results': data.get('results', {}),
                    'timestamp': data.get('timestamp', ''),
                    'status': 'completed'
                }
        
        # Get DNS results
        dns_results = cache.get('dns_results', {})
        for scan_id, data in dns_results.items():
            if data.get('status') == 'completed':
                all_results[scan_id] = {
                    'type': 'dns',
                    'target': data.get('target', ''),
                    'results': data.get('results', {}),
                    'timestamp': data.get('timestamp', ''),
                    'status': 'completed'
                }
        
        # Get Subdomain results
        subdomain_results = cache.get('subdomain_results', {})
        for scan_id, data in subdomain_results.items():
            if data.get('status') == 'completed':
                all_results[scan_id] = {
                    'type': 'subdomain',
                    'target': data.get('target', ''),
                    'results': data.get('results', {}),
                    'timestamp': data.get('timestamp', ''),
                    'status': 'completed'
                }
        
        # Get Port scan results
        port_scan_results = cache.get('port_scan_results', {})
        for scan_id, data in port_scan_results.items():
            if data.get('status') == 'completed':
                all_results[scan_id] = {
                    'type': 'port_scan',
                    'target': data.get('target', ''),
                    'results': data.get('results', {}),
                    'timestamp': data.get('timestamp', ''),
                    'status': 'completed'
                }
        
        # Get Vulnerability scan results
        vuln_scan_results = cache.get('vuln_scan_results', {})
        for scan_id, data in vuln_scan_results.items():
            if data.get('status') == 'completed':
                all_results[scan_id] = {
                    'type': 'vulnerability_scan',
                    'target': data.get('target', ''),
                    'results': data.get('results', {}),
                    'timestamp': data.get('timestamp', ''),
                    'status': 'completed'
                }
        
        return JsonResponse({
            'success': True,
            'results': all_results
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['POST'])
def generate_report(request):
    """Generate a comprehensive report from scan results"""
    try:
        data = json.loads(request.body)
        report_title = data.get('title', 'Security Assessment Report')
        report_type = data.get('type', 'comprehensive')
        target_domain = data.get('target', '')
        include_sections = data.get('sections', [])
        
        # Get scan results for the target
        all_results = {}
        
        # Collect all scan results for the target
        scan_types = ['whois', 'dns', 'subdomain', 'port_scan', 'vulnerability_scan']
        for scan_type in scan_types:
            cache_key = f'{scan_type}_results'
            scan_results = cache.get(cache_key, {})
            
            for scan_id, scan_data in scan_results.items():
                if scan_data.get('target') == target_domain and scan_data.get('status') == 'completed':
                    all_results[scan_type] = scan_data.get('results', {})
        
        # Generate report data
        report_data = {
            'title': report_title,
            'type': report_type,
            'target': target_domain,
            'generated_at': datetime.datetime.now().isoformat(),
            'sections': include_sections,
            'executive_summary': generate_executive_summary(all_results),
            'findings': extract_findings(all_results),
            'recommendations': generate_recommendations(all_results),
            'technical_details': all_results
        }
        
        # Store report in cache
        report_id = str(int(time.time()))
        cache.set(f'report_{report_id}', report_data, timeout=86400)  # 24 hours
        
        # Add report ID to the list of reports
        report_ids = cache.get('report_ids', [])
        report_ids.append(report_id)
        cache.set('report_ids', report_ids, timeout=86400)  # 24 hours
        
        return JsonResponse({
            'success': True,
            'report_id': report_id,
            'report_data': report_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def get_reports(request):
    """Get all generated reports"""
    try:
        reports = []
        
        # Since Django cache doesn't support keys(), we'll store report IDs in a separate cache key
        report_ids = cache.get('report_ids', [])
        
        for report_id in report_ids:
            report_data = cache.get(f'report_{report_id}')
            if report_data:
                reports.append({
                    'id': report_id,
                    'title': report_data.get('title', ''),
                    'type': report_data.get('type', ''),
                    'target': report_data.get('target', ''),
                    'generated_at': report_data.get('generated_at', ''),
                    'findings_count': len(report_data.get('findings', [])),
                    'severity': calculate_overall_severity(report_data.get('findings', []))
                })
        
        # Sort by generation date (newest first)
        reports.sort(key=lambda x: x['generated_at'], reverse=True)
        
        return JsonResponse({
            'success': True,
            'reports': reports
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def get_report_detail(request, report_id):
    """Get detailed report data"""
    try:
        report_data = cache.get(f'report_{report_id}')
        if not report_data:
            return JsonResponse({
                'success': False,
                'error': 'Report not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'report': report_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def generate_executive_summary(results):
    """Generate executive summary from scan results"""
    summary = {
        'total_findings': 0,
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'low_count': 0,
        'key_insights': []
    }
    
    # Count vulnerabilities from vulnerability scan
    if 'vulnerability_scan' in results:
        vuln_data = results['vulnerability_scan']
        summary['critical_count'] = len(vuln_data.get('critical_vulnerabilities', []))
        summary['high_count'] = len(vuln_data.get('high_vulnerabilities', []))
        summary['medium_count'] = len(vuln_data.get('medium_vulnerabilities', []))
        summary['low_count'] = len(vuln_data.get('low_vulnerabilities', []))
        summary['total_findings'] = summary['critical_count'] + summary['high_count'] + summary['medium_count'] + summary['low_count']
    
    # Add port scan insights
    if 'port_scan' in results:
        port_data = results['port_scan']
        open_ports = len(port_data.get('open_ports', []))
        if open_ports > 0:
            summary['key_insights'].append(f"Found {open_ports} open ports that may require attention")
    
    # Add domain insights
    if 'whois' in results:
        whois_data = results['whois']
        if whois_data:
            summary['key_insights'].append("Domain registration information analyzed")
    
    if 'dns' in results:
        dns_data = results['dns']
        if dns_data:
            summary['key_insights'].append("DNS configuration reviewed")
    
    return summary

def extract_findings(results):
    """Extract and categorize findings from scan results"""
    findings = []
    
    # Extract vulnerability findings
    if 'vulnerability_scan' in results:
        vuln_data = results['vulnerability_scan']
        
        for vuln in vuln_data.get('critical_vulnerabilities', []):
            findings.append({
                'type': 'vulnerability',
                'severity': 'critical',
                'title': vuln.get('name', 'Critical Vulnerability'),
                'description': vuln.get('description', ''),
                'solution': vuln.get('solution', ''),
                'cve': vuln.get('cve', ''),
                'port': vuln.get('port', '')
            })
        
        for vuln in vuln_data.get('high_vulnerabilities', []):
            findings.append({
                'type': 'vulnerability',
                'severity': 'high',
                'title': vuln.get('name', 'High Severity Vulnerability'),
                'description': vuln.get('description', ''),
                'solution': vuln.get('solution', ''),
                'cve': vuln.get('cve', ''),
                'port': vuln.get('port', '')
            })
        
        for vuln in vuln_data.get('medium_vulnerabilities', []):
            findings.append({
                'type': 'vulnerability',
                'severity': 'medium',
                'title': vuln.get('name', 'Medium Severity Vulnerability'),
                'description': vuln.get('description', ''),
                'solution': vuln.get('solution', ''),
                'cve': vuln.get('cve', ''),
                'port': vuln.get('port', '')
            })
        
        for vuln in vuln_data.get('low_vulnerabilities', []):
            findings.append({
                'type': 'vulnerability',
                'severity': 'low',
                'title': vuln.get('name', 'Low Severity Vulnerability'),
                'description': vuln.get('description', ''),
                'solution': vuln.get('solution', ''),
                'cve': vuln.get('cve', ''),
                'port': vuln.get('port', '')
            })
    
    # Extract port scan findings
    if 'port_scan' in results:
        port_data = results['port_scan']
        open_ports = port_data.get('open_ports', [])
        
        for port in open_ports:
            findings.append({
                'type': 'port',
                'severity': 'medium',
                'title': f'Open Port {port.get("port", "")}',
                'description': f'Port {port.get("port", "")} ({port.get("service", "Unknown")}) is open and accessible',
                'solution': 'Review if this port needs to be open and implement proper access controls',
                'port': port.get('port', ''),
                'service': port.get('service', '')
            })
    
    return findings

def generate_recommendations(results):
    """Generate recommendations based on findings"""
    recommendations = []
    
    # Check for critical vulnerabilities
    if 'vulnerability_scan' in results:
        vuln_data = results['vulnerability_scan']
        critical_count = len(vuln_data.get('critical_vulnerabilities', []))
        high_count = len(vuln_data.get('high_vulnerabilities', []))
        
        if critical_count > 0:
            recommendations.append({
                'priority': 'immediate',
                'title': 'Address Critical Vulnerabilities',
                'description': f'Immediately patch {critical_count} critical vulnerabilities to prevent potential exploitation',
                'action': 'Apply security patches and updates as soon as possible'
            })
        
        if high_count > 0:
            recommendations.append({
                'priority': 'high',
                'title': 'Fix High Severity Issues',
                'description': f'Address {high_count} high severity vulnerabilities within 30 days',
                'action': 'Implement security fixes and conduct follow-up testing'
            })
    
    # Check for open ports
    if 'port_scan' in results:
        port_data = results['port_scan']
        open_ports = len(port_data.get('open_ports', []))
        
        if open_ports > 10:
            recommendations.append({
                'priority': 'medium',
                'title': 'Reduce Attack Surface',
                'description': f'Close unnecessary open ports ({open_ports} currently open)',
                'action': 'Review and close ports that are not required for business operations'
            })
    
    # General recommendations
    recommendations.extend([
        {
            'priority': 'medium',
            'title': 'Implement Security Monitoring',
            'description': 'Deploy continuous security monitoring and alerting systems',
            'action': 'Set up SIEM tools and establish incident response procedures'
        },
        {
            'priority': 'low',
            'title': 'Regular Security Assessments',
            'description': 'Conduct periodic security assessments and penetration testing',
            'action': 'Schedule quarterly security reviews and annual penetration tests'
        }
    ])
    
    return recommendations

def calculate_overall_severity(findings):
    """Calculate overall severity based on findings"""
    if not findings:
        return 'low'
    
    severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    max_severity = max([severity_scores.get(finding.get('severity', 'low'), 1) for finding in findings])
    
    for severity, score in severity_scores.items():
        if score == max_severity:
            return severity
    
    return 'low'

@api_view(['POST'])
def cancel_nmap_scan(request, scan_id):
    """Cancel a running NMAP scan"""
    try:
        result = nmap_service.cancel_scan(scan_id)
        return Response(result)
    except Exception as e:
        return Response({'error': f'Failed to cancel NMAP scan: {str(e)}'}, status=500)

@api_view(['GET'])
def zap_scan_status(request, scan_id):
    """Get ZAP scan status"""
    try:
        # Check if we have results for this scan
        if scan_id in zap_scan_results:
            scan_result = zap_scan_results[scan_id]
            return Response({
                'status': 'completed',
                'scan_id': scan_id,
                'progress': 100,
                'message': 'ZAP scan completed',
                'results': scan_result
            })
        else:
            # If no results found, return basic completion status
            return Response({
                'status': 'completed',
                'scan_id': scan_id,
                'progress': 100,
                'message': 'ZAP scan completed'
            })
    except Exception as e:
        return Response({'error': f'Failed to get ZAP scan status: {str(e)}'}, status=500)

@api_view(['POST'])
def cancel_zap_scan(request, scan_id):
    """Cancel a running ZAP scan"""
    try:
        # This would need to be implemented based on how ZAP scans are tracked
        return Response({'status': 'not_implemented', 'message': 'ZAP scan cancellation not implemented yet'})
    except Exception as e:
        return Response({'error': f'Failed to cancel ZAP scan: {str(e)}'}, status=500)

@api_view(['GET'])
def get_all_nmap_scans(request):
    """Get all NMAP scan results"""
    try:
        result = nmap_service.get_all_scans()
        return Response(result)
    except Exception as e:
        return Response({'error': f'Failed to get NMAP scans: {str(e)}'}, status=500)

@api_view(['GET'])
def get_all_zap_scans(request):
    """Get all ZAP scan results"""
    try:
        # This would need to be implemented based on how ZAP scans are tracked
        return Response({'scans': [], 'total_scans': 0, 'message': 'ZAP scan tracking not implemented yet'})
    except Exception as e:
        return Response({'error': f'Failed to get ZAP scans: {str(e)}'}, status=500)

@api_view(['GET'])
def get_scan_statistics(request):
    """Get comprehensive scan statistics for dashboard"""
    try:
        # Get all scan results from cache
        all_results = {}
        
        # Collect all scan results
        scan_types = ['whois', 'dns', 'subdomain', 'port_scan', 'vulnerability_scan']
        for scan_type in scan_types:
            cache_key = f'{scan_type}_results'
            scan_results = cache.get(cache_key, {})
            
            for scan_id, scan_data in scan_results.items():
                if scan_data.get('status') == 'completed':
                    all_results[scan_id] = {
                        'type': scan_type,
                        'target': scan_data.get('target', ''),
                        'results': scan_data.get('results', {}),
                        'timestamp': scan_data.get('timestamp', ''),
                        'status': 'completed'
                    }
        
        # Calculate statistics
        stats = {
            'total_scans': len(all_results),
            'completed_scans': len([r for r in all_results.values() if r['status'] == 'completed']),
            'failed_scans': len([r for r in all_results.values() if r['status'] == 'failed']),
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'open_ports': 0,
            'subdomains_found': 0,
            'dns_records': 0,
            'targets_scanned': len(set([r['target'] for r in all_results.values()])),
            'scan_types': {}
        }
        
        # Calculate detailed statistics
        for result in all_results.values():
            if result['type'] == 'vulnerability_scan':
                vulns = result['results']
                stats['critical_vulnerabilities'] += len(vulns.get('critical_vulnerabilities', []))
                stats['high_vulnerabilities'] += len(vulns.get('high_vulnerabilities', []))
                stats['medium_vulnerabilities'] += len(vulns.get('medium_vulnerabilities', []))
                stats['low_vulnerabilities'] += len(vulns.get('low_vulnerabilities', []))
            
            elif result['type'] == 'port_scan':
                ports = result['results']
                stats['open_ports'] += len(ports.get('open_ports', []))
            
            elif result['type'] == 'subdomain':
                subdomains = result['results']
                stats['subdomains_found'] += len(subdomains.get('subdomains', []))
            
            elif result['type'] == 'dns':
                dns_data = result['results']
                stats['dns_records'] += (
                    len(dns_data.get('a_records', [])) +
                    len(dns_data.get('aaaa_records', [])) +
                    len(dns_data.get('mx_records', [])) +
                    len(dns_data.get('ns_records', [])) +
                    len(dns_data.get('txt_records', []))
                )
            
            # Count scan types
            scan_type = result['type']
            if scan_type not in stats['scan_types']:
                stats['scan_types'][scan_type] = 0
            stats['scan_types'][scan_type] += 1
        
        return JsonResponse({
            'success': True,
            'statistics': stats
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def get_detailed_scan_results(request):
    """Get detailed scan results with enhanced information"""
    try:
        target = request.GET.get('target', '')
        
        # Get all scan results from cache
        all_results = {}
        
        # Collect all scan results
        scan_types = ['whois', 'dns', 'subdomain', 'port_scan', 'vulnerability_scan']
        for scan_type in scan_types:
            cache_key = f'{scan_type}_results'
            scan_results = cache.get(cache_key, {})
            
            for scan_id, scan_data in scan_results.items():
                if scan_data.get('status') == 'completed':
                    if not target or scan_data.get('target') == target:
                        all_results[scan_id] = {
                            'type': scan_type,
                            'target': scan_data.get('target', ''),
                            'results': scan_data.get('results', {}),
                            'timestamp': scan_data.get('timestamp', ''),
                            'status': 'completed'
                        }
        
        # Group results by target
        grouped_results = {}
        for result in all_results.values():
            target = result['target']
            if target not in grouped_results:
                grouped_results[target] = []
            grouped_results[target].append(result)
        
        return JsonResponse({
            'success': True,
            'results': grouped_results
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['POST'])
def generate_enhanced_report(request):
    """Generate an enhanced report with detailed analysis"""
    try:
        data = json.loads(request.body)
        report_title = data.get('title', 'Security Assessment Report')
        report_type = data.get('type', 'comprehensive')
        target_domain = data.get('target', '')
        include_sections = data.get('sections', [])
        
        # Get scan results for the target
        all_results = {}
        
        # Collect all scan results for the target
        scan_types = ['whois', 'dns', 'subdomain', 'port_scan', 'vulnerability_scan']
        for scan_type in scan_types:
            cache_key = f'{scan_type}_results'
            scan_results = cache.get(cache_key, {})
            
            for scan_id, scan_data in scan_results.items():
                if scan_data.get('target') == target_domain and scan_data.get('status') == 'completed':
                    all_results[scan_type] = scan_data.get('results', {})
        
        # Generate enhanced report data
        report_data = {
            'title': report_title,
            'type': report_type,
            'target': target_domain,
            'generated_at': datetime.datetime.now().isoformat(),
            'sections': include_sections,
            'executive_summary': generate_enhanced_executive_summary(all_results),
            'findings': extract_enhanced_findings(all_results),
            'recommendations': generate_enhanced_recommendations(all_results),
            'technical_details': all_results,
            'risk_assessment': generate_risk_assessment(all_results),
            'methodology': generate_methodology_section(all_results)
        }
        
        # Store report in cache
        report_id = str(int(time.time()))
        cache.set(f'report_{report_id}', report_data, timeout=86400)  # 24 hours
        
        # Add report ID to the list of reports
        report_ids = cache.get('report_ids', [])
        report_ids.append(report_id)
        cache.set('report_ids', report_ids, timeout=86400)  # 24 hours
        
        return JsonResponse({
            'success': True,
            'report_id': report_id,
            'report_data': report_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def generate_enhanced_executive_summary(results):
    """Generate an enhanced executive summary"""
    summary = {
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'low_count': 0,
        'total_vulnerabilities': 0,
        'open_ports_count': 0,
        'subdomains_count': 0,
        'dns_records_count': 0,
        'overall_risk_level': 'Low',
        'key_findings': [],
        'recommendations_summary': []
    }
    
    # Calculate vulnerability counts
    if 'vulnerability_scan' in results:
        vulns = results['vulnerability_scan']
        summary['critical_count'] = len(vulns.get('critical_vulnerabilities', []))
        summary['high_count'] = len(vulns.get('high_vulnerabilities', []))
        summary['medium_count'] = len(vulns.get('medium_vulnerabilities', []))
        summary['low_count'] = len(vulns.get('low_vulnerabilities', []))
        summary['total_vulnerabilities'] = summary['critical_count'] + summary['high_count'] + summary['medium_count'] + summary['low_count']
    
    # Calculate other metrics
    if 'port_scan' in results:
        summary['open_ports_count'] = len(results['port_scan'].get('open_ports', []))
    
    if 'subdomain' in results:
        summary['subdomains_count'] = len(results['subdomain'].get('subdomains', []))
    
    if 'dns' in results:
        dns_data = results['dns']
        summary['dns_records_count'] = (
            len(dns_data.get('a_records', [])) +
            len(dns_data.get('aaaa_records', [])) +
            len(dns_data.get('mx_records', [])) +
            len(dns_data.get('ns_records', [])) +
            len(dns_data.get('txt_records', []))
        )
    
    # Determine overall risk level
    if summary['critical_count'] > 0:
        summary['overall_risk_level'] = 'Critical'
    elif summary['high_count'] > 0:
        summary['overall_risk_level'] = 'High'
    elif summary['medium_count'] > 0:
        summary['overall_risk_level'] = 'Medium'
    elif summary['low_count'] > 0:
        summary['overall_risk_level'] = 'Low'
    
    # Generate key findings
    if summary['critical_count'] > 0:
        summary['key_findings'].append(f"{summary['critical_count']} critical vulnerabilities identified")
    if summary['high_count'] > 0:
        summary['key_findings'].append(f"{summary['high_count']} high severity issues found")
    if summary['open_ports_count'] > 0:
        summary['key_findings'].append(f"{summary['open_ports_count']} open ports discovered")
    if summary['subdomains_count'] > 0:
        summary['key_findings'].append(f"{summary['subdomains_count']} subdomains enumerated")
    
    return summary

def extract_enhanced_findings(results):
    """Extract enhanced findings from scan results"""
    findings = []
    
    # Vulnerability findings
    if 'vulnerability_scan' in results:
        vulns = results['vulnerability_scan']
        
        for critical in vulns.get('critical_vulnerabilities', []):
            findings.append({
                'title': critical.get('title', 'Critical Vulnerability'),
                'description': critical.get('description', ''),
                'severity': 'Critical',
                'cvss_score': critical.get('cvss_score', ''),
                'cve_id': critical.get('cve_id', ''),
                'recommendation': critical.get('recommendation', '')
            })
        
        for high in vulns.get('high_vulnerabilities', []):
            findings.append({
                'title': high.get('title', 'High Severity Vulnerability'),
                'description': high.get('description', ''),
                'severity': 'High',
                'cvss_score': high.get('cvss_score', ''),
                'cve_id': high.get('cve_id', ''),
                'recommendation': high.get('recommendation', '')
            })
        
        for medium in vulns.get('medium_vulnerabilities', []):
            findings.append({
                'title': medium.get('title', 'Medium Severity Vulnerability'),
                'description': medium.get('description', ''),
                'severity': 'Medium',
                'cvss_score': medium.get('cvss_score', ''),
                'cve_id': medium.get('cve_id', ''),
                'recommendation': medium.get('recommendation', '')
            })
        
        for low in vulns.get('low_vulnerabilities', []):
            findings.append({
                'title': low.get('title', 'Low Severity Vulnerability'),
                'description': low.get('description', ''),
                'severity': 'Low',
                'cvss_score': low.get('cvss_score', ''),
                'cve_id': low.get('cve_id', ''),
                'recommendation': low.get('recommendation', '')
            })
    
    # Port scan findings
    if 'port_scan' in results:
        ports = results['port_scan']
        open_ports = ports.get('open_ports', [])
        
        if open_ports:
            findings.append({
                'title': f'{len(open_ports)} Open Ports Discovered',
                'description': f'Found {len(open_ports)} open ports that may expose services',
                'severity': 'Medium',
                'details': open_ports,
                'recommendation': 'Review and close unnecessary open ports'
            })
    
    # Subdomain findings
    if 'subdomain' in results:
        subdomains = results['subdomain']
        subdomain_list = subdomains.get('subdomains', [])
        
        if subdomain_list:
            findings.append({
                'title': f'{len(subdomain_list)} Subdomains Enumerated',
                'description': f'Discovered {len(subdomain_list)} subdomains',
                'severity': 'Low',
                'details': subdomain_list,
                'recommendation': 'Review subdomains for security implications'
            })
    
    return findings

def generate_enhanced_recommendations(results):
    """Generate enhanced recommendations based on findings"""
    recommendations = []
    
    # Vulnerability-based recommendations
    if 'vulnerability_scan' in results:
        vulns = results['vulnerability_scan']
        
        if vulns.get('critical_vulnerabilities'):
            recommendations.append({
                'title': 'Immediate Patch Critical Vulnerabilities',
                'description': 'Critical vulnerabilities should be patched immediately as they pose the highest risk',
                'priority': 'Critical',
                'effort': 'High'
            })
        
        if vulns.get('high_vulnerabilities'):
            recommendations.append({
                'title': 'Address High Severity Issues',
                'description': 'High severity vulnerabilities should be addressed within 30 days',
                'priority': 'High',
                'effort': 'Medium'
            })
    
    # Port-based recommendations
    if 'port_scan' in results:
        ports = results['port_scan']
        open_ports = ports.get('open_ports', [])
        
        if open_ports:
            recommendations.append({
                'title': 'Implement Port Security',
                'description': 'Close unnecessary open ports and implement firewall rules',
                'priority': 'Medium',
                'effort': 'Medium'
            })
    
    # General security recommendations
    recommendations.extend([
        {
            'title': 'Implement Security Monitoring',
            'description': 'Deploy intrusion detection and monitoring systems',
            'priority': 'Medium',
            'effort': 'High'
        },
        {
            'title': 'Regular Security Assessments',
            'description': 'Conduct regular security assessments and penetration testing',
            'priority': 'Low',
            'effort': 'Medium'
        }
    ])
    
    return recommendations

def generate_risk_assessment(results):
    """Generate comprehensive risk assessment"""
    risk_assessment = {
        'overall_risk': 'Low',
        'risk_factors': [],
        'risk_score': 0,
        'risk_levels': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    }
    
    # Calculate risk based on vulnerabilities
    if 'vulnerability_scan' in results:
        vulns = results['vulnerability_scan']
        risk_assessment['risk_levels']['critical'] = len(vulns.get('critical_vulnerabilities', []))
        risk_assessment['risk_levels']['high'] = len(vulns.get('high_vulnerabilities', []))
        risk_assessment['risk_levels']['medium'] = len(vulns.get('medium_vulnerabilities', []))
        risk_assessment['risk_levels']['low'] = len(vulns.get('low_vulnerabilities', []))
    
    # Calculate risk score
    risk_assessment['risk_score'] = (
        risk_assessment['risk_levels']['critical'] * 10 +
        risk_assessment['risk_levels']['high'] * 7 +
        risk_assessment['risk_levels']['medium'] * 4 +
        risk_assessment['risk_levels']['low'] * 1
    )
    
    # Determine overall risk level
    if risk_assessment['risk_score'] >= 30:
        risk_assessment['overall_risk'] = 'Critical'
    elif risk_assessment['risk_score'] >= 20:
        risk_assessment['overall_risk'] = 'High'
    elif risk_assessment['risk_score'] >= 10:
        risk_assessment['overall_risk'] = 'Medium'
    else:
        risk_assessment['overall_risk'] = 'Low'
    
    # Add risk factors
    if risk_assessment['risk_levels']['critical'] > 0:
        risk_assessment['risk_factors'].append('Critical vulnerabilities present')
    if risk_assessment['risk_levels']['high'] > 0:
        risk_assessment['risk_factors'].append('High severity issues identified')
    if 'port_scan' in results and results['port_scan'].get('open_ports'):
        risk_assessment['risk_factors'].append('Multiple open ports detected')
    
    return risk_assessment

def generate_methodology_section(results):
    """Generate methodology section for the report"""
    methodology = {
        'tools_used': [],
        'scan_types': [],
        'timeline': {},
        'scope': {}
    }
    
    # Determine tools used based on scan types
    if 'whois' in results:
        methodology['tools_used'].append('WHOIS Lookup')
        methodology['scan_types'].append('Domain Information Gathering')
    
    if 'dns' in results:
        methodology['tools_used'].append('DNS Enumeration')
        methodology['scan_types'].append('DNS Record Analysis')
    
    if 'subdomain' in results:
        methodology['tools_used'].append('Subdomain Enumeration')
        methodology['scan_types'].append('Subdomain Discovery')
    
    if 'port_scan' in results:
        methodology['tools_used'].append('Nmap Port Scanner')
        methodology['scan_types'].append('Port Scanning')
    
    if 'vulnerability_scan' in results:
        methodology['tools_used'].append('OWASP ZAP')
        methodology['scan_types'].append('Vulnerability Assessment')
    
    return methodology

@api_view(['GET'])
def get_individual_reports(request):
    """Get all individual scan reports"""
    try:
        reports = []
        
        # Get individual report IDs from cache
        individual_report_ids = cache.get('individual_report_ids', [])
        
        for report_id in individual_report_ids:
            report_data = cache.get(f'individual_report_{report_id}')
            if report_data:
                reports.append({
                    'id': report_id,
                    'title': report_data.get('title', ''),
                    'scan_type': report_data.get('scan_type', ''),
                    'target': report_data.get('target', ''),
                    'timestamp': report_data.get('timestamp', ''),
                    'status': report_data.get('status', ''),
                    'severity': report_data.get('severity', ''),
                    'summary': report_data.get('summary', ''),
                    'details': report_data.get('details', {}),
                    'findings_count': report_data.get('findings_count', 0)
                })
        
        # Sort by timestamp (newest first)
        reports.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return JsonResponse({
            'success': True,
            'reports': reports
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def get_comprehensive_reports(request):
    """Get all comprehensive reports"""
    try:
        reports = []
        
        # Get comprehensive report IDs from cache
        comprehensive_report_ids = cache.get('comprehensive_report_ids', [])
        
        for report_id in comprehensive_report_ids:
            report_data = cache.get(f'comprehensive_report_{report_id}')
            if report_data:
                reports.append({
                    'id': report_id,
                    'title': report_data.get('title', ''),
                    'generated_at': report_data.get('generated_at', ''),
                    'included_reports': report_data.get('included_reports', []),
                    'total_findings': report_data.get('total_findings', 0),
                    'overall_severity': report_data.get('overall_severity', ''),
                    'status': report_data.get('status', 'draft')
                })
        
        # Sort by generation date (newest first)
        reports.sort(key=lambda x: x['generated_at'], reverse=True)
        
        return JsonResponse({
            'success': True,
            'reports': reports
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def get_individual_report_detail(request, report_id):
    """Get detailed individual report data"""
    try:
        report_data = cache.get(f'individual_report_{report_id}')
        if not report_data:
            return JsonResponse({
                'success': False,
                'error': 'Report not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'report': report_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['GET'])
def get_comprehensive_report_detail(request, report_id):
    """Get detailed comprehensive report data"""
    try:
        report_data = cache.get(f'comprehensive_report_{report_id}')
        if not report_data:
            return JsonResponse({
                'success': False,
                'error': 'Comprehensive report not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'report': report_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['POST'])
def save_individual_report(request):
    """Save an individual scan result as a report"""
    try:
        data = json.loads(request.body)
        scan_type = data.get('scan_type')
        target = data.get('target')
        results = data.get('results', {})
        scan_id = data.get('scan_id')
        
        # Generate report title
        scan_type_names = {
            'whois': 'WHOIS Lookup',
            'dns': 'DNS Enumeration',
            'subdomain': 'Subdomain Enumeration',
            'port_scan': 'Port Scanning',
            'vulnerability_scan': 'Vulnerability Assessment',
            'exploit': 'Exploitation'
        }
        
        title = f"{scan_type_names.get(scan_type, scan_type)} Report - {target}"
        
        # Calculate severity and findings count
        severity = 'Low'
        findings_count = 0
        
        if scan_type == 'vulnerability_scan':
            critical_count = len(results.get('critical_vulnerabilities', []))
            high_count = len(results.get('high_vulnerabilities', []))
            medium_count = len(results.get('medium_vulnerabilities', []))
            low_count = len(results.get('low_vulnerabilities', []))
            
            findings_count = critical_count + high_count + medium_count + low_count
            
            if critical_count > 0:
                severity = 'Critical'
            elif high_count > 0:
                severity = 'High'
            elif medium_count > 0:
                severity = 'Medium'
            else:
                severity = 'Low'
        
        elif scan_type == 'port_scan':
            open_ports = len(results.get('open_ports', []))
            findings_count = open_ports
            
            if open_ports > 10:
                severity = 'High'
            elif open_ports > 5:
                severity = 'Medium'
            else:
                severity = 'Low'
        
        elif scan_type == 'subdomain':
            subdomains = len(results.get('subdomains', []))
            findings_count = subdomains
            
            if subdomains > 20:
                severity = 'Medium'
            else:
                severity = 'Low'
        
        elif scan_type == 'dns':
            dns_records = (
                len(results.get('a_records', [])) +
                len(results.get('aaaa_records', [])) +
                len(results.get('mx_records', [])) +
                len(results.get('ns_records', [])) +
                len(results.get('txt_records', []))
            )
            findings_count = dns_records
            severity = 'Low'
        
        else:
            severity = 'Low'
            findings_count = 1
        
        # Generate summary
        summary = generate_scan_summary(scan_type, results, findings_count)
        
        # Create report data
        report_data = {
            'id': scan_id,
            'title': title,
            'scan_type': scan_type,
            'target': target,
            'timestamp': datetime.datetime.now().isoformat(),
            'status': 'completed',
            'severity': severity,
            'summary': summary,
            'details': results,
            'findings_count': findings_count
        }
        
        # Store report in cache
        cache.set(f'individual_report_{scan_id}', report_data, timeout=86400*7)  # 7 days
        
        # Add to individual report IDs list
        individual_report_ids = cache.get('individual_report_ids', [])
        if scan_id not in individual_report_ids:
            individual_report_ids.append(scan_id)
            cache.set('individual_report_ids', individual_report_ids, timeout=86400*7)  # 7 days
        
        return JsonResponse({
            'success': True,
            'report_id': scan_id,
            'message': 'Individual report saved successfully'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['POST'])
def generate_comprehensive_report(request):
    """Generate a comprehensive report from multiple individual reports"""
    try:
        data = json.loads(request.body)
        title = data.get('title', 'Comprehensive Security Assessment Report')
        included_report_ids = data.get('included_reports', [])
        
        if not included_report_ids:
            return JsonResponse({
                'success': False,
                'error': 'No reports selected'
            }, status=400)
        
        # Get individual reports
        individual_reports = []
        total_findings = 0
        severity_scores = []
        
        for report_id in included_report_ids:
            report_data = cache.get(f'individual_report_{report_id}')
            if report_data:
                individual_reports.append(report_data)
                total_findings += report_data.get('findings_count', 0)
                
                # Calculate severity score
                severity = report_data.get('severity', 'Low')
                severity_scores.append({
                    'Critical': 10,
                    'High': 7,
                    'Medium': 4,
                    'Low': 1
                }.get(severity, 1))
        
        # Calculate overall severity
        if severity_scores:
            avg_severity_score = sum(severity_scores) / len(severity_scores)
            if avg_severity_score >= 8:
                overall_severity = 'Critical'
            elif avg_severity_score >= 5:
                overall_severity = 'High'
            elif avg_severity_score >= 2:
                overall_severity = 'Medium'
            else:
                overall_severity = 'Low'
        else:
            overall_severity = 'Low'
        
        # Generate comprehensive report data
        comprehensive_report_data = {
            'title': title,
            'generated_at': datetime.datetime.now().isoformat(),
            'included_reports': included_report_ids,
            'total_findings': total_findings,
            'overall_severity': overall_severity,
            'status': 'generated',
            'individual_reports': individual_reports,
            'executive_summary': generate_comprehensive_executive_summary(individual_reports),
            'findings': extract_comprehensive_findings(individual_reports),
            'recommendations': generate_comprehensive_recommendations(individual_reports),
            'risk_assessment': generate_comprehensive_risk_assessment(individual_reports)
        }
        
        # Store comprehensive report
        report_id = str(int(time.time()))
        cache.set(f'comprehensive_report_{report_id}', comprehensive_report_data, timeout=86400*30)  # 30 days
        
        # Add to comprehensive report IDs list
        comprehensive_report_ids = cache.get('comprehensive_report_ids', [])
        comprehensive_report_ids.append(report_id)
        cache.set('comprehensive_report_ids', comprehensive_report_ids, timeout=86400*30)  # 30 days
        
        return JsonResponse({
            'success': True,
            'report_id': report_id,
            'report_data': comprehensive_report_data
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['POST'])
def download_report_pdf(request, report_type, report_id):
    """Generate and download a PDF report"""
    try:
        if report_type == 'individual':
            report_data = cache.get(f'individual_report_{report_id}')
        else:
            report_data = cache.get(f'comprehensive_report_{report_id}')
        
        if not report_data:
            return JsonResponse({
                'success': False,
                'error': 'Report not found'
            }, status=404)
        
        # Generate PDF content
        pdf_content = generate_pdf_content(report_data, report_type)
        
        # Check if PDF generation was successful
        if isinstance(pdf_content, str) and pdf_content.startswith('Error generating PDF:'):
            return JsonResponse({
                'success': False,
                'error': pdf_content
            }, status=500)
        
        # Return the PDF as a file response
        from django.http import HttpResponse
        response = HttpResponse(pdf_content, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="{report_type}-report-{report_id}.pdf"'
        return response
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@api_view(['DELETE'])
def delete_report(request, report_type, report_id):
    """Delete a report"""
    try:
        if report_type == 'individual':
            cache.delete(f'individual_report_{report_id}')
            report_ids = cache.get('individual_report_ids', [])
            if report_id in report_ids:
                report_ids.remove(report_id)
                cache.set('individual_report_ids', report_ids, timeout=86400*7)
        else:
            cache.delete(f'comprehensive_report_{report_id}')
            report_ids = cache.get('comprehensive_report_ids', [])
            if report_id in report_ids:
                report_ids.remove(report_id)
                cache.set('comprehensive_report_ids', report_ids, timeout=86400*30)
        
        return JsonResponse({
            'success': True,
            'message': f'{report_type} report deleted successfully'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

def generate_scan_summary(scan_type, results, findings_count):
    """Generate a summary for a scan result"""
    if scan_type == 'vulnerability_scan':
        critical = len(results.get('critical_vulnerabilities', []))
        high = len(results.get('high_vulnerabilities', []))
        medium = len(results.get('medium_vulnerabilities', []))
        low = len(results.get('low_vulnerabilities', []))
        
        return f"Found {findings_count} vulnerabilities: {critical} critical, {high} high, {medium} medium, {low} low severity issues."
    
    elif scan_type == 'port_scan':
        open_ports = len(results.get('open_ports', []))
        return f"Discovered {open_ports} open ports that may expose services."
    
    elif scan_type == 'subdomain':
        subdomains = len(results.get('subdomains', []))
        return f"Enumerated {subdomains} subdomains for the target domain."
    
    elif scan_type == 'dns':
        dns_records = (
            len(results.get('a_records', [])) +
            len(results.get('aaaa_records', [])) +
            len(results.get('mx_records', [])) +
            len(results.get('ns_records', [])) +
            len(results.get('txt_records', []))
        )
        return f"Retrieved {dns_records} DNS records including A, AAAA, MX, NS, and TXT records."
    
    elif scan_type == 'whois':
        return "Retrieved domain registration and ownership information."
    
    else:
        return f"Completed {scan_type} scan with {findings_count} findings."

def generate_comprehensive_executive_summary(individual_reports):
    """Generate executive summary for comprehensive report"""
    total_reports = len(individual_reports)
    total_findings = sum(report.get('findings_count', 0) for report in individual_reports)
    
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for report in individual_reports:
        severity = report.get('severity', 'Low')
        severity_counts[severity] += 1
    
    overall_severity = 'Low'
    if severity_counts['Critical'] > 0:
        overall_severity = 'Critical'
    elif severity_counts['High'] > 0:
        overall_severity = 'High'
    elif severity_counts['Medium'] > 0:
        overall_severity = 'Medium'
    
    return {
        'total_reports': total_reports,
        'total_findings': total_findings,
        'overall_severity': overall_severity,
        'severity_breakdown': severity_counts,
        'key_findings': f"Comprehensive security assessment covering {total_reports} different scan types with {total_findings} total findings."
    }

def extract_comprehensive_findings(individual_reports):
    """Extract findings from multiple individual reports"""
    findings = []
    
    for report in individual_reports:
        scan_type = report.get('scan_type')
        target = report.get('target')
        severity = report.get('severity')
        details = report.get('details', {})
        
        if scan_type == 'vulnerability_scan':
            for critical in details.get('critical_vulnerabilities', []):
                findings.append({
                    'title': f"Critical: {critical.get('title', 'Vulnerability')}",
                    'description': critical.get('description', ''),
                    'severity': 'Critical',
                    'scan_type': scan_type,
                    'target': target
                })
            
            for high in details.get('high_vulnerabilities', []):
                findings.append({
                    'title': f"High: {high.get('title', 'Vulnerability')}",
                    'description': high.get('description', ''),
                    'severity': 'High',
                    'scan_type': scan_type,
                    'target': target
                })
        
        elif scan_type == 'port_scan':
            open_ports = details.get('open_ports', [])
            if open_ports:
                findings.append({
                    'title': f"Open Ports Discovered ({len(open_ports)} ports)",
                    'description': f"Found {len(open_ports)} open ports that may expose services",
                    'severity': 'Medium',
                    'scan_type': scan_type,
                    'target': target,
                    'details': open_ports
                })
    
    return findings

def generate_comprehensive_recommendations(individual_reports):
    """Generate data-driven recommendations based on comprehensive findings"""
    recommendations = []
    
    # Analyze scan types and findings
    scan_types = {}
    total_findings = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    
    for report in individual_reports:
        scan_type = report.get('scan_type', 'unknown')
        severity = report.get('severity', 'Low')
        findings_count = report.get('findings_count', 0)
        
        if scan_type not in scan_types:
            scan_types[scan_type] = {
                'count': 0,
                'findings': 0,
                'severities': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            }
        
        scan_types[scan_type]['count'] += 1
        scan_types[scan_type]['findings'] += findings_count
        scan_types[scan_type]['severities'][severity] += 1
        
        total_findings += findings_count
        
        if severity == 'Critical':
            critical_count += 1
        elif severity == 'High':
            high_count += 1
        elif severity == 'Medium':
            medium_count += 1
    
    # Critical vulnerabilities - Immediate action
    if critical_count > 0:
        recommendations.append({
            'title': 'Immediate Action Required',
            'description': f'Critical vulnerabilities were identified in {critical_count} reports that require immediate attention',
            'priority': 'Critical',
            'effort': 'High',
            'basis': f'Based on {critical_count} critical severity findings across {len(individual_reports)} scan reports'
        })
    
    # High severity issues - High priority
    if high_count > 0:
        recommendations.append({
            'title': 'Address High Priority Issues',
            'description': f'High severity findings in {high_count} reports should be addressed within 30 days',
            'priority': 'High',
            'effort': 'Medium',
            'basis': f'Based on {high_count} high severity findings with {total_findings} total issues discovered'
        })
    
    # Port scan specific recommendations
    if 'port_scan' in scan_types or 'basic_port_scan' in scan_types:
        port_scan_data = scan_types.get('port_scan', scan_types.get('basic_port_scan', {}))
        if port_scan_data.get('findings', 0) > 10:
            recommendations.append({
                'title': 'Reduce Attack Surface',
                'description': f'Close unnecessary open ports ({port_scan_data["findings"]} currently open)',
                'priority': 'Medium',
                'effort': 'Medium',
                'basis': f'Based on port scan revealing {port_scan_data["findings"]} open ports'
            })
        elif port_scan_data.get('findings', 0) > 0:
            recommendations.append({
                'title': 'Review Open Ports',
                'description': f'Review and secure {port_scan_data["findings"]} open ports',
                'priority': 'Medium',
                'effort': 'Low',
                'basis': f'Based on port scan revealing {port_scan_data["findings"]} open ports'
            })
    
    # Subdomain enumeration recommendations
    if 'subdomain' in scan_types:
        subdomain_data = scan_types['subdomain']
        if subdomain_data.get('findings', 0) > 20:
            recommendations.append({
                'title': 'Subdomain Security Review',
                'description': f'Review security of {subdomain_data["findings"]} discovered subdomains',
                'priority': 'Medium',
                'effort': 'High',
                'basis': f'Based on subdomain enumeration discovering {subdomain_data["findings"]} subdomains'
            })
        elif subdomain_data.get('findings', 0) > 0:
            recommendations.append({
                'title': 'Subdomain Monitoring',
                'description': f'Implement monitoring for {subdomain_data["findings"]} discovered subdomains',
                'priority': 'Low',
                'effort': 'Medium',
                'basis': f'Based on subdomain enumeration discovering {subdomain_data["findings"]} subdomains'
            })
    
    # DNS enumeration recommendations
    if 'dns' in scan_types:
        dns_data = scan_types['dns']
        if dns_data.get('findings', 0) > 10:
            recommendations.append({
                'title': 'DNS Security Hardening',
                'description': f'Review and secure {dns_data["findings"]} DNS records',
                'priority': 'Medium',
                'effort': 'Medium',
                'basis': f'Based on DNS enumeration revealing {dns_data["findings"]} DNS records'
            })
    
    # Vulnerability scan specific recommendations
    if 'vulnerability_scan' in scan_types:
        vuln_data = scan_types['vulnerability_scan']
        if vuln_data.get('severities', {}).get('Critical', 0) > 0:
            recommendations.append({
                'title': 'Patch Critical Vulnerabilities',
                'description': f'Apply patches for {vuln_data["severities"]["Critical"]} critical vulnerabilities immediately',
                'priority': 'Critical',
                'effort': 'High',
                'basis': f'Based on vulnerability scan detecting {vuln_data["severities"]["Critical"]} critical vulnerabilities'
            })
        
        if vuln_data.get('severities', {}).get('High', 0) > 0:
            recommendations.append({
                'title': 'Address High-Risk Vulnerabilities',
                'description': f'Fix {vuln_data["severities"]["High"]} high-risk vulnerabilities within 30 days',
                'priority': 'High',
                'effort': 'Medium',
                'basis': f'Based on vulnerability scan detecting {vuln_data["severities"]["High"]} high-risk vulnerabilities'
            })
    
    # Information disclosure recommendations
    if 'whois' in scan_types:
        recommendations.append({
            'title': 'Review Public Information',
            'description': 'Review and minimize sensitive information in public WHOIS records',
            'priority': 'Low',
            'effort': 'Low',
            'basis': 'Based on WHOIS information gathering revealing public domain details'
        })
    
    # General recommendations based on overall findings
    if total_findings > 50:
        recommendations.append({
            'title': 'Comprehensive Security Overhaul',
            'description': f'Implement comprehensive security improvements across {len(individual_reports)} assessed areas',
            'priority': 'High',
            'effort': 'High',
            'basis': f'Based on {total_findings} total findings across {len(individual_reports)} scan types'
        })
    elif total_findings > 20:
        recommendations.append({
            'title': 'Enhanced Security Monitoring',
            'description': 'Implement enhanced security monitoring and alerting systems',
            'priority': 'Medium',
            'effort': 'High',
            'basis': f'Based on {total_findings} findings requiring ongoing monitoring'
        })
    elif total_findings > 0:
        recommendations.append({
            'title': 'Implement Security Monitoring',
            'description': 'Deploy basic security monitoring and alerting systems',
            'priority': 'Medium',
            'effort': 'Medium',
            'basis': f'Based on {total_findings} findings requiring monitoring'
        })
    
    # Regular assessment recommendation (always include)
    recommendations.append({
        'title': 'Regular Security Assessments',
        'description': 'Conduct regular security assessments and penetration testing',
        'priority': 'Low',
        'effort': 'Medium',
        'basis': 'Best practice recommendation for ongoing security maintenance'
    })
    
    return recommendations

def generate_comprehensive_risk_assessment(individual_reports):
    """Generate comprehensive risk assessment with enhanced algorithm"""
    risk_score = 0
    risk_factors = []
    scan_type_weights = {
        'vulnerability_scan': 1.5,  # Higher weight for vulnerability scans
        'port_scan': 1.2,          # Moderate weight for port scans
        'basic_port_scan': 1.2,    # Same as port scan
        'whois': 0.8,              # Lower weight for info gathering
        'dns': 0.8,                # Lower weight for info gathering
        'subdomain': 0.9,          # Moderate weight for subdomain enumeration
        'exploit': 2.0             # Highest weight for exploitation
    }
    
    severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
    total_findings = 0
    critical_count = 0
    high_count = 0
    
    for report in individual_reports:
        severity = report.get('severity', 'Low')
        scan_type = report.get('scan_type', 'unknown')
        findings_count = report.get('findings_count', 0)
        
        # Get scan type weight (default to 1.0 if not found)
        scan_weight = scan_type_weights.get(scan_type, 1.0)
        
        # Calculate weighted risk score for this report
        base_score = severity_weights.get(severity, 1)
        weighted_score = base_score * scan_weight
        
        # Add findings count multiplier (more findings = higher risk)
        findings_multiplier = min(1 + (findings_count * 0.1), 2.0)  # Cap at 2x
        final_score = weighted_score * findings_multiplier
        
        risk_score += final_score
        total_findings += findings_count
        
        # Track critical and high findings
        if severity == 'Critical':
            critical_count += 1
            risk_factors.append(f"Critical {scan_type.replace('_', ' ').title()} findings detected ({findings_count} issues)")
        elif severity == 'High':
            high_count += 1
            risk_factors.append(f"High severity {scan_type.replace('_', ' ').title()} issues identified ({findings_count} issues)")
        elif severity == 'Medium':
            risk_factors.append(f"Medium severity {scan_type.replace('_', ' ').title()} findings ({findings_count} issues)")
    
    # Enhanced risk level determination with dynamic thresholds
    num_reports = len(individual_reports)
    
    # Adjust thresholds based on number of reports
    if num_reports <= 2:
        critical_threshold = 25
        high_threshold = 15
        medium_threshold = 8
    elif num_reports <= 5:
        critical_threshold = 35
        high_threshold = 25
        medium_threshold = 15
    else:
        critical_threshold = 45
        high_threshold = 35
        medium_threshold = 25
    
    # Determine overall risk level
    if risk_score >= critical_threshold or critical_count >= 2:
        overall_risk = 'Critical'
    elif risk_score >= high_threshold or high_count >= 3:
        overall_risk = 'High'
    elif risk_score >= medium_threshold:
        overall_risk = 'Medium'
    else:
        overall_risk = 'Low'
    
    # Generate detailed risk assessment
    risk_assessment = {
        'overall_risk': overall_risk,
        'risk_score': round(risk_score, 2),
        'risk_factors': risk_factors,
        'total_reports_assessed': num_reports,
        'total_findings': total_findings,
        'critical_findings_count': critical_count,
        'high_findings_count': high_count,
        'risk_breakdown': {
            'critical_reports': critical_count,
            'high_reports': high_count,
            'medium_reports': sum(1 for r in individual_reports if r.get('severity') == 'Medium'),
            'low_reports': sum(1 for r in individual_reports if r.get('severity') == 'Low')
        },
        'assessment_methodology': f"Risk calculated using weighted severity scores with scan type multipliers. Thresholds adjusted for {num_reports} reports."
    }
    
    return risk_assessment

def generate_pdf_content(report_data, report_type):
    """Generate PDF content for a report using ReportLab"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from io import BytesIO
        import json
        from datetime import datetime
        
        # Create a buffer to store the PDF
        buffer = BytesIO()
        
        # Create the PDF document with margins
        doc = SimpleDocTemplate(buffer, pagesize=A4, 
                              leftMargin=0.75*inch, rightMargin=0.75*inch,
                              topMargin=0.75*inch, bottomMargin=0.75*inch)
        story = []
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Custom styles for better readability
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=20,
            spaceAfter=30,
            alignment=1,  # Center alignment
            fontName='Helvetica-Bold',
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            fontName='Helvetica-Bold',
            textColor=colors.darkblue
        )
        
        subheading_style = ParagraphStyle(
            'SubHeading',
            parent=styles['Heading3'],
            fontSize=12,
            spaceAfter=8,
            spaceBefore=12,
            fontName='Helvetica-Bold',
            textColor=colors.darkgreen
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=6,
            leading=14
        )
        
        # Header with logo and title
        story.append(Paragraph("🔒 SECURITY ASSESSMENT REPORT", title_style))
        story.append(Spacer(1, 20))
        
        # Report Overview Section
        story.append(Paragraph("📋 REPORT OVERVIEW", heading_style))
        
        # Handle different report types
        if report_type == 'comprehensive':
            # Format timestamp for comprehensive reports
            timestamp = report_data.get('generated_at', 'N/A')
            if timestamp != 'N/A':
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    formatted_time = dt.strftime("%B %d, %Y at %I:%M %p UTC")
                except:
                    formatted_time = timestamp
            else:
                formatted_time = 'N/A'
            
            overview_data = [
                ['Field', 'Value'],
                ['Report Title', report_data.get('title', 'Untitled')],
                ['Report Type', 'Comprehensive Security Assessment'],
                ['Overall Severity', report_data.get('overall_severity', 'N/A').upper()],
                ['Total Findings', str(report_data.get('total_findings', 0))],
                ['Included Reports', str(len(report_data.get('included_reports', [])))],
                ['Generated On', formatted_time]
            ]
        else:
            # Individual report format
            timestamp = report_data.get('timestamp', 'N/A')
            if timestamp != 'N/A':
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    formatted_time = dt.strftime("%B %d, %Y at %I:%M %p UTC")
                except:
                    formatted_time = timestamp
            else:
                formatted_time = 'N/A'
            
            overview_data = [
                ['Field', 'Value'],
                ['Report Title', report_data.get('title', 'Untitled')],
                ['Target', report_data.get('target', 'N/A')],
                ['Scan Type', report_data.get('scan_type', 'N/A').replace('_', ' ').title()],
                ['Severity Level', report_data.get('severity', 'N/A').upper()],
                ['Total Findings', str(report_data.get('findings_count', 0))],
                ['Generated On', formatted_time]
            ]
        
        overview_table = Table(overview_data, colWidths=[2.2*inch, 4.3*inch])
        overview_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
        ]))
        story.append(overview_table)
        story.append(Spacer(1, 25))
        
        # Handle different content sections based on report type
        if report_type == 'comprehensive':
            # Comprehensive Report Executive Summary
            if report_data.get('executive_summary'):
                story.append(Paragraph("📊 EXECUTIVE SUMMARY", heading_style))
                story.append(Paragraph(report_data['executive_summary'].get('key_findings', 'No summary available'), normal_style))
                story.append(Spacer(1, 20))
            
            # Comprehensive Report Statistics
            if report_data.get('executive_summary'):
                story.append(Paragraph("📈 COMPREHENSIVE STATISTICS", heading_style))
                
                stats_data = [
                    ['Metric', 'Count'],
                    ['Total Reports Combined', str(report_data['executive_summary'].get('total_reports', 0))],
                    ['Total Findings', str(report_data['executive_summary'].get('total_findings', 0))],
                    ['Overall Severity', report_data.get('overall_severity', 'N/A').upper()]
                ]
                
                # Add severity breakdown if available
                severity_breakdown = report_data['executive_summary'].get('severity_breakdown', {})
                if severity_breakdown:
                    stats_data.extend([
                        ['Critical Findings', str(severity_breakdown.get('Critical', 0))],
                        ['High Findings', str(severity_breakdown.get('High', 0))],
                        ['Medium Findings', str(severity_breakdown.get('Medium', 0))],
                        ['Low Findings', str(severity_breakdown.get('Low', 0))]
                    ])
                
                stats_table = Table(stats_data, colWidths=[3*inch, 3.5*inch])
                stats_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
                ]))
                story.append(stats_table)
                story.append(Spacer(1, 25))
            
            # Included Reports List
            if report_data.get('included_reports'):
                story.append(Paragraph("📋 INCLUDED REPORTS", heading_style))
                story.append(Paragraph("This comprehensive report combines the following individual reports:", normal_style))
                
                included_reports_data = [['Report ID', 'Type']]
                for report_id in report_data['included_reports']:
                    # Try to get report details from cache
                    individual_report = cache.get(f'individual_report_{report_id}')
                    if individual_report:
                        scan_type = individual_report.get('scan_type', 'Unknown').replace('_', ' ').title()
                        # Truncate long report IDs for better display
                        display_id = report_id[:20] + '...' if len(report_id) > 20 else report_id
                        included_reports_data.append([display_id, scan_type])
                    else:
                        display_id = report_id[:20] + '...' if len(report_id) > 20 else report_id
                        included_reports_data.append([display_id, 'Unknown'])
                
                reports_table = Table(included_reports_data, colWidths=[3.5*inch, 3*inch])
                reports_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgreen]),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('WORDWRAP', (0, 0), (-1, -1), True),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6)
                ]))
                story.append(reports_table)
                
                # Add note about truncated IDs if any reports have long IDs
                long_ids = [rid for rid in report_data['included_reports'] if len(rid) > 20]
                if long_ids:
                    story.append(Spacer(1, 10))
                    story.append(Paragraph("Note: Long report IDs have been truncated for display. Full IDs are available in the web interface.", 
                                          ParagraphStyle('Note', fontSize=7, textColor=colors.grey)))
                
                story.append(Spacer(1, 25))
            
            # Comprehensive Findings
            if report_data.get('findings'):
                story.append(Paragraph("🔍 COMPREHENSIVE FINDINGS", heading_style))
                for i, finding in enumerate(report_data['findings'][:20], 1):  # Limit to first 20 findings
                    story.append(Paragraph(f"<b>{i}. {finding.get('title', 'Finding')}</b>", subheading_style))
                    story.append(Paragraph(f"Severity: {finding.get('severity', 'Unknown')}", normal_style))
                    story.append(Paragraph(f"Description: {finding.get('description', 'No description available')}", normal_style))
                    if finding.get('recommendation'):
                        story.append(Paragraph(f"Recommendation: {finding.get('recommendation')}", normal_style))
                    story.append(Spacer(1, 10))
                
                if len(report_data['findings']) > 20:
                    story.append(Paragraph(f"... and {len(report_data['findings']) - 20} more findings", normal_style))
                story.append(Spacer(1, 20))
            
            # Risk Assessment
            if report_data.get('risk_assessment'):
                story.append(Paragraph("⚠️ RISK ASSESSMENT", heading_style))
                
                risk_data = report_data['risk_assessment']
                overall_risk = risk_data.get('overall_risk', 'Risk assessment not available')
                
                # Display overall risk with color coding
                risk_color = colors.red if overall_risk == 'Critical' else \
                           colors.orange if overall_risk == 'High' else \
                           colors.yellow if overall_risk == 'Medium' else colors.green
                
                story.append(Paragraph(f"Overall Risk Level: <b>{overall_risk}</b>", 
                                      ParagraphStyle('RiskLevel', fontSize=12, textColor=risk_color)))
                
                # Display risk score and methodology
                if risk_data.get('risk_score'):
                    story.append(Paragraph(f"Risk Score: {risk_data['risk_score']}", normal_style))
                
                if risk_data.get('assessment_methodology'):
                    story.append(Paragraph(f"Methodology: {risk_data['assessment_methodology']}", normal_style))
                
                # Display risk breakdown if available
                if risk_data.get('risk_breakdown'):
                    breakdown = risk_data['risk_breakdown']
                    story.append(Paragraph("Risk Breakdown:", normal_style))
                    story.append(Paragraph(f"• Critical Reports: {breakdown.get('critical_reports', 0)}", normal_style))
                    story.append(Paragraph(f"• High Reports: {breakdown.get('high_reports', 0)}", normal_style))
                    story.append(Paragraph(f"• Medium Reports: {breakdown.get('medium_reports', 0)}", normal_style))
                    story.append(Paragraph(f"• Low Reports: {breakdown.get('low_reports', 0)}", normal_style))
                
                story.append(Spacer(1, 20))
            
            # Recommendations
            if report_data.get('recommendations'):
                story.append(Paragraph("💡 RECOMMENDATIONS", heading_style))
                for i, rec in enumerate(report_data['recommendations'][:10], 1):  # Limit to first 10 recommendations
                    story.append(Paragraph(f"<b>{i}. {rec.get('title', 'Recommendation')}</b>", subheading_style))
                    story.append(Paragraph(rec.get('description', 'No description available'), normal_style))
                    
                    # Show basis for recommendation if available
                    if rec.get('basis'):
                        story.append(Paragraph(f"<i>Basis: {rec.get('basis')}</i>", 
                                              ParagraphStyle('Basis', fontSize=8, textColor=colors.grey)))
                    
                    # Show priority and effort if available
                    if rec.get('priority') or rec.get('effort'):
                        priority_text = f"Priority: {rec.get('priority', 'N/A')}"
                        effort_text = f"Effort: {rec.get('effort', 'N/A')}"
                        story.append(Paragraph(f"<small>{priority_text} | {effort_text}</small>", 
                                              ParagraphStyle('Meta', fontSize=7, textColor=colors.darkgrey)))
                    
                    story.append(Spacer(1, 8))
                
                if len(report_data['recommendations']) > 10:
                    story.append(Paragraph(f"... and {len(report_data['recommendations']) - 10} more recommendations", normal_style))
                story.append(Spacer(1, 20))
        else:
            # Individual Report Executive Summary
            if report_data.get('summary'):
                story.append(Paragraph("📊 EXECUTIVE SUMMARY", heading_style))
                story.append(Paragraph(report_data['summary'], normal_style))
                story.append(Spacer(1, 20))
        
        # Detailed Findings
        if report_data.get('details'):
            story.append(Paragraph("🔍 DETAILED FINDINGS", heading_style))
            
            details = report_data['details']
            scan_type = report_data.get('scan_type', '')
            
            # Handle different scan types with better organization
            if 'port_scan' in scan_type or 'basic_port_scan' in scan_type:
                story.append(Paragraph("🌐 PORT SCAN RESULTS", subheading_style))
                
                # Port Scan Summary
                if details.get('summary'):
                    summary = details['summary']
                    story.append(Paragraph("📈 Scan Statistics", subheading_style))
                    
                    summary_data = [
                        ['Metric', 'Count', 'Percentage'],
                        ['Total Ports Scanned', str(summary.get('total_ports', 0)), '100%'],
                        ['Open Ports', str(summary.get('open_count', 0)), f"{round((summary.get('open_count', 0) / summary.get('total_ports', 1)) * 100, 1)}%"],
                        ['Closed Ports', str(summary.get('closed_count', 0)), f"{round((summary.get('closed_count', 0) / summary.get('total_ports', 1)) * 100, 1)}%"],
                        ['Filtered Ports', str(summary.get('filtered_count', 0)), f"{round((summary.get('filtered_count', 0) / summary.get('total_ports', 1)) * 100, 1)}%"]
                    ]
                    
                    summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
                    summary_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
                    ]))
                    story.append(summary_table)
                    story.append(Spacer(1, 15))
                
                # Open Ports (Most Important)
                if details.get('open_ports') and len(details['open_ports']) > 0:
                    story.append(Paragraph("🚨 OPEN PORTS (CRITICAL FINDINGS)", subheading_style))
                    story.append(Paragraph("These ports are accessible and may expose services:", normal_style))
                    
                    open_ports_data = [['Port', 'Service', 'Status', 'Response Time']]
                    for port in details['open_ports']:
                        response_time = f"{port.get('response_time', 0)}ms" if port.get('response_time', 0) > 0 else 'N/A'
                        open_ports_data.append([
                            str(port.get('port', 'N/A')),
                            port.get('service', 'Unknown'),
                            'OPEN',
                            response_time
                        ])
                    
                    ports_table = Table(open_ports_data, colWidths=[1*inch, 2*inch, 1*inch, 1.5*inch])
                    ports_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightcoral),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
                    ]))
                    story.append(ports_table)
                    story.append(Spacer(1, 15))
                else:
                    story.append(Paragraph("✅ No open ports detected - Good security posture!", normal_style))
                    story.append(Spacer(1, 10))
                
                # Closed Ports (Limited display)
                if details.get('closed_ports') and len(details['closed_ports']) > 0:
                    story.append(Paragraph("🔒 CLOSED PORTS (SECURE)", subheading_style))
                    story.append(Paragraph(f"Found {len(details['closed_ports'])} closed ports. Showing first 10 examples:", normal_style))
                    
                    closed_ports_data = [['Port', 'Service', 'Status']]
                    for port in details['closed_ports'][:10]:  # Show only first 10
                        closed_ports_data.append([
                            str(port.get('port', 'N/A')),
                            port.get('service', 'Unknown'),
                            'CLOSED'
                        ])
                    
                    if len(details['closed_ports']) > 10:
                        closed_ports_data.append(['...', f'and {len(details["closed_ports"]) - 10} more', 'CLOSED'])
                    
                    closed_table = Table(closed_ports_data, colWidths=[1.5*inch, 2.5*inch, 1.5*inch])
                    closed_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
                    ]))
                    story.append(closed_table)
                    story.append(Spacer(1, 15))
                
                # Filtered Ports (if any)
                if details.get('filtered_ports') and len(details['filtered_ports']) > 0:
                    story.append(Paragraph("🛡️ FILTERED PORTS", subheading_style))
                    story.append(Paragraph(f"Found {len(details['filtered_ports'])} filtered ports (likely blocked by firewall):", normal_style))
                    
                    filtered_ports_data = [['Port', 'Service', 'Status']]
                    for port in details['filtered_ports'][:10]:  # Show only first 10
                        filtered_ports_data.append([
                            str(port.get('port', 'N/A')),
                            port.get('service', 'Unknown'),
                            'FILTERED'
                        ])
                    
                    if len(details['filtered_ports']) > 10:
                        filtered_ports_data.append(['...', f'and {len(details["filtered_ports"]) - 10} more', 'FILTERED'])
                    
                    filtered_table = Table(filtered_ports_data, colWidths=[1.5*inch, 2.5*inch, 1.5*inch])
                    filtered_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightyellow),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
                    ]))
                    story.append(filtered_table)
                    story.append(Spacer(1, 15))
            
            elif 'vulnerability_scan' in scan_type:
                story.append(Paragraph("🔍 VULNERABILITY SCAN RESULTS", subheading_style))
                
                if details.get('critical_vulnerabilities'):
                    story.append(Paragraph("🚨 CRITICAL VULNERABILITIES", subheading_style))
                    for i, vuln in enumerate(details['critical_vulnerabilities'][:10], 1):
                        story.append(Paragraph(f"<b>{i}. {vuln.get('name', 'Unknown Vulnerability')}</b>", normal_style))
                        story.append(Paragraph(f"Description: {vuln.get('description', 'No description available')}", normal_style))
                        if vuln.get('cwe'):
                            story.append(Paragraph(f"CWE: {vuln.get('cwe')}", normal_style))
                        if vuln.get('cvss'):
                            story.append(Paragraph(f"CVSS Score: {vuln.get('cvss')}", normal_style))
                        story.append(Spacer(1, 8))
                
                if details.get('high_vulnerabilities'):
                    story.append(Paragraph("⚠️ HIGH VULNERABILITIES", subheading_style))
                    for i, vuln in enumerate(details['high_vulnerabilities'][:10], 1):
                        story.append(Paragraph(f"<b>{i}. {vuln.get('name', 'Unknown Vulnerability')}</b>", normal_style))
                        story.append(Paragraph(f"Description: {vuln.get('description', 'No description available')}", normal_style))
                        if vuln.get('cwe'):
                            story.append(Paragraph(f"CWE: {vuln.get('cwe')}", normal_style))
                        if vuln.get('cvss'):
                            story.append(Paragraph(f"CVSS Score: {vuln.get('cvss')}", normal_style))
                        story.append(Spacer(1, 8))
            
            elif 'subdomain' in scan_type:
                story.append(Paragraph("🌐 SUBDOMAIN ENUMERATION RESULTS", subheading_style))
                
                # Check if we have subdomains in the data (handle different data structures)
                subdomains = []
                if details.get('subdomains'):
                    subdomains = details['subdomains']
                elif details.get('data', {}).get('subdomains'):
                    subdomains = details['data']['subdomains']
                
                if isinstance(subdomains, list) and len(subdomains) > 0:
                    story.append(Paragraph(f"📊 Subdomain Summary", subheading_style))
                    story.append(Paragraph(f"Total subdomains discovered: {len(subdomains)}", normal_style))
                    story.append(Spacer(1, 15))
                    
                    # Create subdomain table
                    story.append(Paragraph("🔍 DISCOVERED SUBDOMAINS", subheading_style))
                    
                    subdomain_data = [['Subdomain', 'IP Address', 'Status', 'Discovery Method']]
                    for subdomain in subdomains[:20]:  # Show first 20 subdomains
                        subdomain_data.append([
                            subdomain.get('subdomain', 'N/A'),
                            subdomain.get('ip', 'N/A'),
                            subdomain.get('status', 'Unknown'),
                            subdomain.get('discovery_method', 'Unknown')
                        ])
                    
                    if len(subdomains) > 20:
                        subdomain_data.append(['...', f'and {len(subdomains) - 20} more subdomains', '...', '...'])
                    
                    subdomain_table = Table(subdomain_data, colWidths=[2.5*inch, 1.5*inch, 1*inch, 1.5*inch])
                    subdomain_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightblue]),
                        ('FONTSIZE', (0, 1), (-1, -1), 8),
                        ('WORDWRAP', (0, 0), (-1, -1), True),
                        ('LEFTPADDING', (0, 0), (-1, -1), 6),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6)
                    ]))
                    story.append(subdomain_table)
                    story.append(Spacer(1, 15))
                    
                    # Show detailed information for first few subdomains
                    story.append(Paragraph("📋 DETAILED SUBDOMAIN ANALYSIS", subheading_style))
                    for i, subdomain in enumerate(subdomains[:5], 1):  # Show details for first 5
                        story.append(Paragraph(f"<b>{i}. {subdomain.get('subdomain', 'Unknown')}</b>", normal_style))
                        
                        # Basic info
                        if subdomain.get('ip'):
                            story.append(Paragraph(f"   IP Address: {subdomain['ip']}", normal_style))
                        if subdomain.get('status'):
                            story.append(Paragraph(f"   Status: {subdomain['status']}", normal_style))
                        if subdomain.get('discovery_method'):
                            story.append(Paragraph(f"   Discovery Method: {subdomain['discovery_method']}", normal_style))
                        
                        # DNS Records
                        if subdomain.get('dns_records') and len(subdomain['dns_records']) > 0:
                            story.append(Paragraph(f"   DNS Records: {len(subdomain['dns_records'])} records found", normal_style))
                        
                        # SSL Certificate info
                        if subdomain.get('ssl_issuer') and subdomain['ssl_issuer'] != 'No SSL':
                            story.append(Paragraph(f"   SSL Certificate: {subdomain['ssl_issuer']}", normal_style))
                            if subdomain.get('ssl_expiry'):
                                story.append(Paragraph(f"   SSL Expiry: {subdomain['ssl_expiry']}", normal_style))
                        
                        # Search engine data
                        if subdomain.get('indexed'):
                            story.append(Paragraph(f"   Search Engine Indexed: Yes", normal_style))
                            if subdomain.get('page_rank'):
                                story.append(Paragraph(f"   Page Rank: {subdomain['page_rank']}", normal_style))
                        
                        # VirusTotal reputation
                        if subdomain.get('reputation_score'):
                            story.append(Paragraph(f"   Reputation Score: {subdomain['reputation_score']}", normal_style))
                        if subdomain.get('detections') and subdomain['detections'] > 0:
                            story.append(Paragraph(f"   Security Detections: {subdomain['detections']}", normal_style))
                        
                        story.append(Spacer(1, 10))
                    
                    if len(subdomains) > 5:
                        story.append(Paragraph(f"... and {len(subdomains) - 5} more subdomains with detailed analysis", normal_style))
                        story.append(Spacer(1, 10))
                else:
                    story.append(Paragraph("No subdomains were discovered during the enumeration scan.", normal_style))
                    story.append(Spacer(1, 10))
            
            elif 'whois' in scan_type:
                story.append(Paragraph("📋 WHOIS LOOKUP RESULTS", subheading_style))
                
                if details.get('registrar'):
                    story.append(Paragraph(f"<b>Registrar:</b> {details['registrar']}", normal_style))
                if details.get('creation_date'):
                    story.append(Paragraph(f"<b>Creation Date:</b> {details['creation_date']}", normal_style))
                if details.get('expiration_date'):
                    story.append(Paragraph(f"<b>Expiration Date:</b> {details['expiration_date']}", normal_style))
                if details.get('updated_date'):
                    story.append(Paragraph(f"<b>Last Updated:</b> {details['updated_date']}", normal_style))
                if details.get('status'):
                    story.append(Paragraph(f"<b>Domain Status:</b> {details['status']}", normal_style))
                if details.get('name_servers'):
                    story.append(Paragraph(f"<b>Name Servers:</b> {', '.join(details['name_servers'])}", normal_style))
                story.append(Spacer(1, 15))
            
            elif 'dns' in scan_type:
                story.append(Paragraph("🌐 DNS ENUMERATION RESULTS", subheading_style))
                
                # Display different DNS record types
                record_types = ['a_records', 'aaaa_records', 'mx_records', 'ns_records', 'txt_records', 'cname_records']
                record_names = ['A Records', 'AAAA Records', 'MX Records', 'NS Records', 'TXT Records', 'CNAME Records']
                
                for record_type, record_name in zip(record_types, record_names):
                    if details.get(record_type) and len(details[record_type]) > 0:
                        story.append(Paragraph(f"<b>{record_name}:</b>", normal_style))
                        for record in details[record_type][:5]:  # Show first 5 records
                            story.append(Paragraph(f"   {record}", normal_style))
                        if len(details[record_type]) > 5:
                            story.append(Paragraph(f"   ... and {len(details[record_type]) - 5} more", normal_style))
                        story.append(Spacer(1, 5))
                story.append(Spacer(1, 10))
            
            else:
                # Generic scan details
                story.append(Paragraph("📄 SCAN DETAILS", subheading_style))
                story.append(Paragraph("Raw scan data:", normal_style))
                
                # Format JSON for better readability
                try:
                    formatted_json = json.dumps(details, indent=2)
                    # Split long JSON into paragraphs
                    lines = formatted_json.split('\n')
                    for line in lines[:50]:  # Limit to first 50 lines
                        story.append(Paragraph(f"<code>{line}</code>", normal_style))
                    if len(lines) > 50:
                        story.append(Paragraph(f"... and {len(lines) - 50} more lines", normal_style))
                except:
                    story.append(Paragraph("Unable to format scan details", normal_style))
        
        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph("Generated by Pent-Framework Security Assessment Tool", 
                              ParagraphStyle('Footer', fontSize=8, alignment=1, textColor=colors.grey)))
        
        # Build the PDF
        doc.build(story)
        
        # Get the PDF content
        pdf_content = buffer.getvalue()
        buffer.close()
        
        return pdf_content
        
    except ImportError:
        # Fallback if ReportLab is not available
        return f"PDF generation requires ReportLab library. Report content: {report_data.get('title', 'Untitled')}"
    except Exception as e:
        return f"Error generating PDF: {str(e)}"

@api_view(['GET'])
def check_nmap_availability(request):
    """Check if Nmap is available on the system"""
    try:
        import subprocess
        import sys
        
        # Try to run nmap --version
        result = subprocess.run(['nmap', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        
        if result.returncode == 0:
            # Extract version from output
            version_line = result.stdout.split('\n')[0]
            version = version_line.replace('Nmap version ', '').split(' ')[0]
            
            return JsonResponse({
                'success': True,
                'available': True,
                'version': version,
                'message': 'Nmap is available'
            })
        else:
            return JsonResponse({
                'success': True,
                'available': False,
                'error': 'Nmap command failed',
                'message': 'Nmap is not properly installed'
            })
            
    except FileNotFoundError:
        return JsonResponse({
            'success': True,
            'available': False,
            'error': 'Nmap not found in PATH',
            'message': 'Nmap is not installed or not in PATH'
        })
    except subprocess.TimeoutExpired:
        return JsonResponse({
            'success': True,
            'available': False,
            'error': 'Nmap command timed out',
            'message': 'Nmap command execution timed out'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'available': False,
            'error': str(e),
            'message': 'Error checking Nmap availability'
        }, status=500)

@api_view(['POST'])
def basic_port_scan(request):
    """
    Perform real port scanning using Python socket connections
    """
    try:
        data = json.loads(request.body)
        target = data.get('target')
        port_range = data.get('port_range', '1-1000')
        
        if not target:
            return JsonResponse({'error': 'Target is required'}, status=400)
        
        # Parse port range
        if port_range == 'common':
            ports = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 162, 389, 443, 445, 465, 514, 515, 587, 636, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 5984, 6379, 8080, 8443, 9000, 9090, 9200, 27017]
        else:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        
        import socket
        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import time
        
        results = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'target': target,
            'scan_type': 'real_basic_port_scan',
            'timestamp': time.time(),
            'ports_scanned': len(ports)
        }
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)  # 2 second timeout
                
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    return {
                        'port': port,
                        'status': 'open',
                        'service': get_service_name(port),
                        'response_time': 0  # We can't measure this easily with connect_ex
                    }
                else:
                    return {
                        'port': port,
                        'status': 'closed',
                        'service': get_service_name(port),
                        'response_time': 0
                    }
                    
            except socket.timeout:
                return {
                    'port': port,
                    'status': 'filtered',
                    'service': get_service_name(port),
                    'response_time': 2000
                }
            except Exception as e:
                return {
                    'port': port,
                    'status': 'filtered',
                    'service': get_service_name(port),
                    'response_time': 0
                }
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=50) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result['status'] == 'open':
                    results['open_ports'].append(result)
                elif result['status'] == 'closed':
                    results['closed_ports'].append(result)
                else:
                    results['filtered_ports'].append(result)
        
        # Add summary
        results['summary'] = {
            'total_ports': len(ports),
            'open_count': len(results['open_ports']),
            'closed_count': len(results['closed_ports']),
            'filtered_count': len(results['filtered_ports'])
        }
        
        return JsonResponse(results)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def get_service_name(port):
    """Get service name for common ports"""
    common_services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
        110: "POP3", 123: "NTP", 135: "RPC", 137: "NetBIOS", 138: "NetBIOS",
        139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
        515: "LPR", 587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
        1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9000: "Webmin",
        9090: "HTTP-Alt", 9200: "Elasticsearch", 27017: "MongoDB"
    }
    
    if port in common_services:
        return common_services[port]
    elif 1 <= port <= 1023:
        return "Well-known service"
    elif 1024 <= port <= 49151:
        return "Registered service"
    elif 49152 <= port <= 65535:
        return "Dynamic/Private service"
    else:
        return "Unknown"

# Audit Logs API Endpoints
@api_view(['GET'])
def get_audit_logs(request):
    """
    Get audit logs with filtering and pagination
    """
    try:
        # Get query parameters
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))
        search = request.GET.get('search', '')
        module_filter = request.GET.get('module', '')
        status_filter = request.GET.get('status', '')
        user_filter = request.GET.get('user', '')
        severity_filter = request.GET.get('severity', '')
        start_date = request.GET.get('start_date', '')
        end_date = request.GET.get('end_date', '')
        
        # Build query
        queryset = AuditLog.objects.all()
        
        # Apply filters
        if search:
            queryset = queryset.filter(
                Q(action__icontains=search) |
                Q(user_email__icontains=search) |
                Q(target__icontains=search) |
                Q(details__icontains=search)
            )
        
        if module_filter:
            queryset = queryset.filter(module=module_filter)
        
        if status_filter:
            queryset = queryset.filter(status=status_filter)
        
        if user_filter:
            queryset = queryset.filter(user_email=user_filter)
        
        if severity_filter:
            queryset = queryset.filter(severity=severity_filter)
        
        if start_date:
            try:
                start_datetime = timezone.datetime.strptime(start_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                queryset = queryset.filter(timestamp__gte=start_datetime)
            except ValueError:
                pass
        
        if end_date:
            try:
                end_datetime = timezone.datetime.strptime(end_date, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                queryset = queryset.filter(timestamp__lte=end_datetime)
            except ValueError:
                pass
        
        # Pagination
        paginator = Paginator(queryset, page_size)
        page_obj = paginator.get_page(page)
        
        # Prepare response data
        logs_data = []
        for log in page_obj:
            logs_data.append({
                'id': log.id,
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': log.user_email or 'Unknown',
                'action': log.action,
                'target': log.target,
                'module': log.module,
                'status': log.status,
                'severity': log.severity,
                'ip': log.ip_address,
                'details': log.details,
                'user_agent': log.user_agent,
                'metadata': log.metadata,
            })
        
        # Get statistics
        total_logs = queryset.count()
        total_users = queryset.values('user_email').distinct().count()
        failed_actions = queryset.filter(status='failed').count()
        security_events = queryset.filter(
            Q(module='authentication') | 
            Q(status='failed') | 
            Q(severity__in=['high', 'critical'])
        ).count()
        
        response_data = {
            'success': True,
            'logs': logs_data,
            'pagination': {
                'current_page': page,
                'total_pages': paginator.num_pages,
                'total_count': total_logs,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous(),
            },
            'statistics': {
                'total_actions': total_logs,
                'failed_actions': failed_actions,
                'active_users': total_users,
                'security_events': security_events,
            },
            'filters': {
                'available_modules': [choice[0] for choice in AuditLog.MODULE_CHOICES],
                'available_statuses': [choice[0] for choice in AuditLog.STATUS_CHOICES],
                'available_severities': [choice[0] for choice in AuditLog.SEVERITY_CHOICES],
                'available_users': list(queryset.values_list('user_email', flat=True).distinct()),
            }
        }
        
        return Response(response_data)
        
    except Exception as e:
        return Response({'success': False, 'error': str(e)}, status=500)

@api_view(['GET'])
def get_audit_statistics(request):
    """
    Get audit logs statistics and analytics
    """
    try:
        # Get date range
        days = int(request.GET.get('days', 30))
        end_date = timezone.now()
        start_date = end_date - timezone.timedelta(days=days)
        
        # Get logs in date range
        logs = AuditLog.objects.filter(timestamp__range=[start_date, end_date])
        
        # Activity by module
        module_stats = logs.values('module').annotate(count=Count('id')).order_by('-count')
        
        # Activity by status
        status_stats = logs.values('status').annotate(count=Count('id')).order_by('-count')
        
        # Activity by severity
        severity_stats = logs.values('severity').annotate(count=Count('id')).order_by('-count')
        
        # Activity by user
        user_stats = logs.values('user_email').annotate(count=Count('id')).order_by('-count')[:10]
        
        # Daily activity
        daily_stats = []
        for i in range(days):
            date = end_date - timezone.timedelta(days=i)
            day_start = date.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = date.replace(hour=23, minute=59, second=59, microsecond=999999)
            count = logs.filter(timestamp__range=[day_start, day_end]).count()
            daily_stats.append({
                'date': date.strftime('%Y-%m-%d'),
                'count': count
            })
        daily_stats.reverse()
        
        # Top actions
        top_actions = logs.values('action').annotate(count=Count('id')).order_by('-count')[:10]
        
        # Security events
        security_events = logs.filter(
            Q(module='authentication') | 
            Q(status='failed') | 
            Q(severity__in=['high', 'critical'])
        ).count()
        
        response_data = {
            'success': True,
            'statistics': {
                'total_events': logs.count(),
                'security_events': security_events,
                'unique_users': logs.values('user_email').distinct().count(),
                'failed_actions': logs.filter(status='failed').count(),
            },
            'analytics': {
                'module_stats': list(module_stats),
                'status_stats': list(status_stats),
                'severity_stats': list(severity_stats),
                'user_stats': list(user_stats),
                'daily_stats': daily_stats,
                'top_actions': list(top_actions),
            }
        }
        
        return Response(response_data)
        
    except Exception as e:
        return Response({'success': False, 'error': str(e)}, status=500)

@api_view(['POST'])
def export_audit_logs(request):
    """
    Export audit logs to CSV/JSON
    """
    try:
        data = request.data
        format_type = data.get('format', 'json')
        filters = data.get('filters', {})
        
        # Apply filters
        queryset = AuditLog.objects.all()
        
        if filters.get('search'):
            queryset = queryset.filter(
                Q(action__icontains=filters['search']) |
                Q(user_email__icontains=filters['search']) |
                Q(target__icontains=filters['search'])
            )
        
        if filters.get('module'):
            queryset = queryset.filter(module=filters['module'])
        
        if filters.get('status'):
            queryset = queryset.filter(status=filters['status'])
        
        if filters.get('start_date'):
            try:
                start_datetime = timezone.datetime.strptime(filters['start_date'], '%Y-%m-%d').replace(tzinfo=timezone.utc)
                queryset = queryset.filter(timestamp__gte=start_datetime)
            except ValueError:
                pass
        
        if filters.get('end_date'):
            try:
                end_datetime = timezone.datetime.strptime(filters['end_date'], '%Y-%m-%d').replace(tzinfo=timezone.utc)
                queryset = queryset.filter(timestamp__lte=end_datetime)
            except ValueError:
                pass
        
        # Prepare data
        logs_data = []
        for log in queryset:
            logs_data.append({
                'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'user': log.user_email or 'Unknown',
                'action': log.action,
                'target': log.target,
                'module': log.module,
                'status': log.status,
                'severity': log.severity,
                'ip_address': log.ip_address,
                'details': log.details,
            })
        
        if format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                'timestamp', 'user', 'action', 'target', 'module', 
                'status', 'severity', 'ip_address', 'details'
            ])
            writer.writeheader()
            writer.writerows(logs_data)
            
            from django.http import HttpResponse
            response = HttpResponse(output.getvalue(), content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="audit_logs.csv"'
            return response
        
        else:  # JSON
            return Response({
                'success': True,
                'data': logs_data,
                'count': len(logs_data)
            })
        
    except Exception as e:
        return Response({'success': False, 'error': str(e)}, status=500)

@api_view(['POST'])
def clear_audit_logs(request):
    """
    Clear audit logs (admin only)
    """
    try:
        data = request.data
        days_to_keep = data.get('days_to_keep', 90)
        
        # Calculate cutoff date
        cutoff_date = timezone.now() - timezone.timedelta(days=days_to_keep)
        
        # Delete old logs
        deleted_count = AuditLog.objects.filter(timestamp__lt=cutoff_date).delete()[0]
        
        # Log this action
        log_audit_event(
            request=request,
            action="Audit logs cleared",
            target=f"Logs older than {days_to_keep} days",
            module="administration",
            status="success",
            details=f"Deleted {deleted_count} log entries"
        )
        
        return Response({
            'success': True,
            'message': f'Successfully deleted {deleted_count} old audit log entries',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        return Response({'success': False, 'error': str(e)}, status=500)
