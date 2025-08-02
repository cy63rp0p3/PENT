from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
import datetime
from django.contrib.auth import authenticate
from .models import UserProfile
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

# Import our services
from .nmap_service import NmapService
from .zap_service import ZAPService

# Initialize services
nmap_service = NmapService()
zap_service = ZAPService()

# In-memory storage for ZAP scan results (in production, use database)
zap_scan_results = {}

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

        response = Response({
            'user': {'id': str(user.id), 'email': user.email, 'role': role},
            'session': {'access_token': 'demo-token'},
        })
        # Mock log
        print(f'Login: {user.email} at {datetime.datetime.now()}')
        return response
    else:
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
            return Response({'error': scan_result['error']}, status=400)
        
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
        
        # Generate PDF content (simplified for now)
        pdf_content = generate_pdf_content(report_data, report_type)
        
        # For now, return a JSON response indicating success
        # In a real implementation, you would generate and return the actual PDF
        return JsonResponse({
            'success': True,
            'message': f'{report_type} report PDF generated successfully',
            'filename': f'{report_type}-report-{report_id}.pdf'
        })
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
    """Generate recommendations based on comprehensive findings"""
    recommendations = []
    
    # Check for critical vulnerabilities
    critical_reports = [r for r in individual_reports if r.get('severity') == 'Critical']
    if critical_reports:
        recommendations.append({
            'title': 'Immediate Action Required',
            'description': 'Critical vulnerabilities were identified that require immediate attention',
            'priority': 'Critical',
            'effort': 'High'
        })
    
    # Check for high severity issues
    high_reports = [r for r in individual_reports if r.get('severity') == 'High']
    if high_reports:
        recommendations.append({
            'title': 'Address High Priority Issues',
            'description': 'High severity findings should be addressed within 30 days',
            'priority': 'High',
            'effort': 'Medium'
        })
    
    # General recommendations
    recommendations.extend([
        {
            'title': 'Implement Security Monitoring',
            'description': 'Deploy comprehensive security monitoring and alerting systems',
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

def generate_comprehensive_risk_assessment(individual_reports):
    """Generate comprehensive risk assessment"""
    risk_score = 0
    risk_factors = []
    
    for report in individual_reports:
        severity = report.get('severity', 'Low')
        scan_type = report.get('scan_type')
        
        # Add to risk score
        severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        risk_score += severity_weights.get(severity, 1)
        
        # Add risk factors
        if severity == 'Critical':
            risk_factors.append(f"Critical {scan_type} findings detected")
        elif severity == 'High':
            risk_factors.append(f"High severity {scan_type} issues identified")
    
    # Determine overall risk level
    if risk_score >= 30:
        overall_risk = 'Critical'
    elif risk_score >= 20:
        overall_risk = 'High'
    elif risk_score >= 10:
        overall_risk = 'Medium'
    else:
        overall_risk = 'Low'
    
    return {
        'overall_risk': overall_risk,
        'risk_score': risk_score,
        'risk_factors': risk_factors,
        'total_reports_assessed': len(individual_reports)
    }

def generate_pdf_content(report_data, report_type):
    """Generate PDF content for a report (placeholder)"""
    # This would integrate with a PDF generation library like ReportLab
    # For now, return a simple text representation
    return f"PDF content for {report_type} report: {report_data.get('title', 'Untitled')}"

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
