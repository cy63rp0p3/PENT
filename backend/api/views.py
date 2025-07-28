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

# Import our new services
from .zap_service import ZAPService
from .nmap_service import NmapService

# Initialize services
zap_service = ZAPService()
nmap_service = NmapService()

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
def nmap_scan_status(request, scan_id):
    """Get Nmap scan status"""
    try:
        status = nmap_service.get_scan_status(scan_id)
        return Response(status)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def check_tools_availability(request):
    """Check availability of scanning tools"""
    try:
        nmap_status = nmap_service.check_nmap_availability()
        zap_status = zap_service.check_zap_status()
        
        return Response({
            'nmap': nmap_status,
            'zap': zap_status,
            'all_available': nmap_status.get('available', False) and 'error' not in zap_status
        })
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def get_all_nmap_scans(request):
    """Get all Nmap scan results"""
    try:
        scans = nmap_service.get_all_scans()
        return Response(scans)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

@api_view(['GET'])
def test_nmap_performance(request):
    """Test Nmap performance with different configurations"""
    try:
        target = request.GET.get('target', '127.0.0.1')
        results = nmap_service.test_performance(target)
        return Response(results)
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
    
    # Use Nmap service for scanning
    try:
        # Start async scan with optimized defaults
        scan_result = nmap_service.start_async_scan(
            target=target,
            scan_type=scan_type,
            ports=options.get('portRange'),  # Use None for quick scan default
            options=options
        )
        
        if 'error' in scan_result:
            return Response({'error': scan_result['error']}, status=400)
        
        return Response(scan_result)
        
    except Exception as e:
        return Response({'error': f'Failed to start scan: {str(e)}'}, status=500)

@api_view(['POST'])
def vulnerability_scan(request):
    """Perform a vulnerability scan on a target using ZAP"""
    target = request.data.get('target')
    scan_type = request.data.get('scan_type', 'basic')  # basic, full, api, custom
    options = request.data.get('options', {})
    
    if not target:
        return Response({'error': 'Target is required.'}, status=400)
    
    # Validate ZAP options
    zap_scan_type = options.get('zapScanType', 'spider')
    zap_scan_level = options.get('zapScanLevel', 'low')
    zap_include_context = options.get('zapIncludeContext', False)
    zap_custom_headers = options.get('zapCustomHeaders', '')
    
    # Validate scan type
    valid_scan_types = ['spider', 'active', 'passive']
    if zap_scan_type not in valid_scan_types:
        return Response({'error': f'Invalid ZAP scan type. Must be one of: {", ".join(valid_scan_types)}'}, status=400)
    
    # Validate scan level
    valid_scan_levels = ['low', 'medium', 'high']
    if zap_scan_level not in valid_scan_levels:
        return Response({'error': f'Invalid ZAP scan level. Must be one of: {", ".join(valid_scan_levels)}'}, status=400)
    
    # Validate custom headers if provided
    if zap_custom_headers:
        try:
            headers_dict = json.loads(zap_custom_headers)
            if not isinstance(headers_dict, dict):
                raise ValueError("Headers must be a JSON object")
        except (json.JSONDecodeError, ValueError) as e:
            return Response({'error': f'Invalid custom headers format: {str(e)}'}, status=400)
    
    scan_id = str(uuid.uuid4())
    cache.set(f'scan:{scan_id}:progress', 0, timeout=SCAN_PROGRESS_TIMEOUT)
    cache.set(f'scan:{scan_id}:result', None, timeout=SCAN_PROGRESS_TIMEOUT)
    
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
