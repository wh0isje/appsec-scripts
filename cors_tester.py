"""
Usage: python3 cors_tester.py -u <URL> [-o ORIGIN] [-v] [--stealth] [--output report.json]

Example:
  python3 cors_tester.py -u https://api.example.com
  python3 cors_tester.py -u https://api.example.com -o https://evil.com -v
  python3 cors_tester.py -u https://api.example.com --stealth --delay 1
  python3 cors_tester.py -u https://api.example.com --output report.json --html
"""

import requests
import argparse
import sys
import time
import json
import re
import random
import hashlib
import threading
from urllib.parse import urlparse, urljoin
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from collections import defaultdict
import os

# Try to import optional dependencies
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

def banner():
    """Display tool banner"""
    print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                    CORS TESTER v2.0 - Advanced                     ║
║         Cross-Origin Resource Sharing Security Scanner              ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

# Thread-safe results collector
class Results:
    def __init__(self):
        self.lock = threading.Lock()
        self.tests_run = 0
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
        self.info: List[Dict[str, Any]] = []
        self.performance_metrics = {
            'total_time': 0,
            'fastest_response': float('inf'),
            'slowest_response': 0,
            'avg_response_time': 0
        }

    def add_vulnerability(self, test_name: str, severity: str, description: str, 
                          headers: Dict[str, str], origin: str, details: Optional[Dict] = None):
        with self.lock:
            self.tests_run += 1
            self.vulnerabilities.append({
                'test': test_name,
                'severity': severity,
                'description': description,
                'headers': headers,
                'origin': origin,
                'details': details or {},
                'timestamp': datetime.now().isoformat()
            })

    def add_warning(self, test_name: str, description: str, headers: Dict[str, str], 
                    severity: str = 'MEDIUM'):
        with self.lock:
            self.tests_run += 1
            self.warnings.append({
                'test': test_name,
                'severity': severity,
                'description': description,
                'headers': headers,
                'timestamp': datetime.now().isoformat()
            })

    def add_info(self, test_name: str, description: str, headers: Dict[str, str]):
        with self.lock:
            self.tests_run += 1
            self.info.append({
                'test': test_name,
                'description': description,
                'headers': headers,
                'timestamp': datetime.now().isoformat()
            })

    def update_performance(self, response_time: float):
        with self.lock:
            if response_time < self.performance_metrics['fastest_response']:
                self.performance_metrics['fastest_response'] = response_time
            if response_time > self.performance_metrics['slowest_response']:
                self.performance_metrics['slowest_response'] = response_time

    def get_summary(self) -> Dict[str, Any]:
        critical = len([v for v in self.vulnerabilities if v.get('severity') == 'CRITICAL'])
        high = len([v for v in self.vulnerabilities if v.get('severity') == 'HIGH'])
        medium = len([w for w in self.warnings if w.get('severity') == 'MEDIUM'])
        low = len([w for w in self.warnings if w.get('severity') == 'LOW'])
        
        return {
            'tests_run': self.tests_run,
            'vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_critical': critical,
            'vulnerabilities_high': high,
            'warnings': len(self.warnings),
            'warnings_medium': medium,
            'warnings_low': low,
            'info': len(self.info),
            'vulnerability_details': self.vulnerabilities,
            'warning_details': self.warnings,
            'info_details': self.info,
            'performance': self.performance_metrics
        }

class StealthMode:
    """Implements stealth mode with random delays"""
    def __init__(self, enabled: bool = False, delay: float = 1.0, jitter: float = 0.5):
        self.enabled = enabled
        self.base_delay = delay
        self.jitter = jitter
        self.request_count = 0
    
    def wait(self):
        if self.enabled:
            delay = self.base_delay + (random.random() * self.jitter)
            time.sleep(delay)
            self.request_count += 1
    
    def get_stats(self):
        return {
            'enabled': self.enabled,
            'avg_delay': self.base_delay,
            'jitter': self.jitter,
            'requests_made': self.request_count
        }

def build_test_origins(custom_origin: Optional[str] = None, 
                       target_domain: Optional[str] = None) -> List[Dict[str, str]]:
    """Build comprehensive list of test origins for CORS testing"""
    
    origins = [
        # Basic tests
        {
            'name': 'Null Origin',
            'origin': 'null',
            'header': 'null',
            'description': 'Tests if null origin is accepted (file://, data:, etc.)'
        },
        {
            'name': 'Wildcard Origin',
            'origin': '*',
            'header': '*',
            'description': 'Tests if wildcard origin is reflected'
        },
        {
            'name': 'Origin Reflection',
            'origin': 'https://malicious-site.com',
            'header': 'https://malicious-site.com',
            'description': 'Tests if arbitrary origin is reflected in ACAO header'
        },
        
        # Bypass techniques
        {
            'name': 'Subdomain Wildcard',
            'origin': 'https://evil.example.com',
            'header': 'https://evil.example.com',
            'description': 'Tests subdomain takeover potential'
        },
        {
            'name': 'Prefix Match Bypass',
            'origin': 'https://evilattacker.com',
            'header': 'https://evilattacker.com',
            'description': 'Tests if prefix matching is vulnerable (e.g., trusted.com vs trusted.com.evil.com)'
        },
        {
            'name': 'Suffix Match Bypass',
            'origin': 'https://attackertrusted.com',
            'header': 'https://attackertrusted.com',
            'description': 'Tests if suffix matching is vulnerable'
        },
        {
            'name': 'HTTPS to HTTP Downgrade',
            'origin': 'http://trusted.com',
            'header': 'http://trusted.com',
            'description': 'Tests if HTTPS origin accepts HTTP (protocol downgrade)'
        },
        
        # Advanced tests
        {
            'name': 'IP Address Origin',
            'origin': 'http://192.168.1.1',
            'header': 'http://192.168.1.1',
            'description': 'Tests acceptance of IP-based origins (internal network)'
        },
        {
            'name': 'localhost Origin',
            'origin': 'http://localhost:8080',
            'header': 'http://localhost:8080',
            'description': 'Tests acceptance of localhost (SSRF potential)'
        },
        {
            'name': 'Domain with Port Variation',
            'origin': 'https://trusted.com:8443',
            'header': 'https://trusted.com:8443',
            'description': 'Tests if port is properly validated'
        },
        {
            'name': 'Unicode/IDN Homograph',
            'origin': 'https://еvil.com',  # Cyrillic 'е' instead of Latin 'e'
            'header': 'https://xn--vil-3cd.com',
            'description': 'Tests IDN homograph attack vectors'
        },
        {
            'name': 'Origin with Path',
            'origin': 'https://evil.com/path',
            'header': 'https://evil.com/path',
            'description': 'Tests if path is ignored in origin validation'
        },
        {
            'name': 'Origin with Query String',
            'origin': 'https://evil.com?trusted.com',
            'header': 'https://evil.com?trusted.com',
            'description': 'Tests query string injection in origin'
        },
        {
            'name': 'Origin with Fragment',
            'origin': 'https://evil.com#trusted.com',
            'header': 'https://evil.com#trusted.com',
            'description': 'Tests fragment injection in origin'
        },
        {
            'name': 'Data URI Origin',
            'origin': 'data:application/json',
            'header': 'data:application/json',
            'description': 'Tests data URI as origin'
        },
        {
            'name': 'About Blank Origin',
            'origin': 'about:blank',
            'header': 'about:blank',
            'description': 'Tests about:blank as origin'
        },
        {
            'name': 'JavaScript Origin',
            'origin': 'javascript:void(0)',
            'header': 'javascript:void(0)',
            'description': 'Tests javascript: scheme as origin'
        }
    ]
    
    # Add domain-specific tests if target domain is provided
    if target_domain:
        parsed = urlparse(target_domain)
        domain = parsed.netloc or parsed.path
        # Remove port if present
        domain = domain.split(':')[0]
        
        domain_tests = [
            {
                'name': 'Subdomain Attack',
                'origin': f'https://evil.{domain}',
                'header': f'https://evil.{domain}',
                'description': f'Tests subdomain takeover on {domain}'
            },
            {
                'name': 'Missing Dot Attack',
                'origin': f'https://{domain}evil.com',
                'header': f'https://{domain}evil.com',
                'description': 'Tests missing dot bypass'
            },
            {
                'name': '@ Symbol Injection',
                'origin': f'https://evil.com@{domain}',
                'header': f'https://evil.com@{domain}',
                'description': 'Tests @ symbol injection'
            },
            {
                'name': 'Backslash Injection',
                'origin': f'https://evil.com\\{domain}',
                'header': f'https://evil.com\\{domain}',
                'description': 'Tests backslash injection'
            }
        ]
        origins.extend(domain_tests)
    
    # Add custom origin if provided
    if custom_origin:
        origins.append({
            'name': 'Custom Origin',
            'origin': custom_origin,
            'header': custom_origin,
            'description': f'Custom test origin: {custom_origin}'
        })
    
    return origins

def analyze_regex_bypass(acao: str, origin: str, target_domain: str) -> Optional[Dict]:
    """Detect common regex bypass patterns in origin validation"""
    
    bypass_patterns = [
        # Bad regex patterns
        (r'^https?://.*\.trusted\.com$', f'https://evil.{target_domain}', 'DOT_WILDCARD_BYPASS'),
        (r'^https?://trusted\.com.*$', f'https://{target_domain}.evil.com', 'SUFFIX_BYPASS'),
        (r'^https?://[a-z]+\.trusted\.com$', f'https://123.{target_domain}', 'ALPHANUMERIC_LIMIT_BYPASS'),
        (r'^https?://trusted\.com(:[0-9]+)?$', f'https://{target_domain}.evil.com', 'PORT_REGEX_BYPASS'),
    ]
    
    for pattern, test_origin, bypass_type in bypass_patterns:
        if re.match(pattern, origin, re.IGNORECASE):
            return {
                'severity': 'HIGH',
                'type': bypass_type,
                'description': f'Regex bypass possible: {origin} matches vulnerable pattern {pattern}'
            }
    return None

def test_websocket_cors(url: str, origin: str, timeout: int = 5) -> Dict:
    """Test CORS in WebSocket connections"""
    try:
        # Convert http(s) to ws(s)
        ws_url = url.replace('https://', 'wss://').replace('http://', 'ws://')
        
        # Simple WebSocket handshake test using HTTP upgrade
        headers = {
            'Origin': origin,
            'Connection': 'Upgrade',
            'Upgrade': 'websocket',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13'
        }
        
        response = requests.get(ws_url, headers=headers, timeout=timeout, allow_redirects=False)
        
        # Check if WebSocket upgrade is accepted
        if response.status_code == 101:
            upgrade_headers = response.headers.get('Upgrade', '')
            if 'websocket' in upgrade_headers.lower():
                return {
                    'websocket_supported': True,
                    'origin_accepted': True,
                    'status': 'WEBSOCKET_UPGRADE_ACCEPTED',
                    'headers': dict(response.headers)
                }
        
        return {
            'websocket_supported': False,
            'origin_accepted': False,
            'status': 'WEBSOCKET_NOT_AVAILABLE'
        }
        
    except Exception as e:
        return {
            'websocket_supported': False,
            'error': str(e),
            'status': 'ERROR'
        }

def test_cors_endpoint(url: str, test_origin: Dict[str, str], timeout: int, 
                       auth_headers: Optional[Dict] = None, 
                       stealth: Optional[StealthMode] = None) -> Dict[str, Any]:
    """Test single origin against target URL with authentication support"""
    
    headers = {
        'Origin': test_origin['header'],
        'User-Agent': 'Mozilla/5.0 (CORS-Tester/2.0)',
        'Accept': 'application/json, text/html, */*',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    
    if auth_headers:
        headers.update(auth_headers)
    
    if stealth:
        stealth.wait()
    
    try:
        start = time.time()
        
        # Test with OPTIONS preflight
        options_response = requests.options(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            verify=False  # For testing only
        )
        
        # Test with GET
        get_response = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            verify=False
        )
        
        elapsed = time.time() - start
        
        # Collect headers from both responses (prefer OPTIONS if successful)
        response_to_analyze = options_response if options_response.status_code == 200 else get_response
        
        cors_headers = {
            'Access-Control-Allow-Origin': response_to_analyze.headers.get('Access-Control-Allow-Origin', 'NOT_PRESENT'),
            'Access-Control-Allow-Credentials': response_to_analyze.headers.get('Access-Control-Allow-Credentials', 'NOT_PRESENT'),
            'Access-Control-Allow-Methods': response_to_analyze.headers.get('Access-Control-Allow-Methods', 'NOT_PRESENT'),
            'Access-Control-Allow-Headers': response_to_analyze.headers.get('Access-Control-Allow-Headers', 'NOT_PRESENT'),
            'Access-Control-Expose-Headers': response_to_analyze.headers.get('Access-Control-Expose-Headers', 'NOT_PRESENT'),
            'Access-Control-Max-Age': response_to_analyze.headers.get('Access-Control-Max-Age', 'NOT_PRESENT'),
            'Vary': response_to_analyze.headers.get('Vary', 'NOT_PRESENT')
        }
        
        return {
            'test_name': test_origin['name'],
            'origin': test_origin['origin'],
            'description': test_origin['description'],
            'status_options': options_response.status_code,
            'status_get': get_response.status_code,
            'time': elapsed,
            'cors_headers': cors_headers,
            'response_size': len(response_to_analyze.content),
            'error': None
        }
        
    except requests.exceptions.Timeout:
        return {
            'test_name': test_origin['name'],
            'origin': test_origin['origin'],
            'error': 'TIMEOUT'
        }
    except requests.exceptions.ConnectionError:
        return {
            'test_name': test_origin['name'],
            'origin': test_origin['origin'],
            'error': 'CONNECTION_ERROR'
        }
    except Exception as e:
        return {
            'test_name': test_origin['name'],
            'origin': test_origin['origin'],
            'error': str(e)
        }

def analyze_cors_response(result: Dict[str, Any], target_url: str) -> Optional[List[Dict[str, Any]]]:
    """Analyze CORS response for vulnerabilities"""
    if result.get('error'):
        return None
    
    cors = result['cors_headers']
    acao = cors.get('Access-Control-Allow-Origin', '')
    acac = cors.get('Access-Control-Allow-Credentials', '')
    vary = cors.get('Vary', '')
    
    issues = []
    
    # Parse target domain for bypass detection
    parsed_target = urlparse(target_url)
    target_domain = parsed_target.netloc or parsed_target.path
    target_domain = target_domain.split(':')[0]
    
    # CRITICAL: Wildcard with credentials
    if acao == '*' and acac.lower() == 'true':
        issues.append({
            'severity': 'CRITICAL',
            'type': 'WILDCARD_WITH_CREDENTIALS',
            'description': 'Access-Control-Allow-Origin: * with Credentials: true allows any origin to access authenticated data. This is a critical misconfiguration.'
        })
    
    # CRITICAL: Null origin with credentials
    if acao == 'null' and acac.lower() == 'true':
        issues.append({
            'severity': 'CRITICAL',
            'type': 'NULL_ORIGIN_WITH_CREDENTIALS',
            'description': 'Null origin accepted with credentials - allows XSS/sandboxed iframe attacks to steal sensitive data.'
        })
    
    # HIGH: Arbitrary origin reflection with credentials
    if acao == result['origin'] and result['origin'] not in ['*', 'null'] and acac.lower() == 'true':
        issues.append({
            'severity': 'HIGH',
            'type': 'ARBITRARY_ORIGIN_REFLECTION_WITH_CREDENTIALS',
            'description': f'Arbitrary origin "{result["origin"]}" reflected with credentials. Any website can make authenticated requests.'
        })
    
    # HIGH: Null origin accepted
    if acao == 'null':
        issues.append({
            'severity': 'HIGH',
            'type': 'NULL_ORIGIN_ACCEPTED',
            'description': 'Null origin is accepted - potential for sandboxed iframe attacks and data theft.'
        })
    
    # HIGH: Sensitive headers exposed
    exposed_headers = cors.get('Access-Control-Expose-Headers', '')
    sensitive_headers = ['Authorization', 'Cookie', 'Set-Cookie', 'X-Session-ID', 'X-CSRF-Token', 'API-Key', 'X-API-Key']
    exposed = [h.strip() for h in exposed_headers.split(',') if h.strip() in sensitive_headers]
    if exposed:
        issues.append({
            'severity': 'HIGH',
            'type': 'SENSITIVE_HEADERS_EXPOSED',
            'description': f'Sensitive headers exposed to client-side JavaScript: {", ".join(exposed)}'
        })
    
    # MEDIUM: Wildcard origin
    if acao == '*':
        issues.append({
            'severity': 'MEDIUM',
            'type': 'WILDCARD_ORIGIN',
            'description': 'Wildcard origin (*) allows any website to read responses (without credentials).'
        })
    
    # MEDIUM: Origin reflection without proper Vary header
    if acao == result['origin'] and 'Origin' not in vary:
        issues.append({
            'severity': 'MEDIUM',
            'type': 'ORIGIN_REFLECTION_NO_VARY',
            'description': 'Origin reflected without Vary: Origin header - may cause cache poisoning attacks.'
        })
    
    # MEDIUM: Long preflight cache
    max_age = cors.get('Access-Control-Max-Age', '')
    if max_age and max_age != 'NOT_PRESENT':
        try:
            age = int(max_age)
            if age > 86400:  # 24 hours
                issues.append({
                    'severity': 'MEDIUM',
                    'type': 'LONG_PREFLIGHT_CACHE',
                    'description': f'Preflight cache duration is very long ({age} seconds) - may cause stale CORS policies to be cached.'
                })
            elif age > 3600:  # 1 hour
                issues.append({
                    'severity': 'LOW',
                    'type': 'MODERATE_PREFLIGHT_CACHE',
                    'description': f'Preflight cache duration is moderately long ({age} seconds).'
                })
        except ValueError:
            pass
    
    # MEDIUM: Arbitrary origin reflection (no credentials)
    if acao == result['origin'] and result['origin'] not in ['*', 'null'] and acac.lower() != 'true':
        issues.append({
            'severity': 'MEDIUM',
            'type': 'ARBITRARY_ORIGIN_REFLECTION',
            'description': f'Arbitrary origin "{result["origin"]}" reflected without credentials. Data can still be stolen from unauthenticated endpoints.'
        })
    
    # LOW: Overly permissive methods
    methods = cors.get('Access-Control-Allow-Methods', '')
    dangerous_methods = ['DELETE', 'PUT', 'PATCH', 'TRACE', 'CONNECT']
    found_methods = [m for m in dangerous_methods if m in methods.upper()]
    if found_methods:
        issues.append({
            'severity': 'LOW',
            'type': 'PERMISSIVE_METHODS',
            'description': f'Dangerous HTTP methods allowed: {", ".join(found_methods)}'
        })
    
    # Check for regex bypass patterns
    if acao != 'NOT_PRESENT' and acao != '*':
        bypass_issue = analyze_regex_bypass(acao, result['origin'], target_domain)
        if bypass_issue:
            issues.append(bypass_issue)
    
    # INFO: CORS headers present (normal)
    if acao != 'NOT_PRESENT':
        issues.append({
            'severity': 'INFO',
            'type': 'CORS_CONFIGURED',
            'description': f'CORS is configured: ACAO={acao}, ACAC={acac}'
        })
    
    return issues if issues else None

def run_cors_tests(url: str, test_origins: List[Dict[str, str]], timeout: int, 
                   verbose: bool, results: Results, stealth: Optional[StealthMode] = None,
                   auth_headers: Optional[Dict] = None, test_websocket: bool = False):
    """Run all CORS tests"""
    
    print(f"{Colors.BLUE}[*] Running {len(test_origins)} CORS tests against: {url}{Colors.RESET}\n")
    
    if stealth and stealth.enabled:
        print(f"{Colors.DIM}[*] Stealth mode enabled (delay: {stealth.base_delay}s ± {stealth.jitter}s){Colors.RESET}\n")
    
    for i, origin in enumerate(test_origins, 1):
        print(f"{Colors.CYAN}[{i}/{len(test_origins)}] Testing: {origin['name']}{Colors.RESET}")
        print(f"    Origin: {origin['origin']}")
        
        result = test_cors_endpoint(url, origin, timeout, auth_headers, stealth)
        
        if result.get('error'):
            print(f"    {Colors.RED}[!] Error: {result['error']}{Colors.RESET}")
            results.add_info(origin['name'], f"Error: {result.get('error')}", {})
            continue
        
        # Update performance metrics
        results.update_performance(result['time'])
        
        # Analyze for vulnerabilities
        issues = analyze_cors_response(result, url)
        
        if issues:
            for issue in issues:
                if issue['severity'] == 'CRITICAL':
                    print(f"    {Colors.RED}{Colors.BOLD}[CRITICAL]{Colors.RESET} {issue['type']}")
                    print(f"    {issue['description']}")
                    results.add_vulnerability(
                        origin['name'], 'CRITICAL', issue['description'],
                        result['cors_headers'], origin['origin'],
                        {'issue_type': issue['type']}
                    )
                elif issue['severity'] == 'HIGH':
                    print(f"    {Colors.RED}[HIGH]{Colors.RESET} {issue['type']}")
                    print(f"    {issue['description']}")
                    results.add_vulnerability(
                        origin['name'], 'HIGH', issue['description'],
                        result['cors_headers'], origin['origin'],
                        {'issue_type': issue['type']}
                    )
                elif issue['severity'] == 'MEDIUM':
                    print(f"    {Colors.YELLOW}[MEDIUM]{Colors.RESET} {issue['type']}")
                    print(f"    {issue['description']}")
                    results.add_warning(
                        origin['name'], issue['description'],
                        result['cors_headers'], 'MEDIUM'
                    )
                elif issue['severity'] == 'LOW':
                    print(f"    {Colors.CYAN}[LOW]{Colors.RESET} {issue['type']}")
                    print(f"    {issue['description']}")
                    results.add_warning(
                        origin['name'], issue['description'],
                        result['cors_headers'], 'LOW'
                    )
                else:
                    if verbose:
                        print(f"    {Colors.BLUE}[INFO]{Colors.RESET} {issue['description']}")
                    results.add_info(
                        origin['name'], issue['description'],
                        result['cors_headers']
                    )
        else:
            if verbose:
                print(f"    {Colors.GREEN}[✓] No issues detected{Colors.RESET}")
        
        print()
    
    # WebSocket tests if requested
    if test_websocket:
        print(f"{Colors.CYAN}[*] Testing WebSocket CORS...{Colors.RESET}")
        ws_results = test_websocket_cors(url, test_origins[0]['header'], timeout)
        if ws_results.get('websocket_supported'):
            print(f"    {Colors.YELLOW}[!] WebSocket endpoint detected with CORS{Colors.RESET}")
            results.add_info('WebSocket', 'WebSocket endpoint supports CORS', ws_results)
        else:
            print(f"    {Colors.GREEN}[✓] No WebSocket endpoints detected{Colors.RESET}")

def print_summary(results: Results, url: str, stealth: Optional[StealthMode] = None):
    """Print final summary and recommendations"""
    summary = results.get_summary()
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 CORS TEST SUMMARY{Colors.RESET}")
    print(f"{'='*70}")
    
    print(f"\n{Colors.BLUE}Target:{Colors.RESET} {url}")
    print(f"{Colors.BLUE}Tests Run:{Colors.RESET} {summary['tests_run']}")
    
    # Performance metrics
    perf = summary['performance']
    if perf['fastest_response'] != float('inf'):
        print(f"{Colors.BLUE}Response Times:{Colors.RESET}")
        print(f"  Fastest: {perf['fastest_response']:.3f}s")
        print(f"  Slowest: {perf['slowest_response']:.3f}s")
    
    if stealth and stealth.enabled:
        stealth_stats = stealth.get_stats()
        print(f"{Colors.BLUE}Stealth Mode:{Colors.RESET} Enabled")
        print(f"  Requests sent: {stealth_stats['requests_made']}")
    
    print(f"\n{Colors.BOLD}Findings:{Colors.RESET}")
    if summary['vulnerabilities_critical'] > 0:
        print(f"  {Colors.RED}🔴 CRITICAL:{Colors.RESET} {summary['vulnerabilities_critical']}")
    if summary['vulnerabilities_high'] > 0:
        print(f"  {Colors.RED}🔴 HIGH:{Colors.RESET} {summary['vulnerabilities_high']}")
    if summary['warnings_medium'] > 0:
        print(f"  {Colors.YELLOW}🟡 MEDIUM:{Colors.RESET} {summary['warnings_medium']}")
    if summary['warnings_low'] > 0:
        print(f"  {Colors.CYAN}🟡 LOW:{Colors.RESET} {summary['warnings_low']}")
    if summary['info'] > 0:
        print(f"  {Colors.BLUE}🔵 INFO:{Colors.RESET} {summary['info']}")
    
    # Risk assessment
    print(f"\n{Colors.BOLD}🎯 Risk Assessment:{Colors.RESET}")
    
    if summary['vulnerabilities_critical'] > 0:
        print(f"  {Colors.RED}{Colors.BOLD}[CRITICAL RISK]{Colors.RESET} {summary['vulnerabilities_critical']} critical issue(s) found")
        print(f"  {Colors.RED}Immediate remediation required! These issues can lead to complete account takeover.{Colors.RESET}")
    elif summary['vulnerabilities_high'] > 0:
        print(f"  {Colors.YELLOW}{Colors.BOLD}[HIGH RISK]{Colors.RESET} {summary['vulnerabilities_high']} high severity issue(s) found")
        print(f"  {Colors.YELLOW}Priority remediation recommended within 24-48 hours.{Colors.RESET}")
    elif summary['warnings_medium'] > 0:
        print(f"  {Colors.CYAN}[MEDIUM RISK]{Colors.RESET} {summary['warnings_medium']} medium severity warning(s) found")
        print(f"  {Colors.BLUE}Review and consider hardening in next development cycle.{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[LOW RISK]{Colors.RESET} No significant CORS issues detected")
    
    # Display critical/high findings
    critical_high = [v for v in summary['vulnerability_details'] 
                     if v.get('severity') in ['CRITICAL', 'HIGH']]
    
    if critical_high:
        print(f"\n{Colors.BOLD}📋 Critical/High Findings:{Colors.RESET}")
        for i, vuln in enumerate(critical_high[:5], 1):
            print(f"  {i}. [{vuln['severity']}] {vuln['test']}")
            print(f"     {vuln['description']}")
            print(f"     Origin: {vuln['origin']}")
            if vuln['headers'].get('Access-Control-Allow-Origin') != 'NOT_PRESENT':
                print(f"     ACAO: {vuln['headers']['Access-Control-Allow-Origin']}")
            if vuln['headers'].get('Access-Control-Allow-Credentials') != 'NOT_PRESENT':
                print(f"     ACAC: {vuln['headers']['Access-Control-Allow-Credentials']}")
            print()
    
    # Recommendations
    print(f"\n{Colors.BOLD}🔐 Security Recommendations:{Colors.RESET}")
    print(f"  • Never use Access-Control-Allow-Origin: * with credentials")
    print(f"  • Avoid reflecting arbitrary origins without strict validation")
    print(f"  • Never accept 'null' origin in production environments")
    print(f"  • Always include 'Vary: Origin' header when reflecting origins")
    print(f"  • Use a strict whitelist of trusted origins instead of regex patterns")
    print(f"  • Implement proper origin validation (exact match, not prefix/suffix)")
    print(f"  • Limit preflight cache duration to reasonable values (max 3600 seconds)")
    print(f"  • Avoid exposing sensitive headers via Access-Control-Expose-Headers")
    print(f"  • Consider using CORS preflight caching appropriately")
    
    # References
    print(f"\n{Colors.BOLD}📚 References:{Colors.RESET}")
    print(f"  • OWASP CORS Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html")
    print(f"  • PortSwigger CORS Vulnerabilities: https://portswigger.net/web-security/cors")
    print(f"  • MDN CORS Documentation: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS")
    print(f"  • CORS Security Guide: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors")
    
    print(f"\n{Colors.BLUE}📝 Note: This tool is for educational and authorized testing only.{Colors.RESET}")

def export_json_results(results: Results, output_file: str, url: str):
    """Export findings to JSON file"""
    summary = results.get_summary()
    report = {
        'timestamp': datetime.now().isoformat(),
        'target': url,
        'tool': 'cors_tester.py',
        'version': '2.0',
        'summary': {
            'tests_run': summary['tests_run'],
            'vulnerabilities': summary['vulnerabilities'],
            'vulnerabilities_critical': summary['vulnerabilities_critical'],
            'vulnerabilities_high': summary['vulnerabilities_high'],
            'warnings': summary['warnings'],
            'warnings_medium': summary['warnings_medium'],
            'warnings_low': summary['warnings_low'],
            'info': summary['info']
        },
        'performance': summary['performance'],
        'findings': {
            'vulnerabilities': summary['vulnerability_details'],
            'warnings': summary['warning_details'],
            'info': summary['info_details']
        }
    }
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"{Colors.GREEN}[✓] JSON report exported to: {output_file}{Colors.RESET}")
        return True
    except Exception as e:
        print(f"{Colors.RED}[!] Error exporting JSON report: {e}{Colors.RESET}")
        return False

def export_html_results(results: Results, output_file: str, url: str):
    """Generate interactive HTML report"""
    summary = results.get_summary()
    
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head
