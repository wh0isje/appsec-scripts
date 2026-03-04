import requests
import argparse
import sys
from urllib.parse import urlparse

def check_headers(url, timeout=10):
    """Fetch headers from target URL"""
    headers = {
        "User-Agent": "Mozilla/5.0 (AppSec-Header-Checker)"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return {
            'status': response.status_code,
            'headers': response.headers,
            'url': response.url,
            'error': None
        }
    except requests.exceptions.Timeout:
        return {'error': 'TIMEOUT', 'status': None, 'headers': None}
    except requests.exceptions.ConnectionError:
        return {'error': 'CONNECTION_ERROR', 'status': None, 'headers': None}
    except requests.exceptions.RequestException as e:
        return {'error': str(e), 'status': None, 'headers': None}

def analyze_headers(headers):
    """Check security headers and return results"""
    security_headers = {
        'Strict-Transport-Security': {
            'description': 'Enforces HTTPS connections',
            'critical': True
        },
        'Content-Security-Policy': {
            'description': 'Prevents XSS and injection attacks',
            'critical': True
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME type sniffing',
            'critical': True
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'critical': True
        },
        'X-XSS-Protection': {
            'description': 'Legacy XSS filter (deprecated but still useful)',
            'critical': False
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'critical': False
        },
        'Permissions-Policy': {
            'description': 'Controls browser features/permissions',
            'critical': False
        }
    }
    
    results = []
    missing_critical = 0
    missing_optional = 0
    
    for header, info in security_headers.items():
        if header in headers:
            results.append({
                'header': header,
                'status': 'PRESENT',
                'value': headers[header][:50] + '...' if len(headers[header]) > 50 else headers[header],
                'critical': info['critical'],
                'description': info['description']
            })
        else:
            results.append({
                'header': header,
                'status': 'MISSING',
                'value': '-',
                'critical': info['critical'],
                'description': info['description']
            })
            if info['critical']:
                missing_critical += 1
            else:
                missing_optional += 1
    
    return results, missing_critical, missing_optional

def main():
    banner()
    
    # Argument parser
    parser = argparse.ArgumentParser(
        description='HTTP Security Headers Checker - Educational Purpose',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 check_headers.py -u https://example.com
  python3 check_headers.py -u https://api.example.com -v
        '''
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL to check')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show header values')
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[!] Invalid URL. Must start with http:// or https://{Colors.RESET}")
        sys.exit(1)
    
    # HTTPS warning
    if args.url.startswith('http://'):
        print(f"{Colors.YELLOW}[!] Warning: Target uses HTTP (not HTTPS){Colors.RESET}\n")
    
    print(f"{Colors.YELLOW}[+] Target:{Colors.RESET} {args.url}\n")
    
    # Fetch headers
    print(f"{Colors.BLUE}[*] Fetching headers...{Colors.RESET}")
    result = check_headers(args.url)
    
    if result.get('error'):
        print(f"{Colors.RED}[!] Error: {result['error']}{Colors.RESET}")
        sys.exit(1)
    
    print(f"    Status Code: {result['status']}")
    print(f"    Final URL: {result['url']}\n")
    
    # Analyze headers
    print(f"{Colors.BLUE}[*] Analyzing security headers...{Colors.RESET}\n")
    analysis, missing_critical, missing_optional = analyze_headers(result['headers'])
    
    # Display results
    for item in analysis:
        if item['status'] == 'PRESENT':
            icon = f"{Colors.GREEN}[+]{Colors.RESET}"
            status = f"{Colors.GREEN}PRESENT{Colors.RESET}"
        else:
            icon = f"{Colors.RED}[-]{Colors.RESET}"
            status = f"{Colors.RED}MISSING{Colors.RESET}"
        
        critical_marker = f"{Colors.YELLOW} [CRITICAL]{Colors.RESET}" if item['critical'] else ""
        
        print(f"{icon} {item['header']}{critical_marker}")
        print(f"    Status: {status}")
        print(f"    Description: {item['description']}")
        
        if args.verbose and item['status'] == 'PRESENT':
            print(f"    Value: {item['value']}")
        print()
    
    # Summary
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 SUMMARY{Colors.RESET}")
    print(f"{'='*60}")
    
    present = sum(1 for item in analysis if item['status'] == 'PRESENT')
    total = len(analysis)
    
    print(f"\nTotal Headers Checked: {total}")
    print(f"{Colors.GREEN}[+] Present:{Colors.RESET} {present}")
    print(f"{Colors.RED}[-] Missing:{Colors.RESET} {total - present}")
    print(f"    - Critical: {missing_critical}")
    print(f"    - Optional: {missing_optional}")
    
    # Risk assessment
    print(f"\n{Colors.BOLD}Risk Assessment:{Colors.RESET}")
    if missing_critical == 0:
        print(f"  {Colors.GREEN}[LOW] All critical headers present{Colors.RESET}")
    elif missing_critical <= 2:
        print(f"  {Colors.YELLOW}[MEDIUM] {missing_critical} critical header(s) missing{Colors.RESET}")
    else:
        print(f"  {Colors.RED}[HIGH] {missing_critical} critical headers missing{Colors.RESET}")
    
    print(f"\n{Colors.BLUE}📝 Note: This tool is for educational and authorized testing only.{Colors.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.RESET}")
        sys.exit(130)
