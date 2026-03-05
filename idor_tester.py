import requests
import argparse
import sys
import time
import re
import json
import threading
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional, List, Dict, Any

#Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

#Thread-safe statistics collector
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.errors = 0
        self.potential_idor = 0
        self.access_denied = 0
        self.response_times: List[float] = []
        self.findings: List[Dict[str, Any]] = []

    def add_result(self, test_id: str, status: int, response_time: float, 
                   content_length: int, is_potential_idor: bool, response_sample: str = ""):
        with self.lock:
            self.total += 1
            self.response_times.append(response_time)
            
            if 200 <= status < 300:
                self.success += 1
            elif status >= 400:
                self.errors += 1
            
            if is_potential_idor:
                self.potential_idor += 1
                self.findings.append({
                    'id': test_id,
                    'status': status,
                    'length': content_length,
                    'time': response_time,
                    'sample': response_sample[:200]
                })
            elif status in [401, 403, 404]:
                self.access_denied += 1

    def get_summary(self) -> Dict[str, Any]:
        avg_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        return {
            'total': self.total,
            'success': self.success,
            'errors': self.errors,
            'potential_idor': self.potential_idor,
            'access_denied': self.access_denied,
            'avg_time': avg_time,
            'findings': self.findings
        }

def load_wordlist(filepath: str) -> List[str]:
    """Load IDs from wordlist file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Wordlist not found: {filepath}{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading wordlist: {e}{Colors.RESET}")
        sys.exit(1)

def parse_range(range_str: str) -> List[str]:
    """Parse range like '1000-1010' or '1,2,3' or 'uuid1,uuid2'"""
    ids = []
    
    #Handle comma-separated list
    if ',' in range_str:
        return [i.strip() for i in range_str.split(',') if i.strip()]
    
    #Handle numeric range
    match = re.match(r'^(\d+)-(\d+)$', range_str)
    if match:
        start, end = int(match.group(1)), int(match.group(2))
        if end - start > 10000:
            print(f"{Colors.YELLOW}[!] Warning: Large range ({end-start+1} IDs). Consider narrowing.{Colors.RESET}")
        return [str(i) for i in range(start, end + 1)]
    
    #Single value
    return [range_str]

def build_headers(auth_headers: Optional[List[str]] = None) -> Dict[str, str]:
    """Build request headers with optional auth"""
    headers = {
        "User-Agent": "Mozilla/5.0 (IDOR-Tester/1.0)",
        "Accept": "application/json, text/html, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }
    
    if auth_headers:
        for header in auth_headers:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    return headers

def test_idor(url_template: str, test_id: str, headers: Dict[str, str], 
              timeout: int, baseline: Optional[Dict] = None) -> Dict[str, Any]:
    """Test single ID and compare with baseline if provided"""
    target_url = url_template.replace('{ID}', test_id).replace('{id}', test_id)
    
    try:
        start = time.time()
        response = requests.get(
            target_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            verify=True
        )
        elapsed = time.time() - start
        
        content = response.text
        is_potential_idor = False
        indicators = []
        
        #Detection logic
        #1. Status code analysis
        if response.status_code == 200:
            if baseline and baseline['status'] in [401, 403, 404]:
                is_potential_idor = True
                indicators.append("STATUS_DIFF_FROM_BASELINE")
        
        #2. Content length analysis
        if baseline and baseline['length'] > 0:
            length_diff = abs(len(content) - baseline['length'])
            if response.status_code == 200 and length_diff > 500:
                indicators.append(f"CONTENT_LENGTH_DIFF({length_diff})")
                if not is_potential_idor:
                    is_potential_idor = True
        
        #3. Keyword-based detection (sensitive data patterns)
        sensitive_patterns = [
            r'"email"\s*:', r'"password"\s*:', r'"token"\s*:',
            r'"api[_-]?key"\s*:', r'"secret"\s*:', r'"ssn"\s*:',
            r'"credit[_-]?card"\s*:', r'"cpf"\s*:', r'"phone"\s*:'
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, content, re.I):
                indicators.append("SENSITIVE_DATA_PATTERN")
                is_potential_idor = True
                break
        
        #4. Error messages that leak info
        leak_patterns = [r'user\s+not\s+found', r'invalid\s+id', r'access\s+denied', r'forbidden']
        for pattern in leak_patterns:
            if re.search(pattern, content, re.I):
                indicators.append("INFO_LEAKAGE_PATTERN")
                break
        
        return {
            'id': test_id,
            'url': target_url,
            'status': response.status_code,
            'length': len(content),
            'time': elapsed,
            'indicators': indicators,
            'is_potential_idor': is_potential_idor,
            'sample': content[:300]
        }
        
    except requests.exceptions.Timeout:
        return {'id': test_id, 'url': target_url, 'error': 'TIMEOUT', 'status': None}
    except requests.exceptions.ConnectionError:
        return {'id': test_id, 'url': target_url, 'error': 'CONNECTION_ERROR', 'status': None}
    except Exception as e:
        return {'id': test_id, 'url': target_url, 'error': str(e), 'status': None}

def run_idor_test(url_template: str, ids: List[str], headers: Dict[str, str],
                  timeout: int, threads: int, verbose: bool, 
                  baseline_id: Optional[str] = None) -> Stats:
    """Run IDOR test with threading support"""
    
    stats = Stats()
    lock = threading.Lock()
    
    #Establish baseline if requested
    baseline = None
    if baseline_id:
        print(f"{Colors.BLUE}[*] Establishing baseline with ID: {baseline_id}{Colors.RESET}")
        baseline_result = test_idor(url_template, baseline_id, headers, timeout)
        if baseline_result.get('error'):
            print(f"{Colors.YELLOW}[!] Baseline warning: {baseline_result.get('error')}{Colors.RESET}")
        else:
            baseline = {
                'status': baseline_result['status'],
                'length': baseline_result['length']
            }
            print(f"    Baseline: Status={baseline['status']}, Length={baseline['length']} bytes\n")
    
    print(f"{Colors.BLUE}[*] Testing {len(ids)} IDs with {threads} concurrent threads...{Colors.RESET}\n")
    
    def worker(test_ids: List[str]):
        for test_id in test_ids:
            result = test_idor(url_template, test_id, headers, timeout, baseline)
            
            if result.get('error'):
                stats.add_result(test_id, 0, 0, 0, False)
                if verbose:
                    print(f"{Colors.RED}[{test_id}] ERROR: {result['error']}{Colors.RESET}")
                continue
            
            stats.add_result(
                test_id,
                result['status'],
                result['time'],
                result['length'],
                result['is_potential_idor'],
                result.get('sample', '')
            )
            
            #Output based on result
            if result['is_potential_idor']:
                print(f"{Colors.GREEN}[{test_id}] {result['status']} {result['time']:.2f}s ⚠️ POTENTIAL IDOR{Colors.RESET}")
                if verbose:
                    print(f"    Indicators: {', '.join(result['indicators'])}")
                    print(f"    Sample: {result['sample'][:100]}...")
            elif result['status'] in [401, 403, 404]:
                if verbose:
                    print(f"{Colors.YELLOW}[{test_id}] {result['status']} {result['time']:.2f}s (Denied){Colors.RESET}")
            elif 200 <= result['status'] < 300:
                if verbose:
                    print(f"{Colors.CYAN}[{test_id}] {result['status']} {result['time']:.2f}s{Colors.RESET}")
            
            #Small delay to avoid overwhelming target
            time.sleep(0.05)
    
    #Distribute work across threads
    chunk_size = max(1, len(ids) // threads)
    chunks = [ids[i:i + chunk_size] for i in range(0, len(ids), chunk_size)]
    
    thread_list = []
    for chunk in chunks:
        t = threading.Thread(target=worker, args=(chunk,))
        t.start()
        thread_list.append(t)
    
    for t in thread_list:
        t.join()
    
    return stats

def print_summary(stats: Stats, url_template: str):
    """Print final summary and risk assessment"""
    summary = stats.get_summary()
    
    print(f"\n{Colors.BOLD}{'='*70}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 IDOR TEST SUMMARY{Colors.RESET}")
    print(f"{'='*70}")
    
    print(f"\n{Colors.BLUE}Target:{Colors.RESET} {url_template}")
    print(f"{Colors.BLUE}Requests:{Colors.RESET}")
    print(f"  Total:              {summary['total']}")
    print(f"  {Colors.GREEN}Success (2xx):{Colors.RESET}    {summary['success']}")
    print(f"  {Colors.RED}Errors (4xx/5xx):{Colors.RESET} {summary['errors']}")
    print(f"  {Colors.YELLOW}Access Denied:{Colors.RESET}  {summary['access_denied']}")
    
    print(f"\n{Colors.BLUE}Performance:{Colors.RESET}")
    avg_time = summary['avg_time']
    print(f"  Avg Response Time:  {avg_time:.2f}s")
    if avg_time > 0:
        print(f"  Est. Requests/sec:  {1/avg_time:.2f}")
    
    #IDOR findings
    print(f"\n{Colors.BOLD}🔍 IDOR Assessment:{Colors.RESET}")
    potential = summary['potential_idor']
    
    if potential == 0:
        print(f"  {Colors.GREEN}[✓] No potential IDOR vulnerabilities detected{Colors.RESET}")
        print(f"  {Colors.BLUE}💡 Tip: Try testing with different auth contexts or UUIDs{Colors.RESET}")
    elif potential <= 2:
        print(f"  {Colors.YELLOW}[⚠] {potential} potential IDOR finding(s) - manual validation recommended{Colors.RESET}")
        print(f"  {Colors.BLUE}💡 Tip: Verify authorization logic on server-side{Colors.RESET}")
    else:
        print(f"  {Colors.RED}[!] {potential} potential IDOR findings - investigate immediately{Colors.RESET}")
        print(f"  {Colors.BLUE}💡 Tip: Review object-level authorization implementation{Colors.RESET}")
    
    #Display findings if any
    if summary['findings']:
        print(f"\n{Colors.BOLD}📋 Potential Findings:{Colors.RESET}")
        for i, finding in enumerate(summary['findings'][:5], 1):  # Show top 5
            print(f"  {i}. ID: {finding['id']}")
            print(f"     Status: {finding['status']} | Length: {finding['length']} | Time: {finding['time']:.2f}s")
            if finding['sample']:
                print(f"     Preview: {finding['sample'][:80]}...")
        if len(summary['findings']) > 5:
            print(f"  ... and {len(summary['findings']) - 5} more (use --output for full report)")
    
    #Recommendations
    print(f"\n{Colors.BOLD}🔐 Security Recommendations:{Colors.RESET}")
    print(f"  • Implement server-side authorization checks for every object access")
    print(f"  • Use indirect reference maps (e.g., random UUIDs) instead of sequential IDs")
    print(f"  • Log and monitor unauthorized access attempts")
    print(f"  • Apply principle of least privilege to API endpoints")
    
    print(f"\n{Colors.BLUE}📝 Note: This tool is for educational and authorized testing only.{Colors.RESET}")

def export_results(stats: Stats, output_file: str):
    """Export findings to JSON file"""
    summary = stats.get_summary()
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': summary,
        'findings': summary.pop('findings', [])
    }
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"{Colors.GREEN}[✓] Report exported to: {output_file}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[!] Error exporting report: {e}{Colors.RESET}")

def main():
    banner()
    
    #Argument parser
    parser = argparse.ArgumentParser(
        description='IDOR/BOLA Testing Helper - Educational Purpose',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 idor_tester.py -u "https://api.example.com/users/{ID}" -r 1000-1010
  python3 idor_tester.py -u "https://api.example.com/orders/{id}" -w ids.txt
  python3 idor_tester.py -u "https://api.example.com/profile/{ID}" -r 100-110 -H "Authorization: Bearer xyz" -v
  python3 idor_tester.py -u "https://api.example.com/data/{ID}" -r 1-50 --baseline 999 -o report.json

Placeholders:
  Use {ID} or {id} in URL to mark where the test ID should be inserted

ID Sources:
  -r, --range: Numeric range (100-110) or comma-separated list (abc,def,ghi)
  -w, --wordlist: File with one ID per line

Exit Codes:
  0 = No critical findings
  1 = Potential IDOR vulnerabilities detected
  2 = Error during execution
        '''
    )
    
    #Required arguments
    parser.add_argument('-u', '--url', required=True, 
                       help='Target URL with {ID} placeholder (e.g., https://api.com/users/{ID})')
    
    #ID source (mutually exclusive)
    id_group = parser.add_mutually_exclusive_group(required=True)
    id_group.add_argument('-r', '--range', help='ID range: 100-110 or comma-separated: abc,def,ghi')
    id_group.add_argument('-w', '--wordlist', help='File with IDs (one per line)')
    
    #Optional arguments
    parser.add_argument('-H', '--header', action='append', dest='headers',
                       help='Additional header (can be used multiple times)')
    parser.add_argument('-b', '--baseline', help='ID to use as baseline for comparison')
    parser.add_argument('-t', '--threads', type=int, default=10, 
                       help='Concurrent threads (default: 10, max: 50)')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Verbose output')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--safe', action='store_true', 
                       help='Safe mode: only detect, no aggressive testing')
    
    args = parser.parse_args()
    
    #Validate URL
    if '{ID}' not in args.url and '{id}' not in args.url:
        print(f"{Colors.RED}[!] URL must contain {{ID}} or {{id}} placeholder{Colors.RESET}")
        print(f"    Example: https://api.example.com/users/{{ID}}")
        sys.exit(2)
    
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[!] Invalid URL. Must start with http:// or https://{Colors.RESET}")
        sys.exit(2)
    
    #Validate thread count
    args.threads = min(max(1, args.threads), 50)
    
    #Load IDs
    if args.range:
        ids = parse_range(args.range)
    else:
        ids = load_wordlist(args.wordlist)
    
    if not ids:
        print(f"{Colors.RED}[!] No IDs to test. Check your range or wordlist.{Colors.RESET}")
        sys.exit(2)
    
    print(f"{Colors.YELLOW}[+] Target Template:{Colors.RESET} {args.url}")
    print(f"{Colors.YELLOW}[+] IDs to Test:{Colors.RESET} {len(ids)}")
    if args.baseline:
        print(f"{Colors.YELLOW}[+] Baseline ID:{Colors.RESET} {args.baseline}")
    if args.headers:
        print(f"{Colors.YELLOW}[+] Auth Headers:{Colors.RESET} {len(args.headers)} configured")
    print()
    
    #Build headers
    headers = build_headers(args.headers)
    
    #Run test
    try:
        stats = run_idor_test(
            url_template=args.url.strip(),
            ids=ids,
            headers=headers,
            timeout=args.timeout,
            threads=args.threads,
            verbose=args.verbose,
            baseline_id=args.baseline
        )
        
        #Print summary
        print_summary(stats, args.url)
        
        #Export if requested
        if args.output:
            export_results(stats, args.output)
        
        #Exit code based on findings
        summary = stats.get_summary()
        if summary['potential_idor'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()
