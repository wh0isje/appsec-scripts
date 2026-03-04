import threading
import requests
import argparse
import time
import sys
from urllib.parse import urlparse
from datetime import datetime

#Thread-safe counter
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.errors = 0
        self.rate_limited = 0
        self.response_times = []

    def add_result(self, status_code, response_time, rate_limited=False):
        with self.lock:
            self.total += 1
            self.response_times.append(response_time)
            if rate_limited or status_code in [429, 503]:
                self.rate_limited += 1
            elif 200 <= status_code < 400:
                self.success += 1
            else:
                self.errors += 1

    def get_summary(self):
        avg_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        return {
            'total': self.total,
            'success': self.success,
            'errors': self.errors,
            'rate_limited': self.rate_limited,
            'avg_time': avg_time
        }

def send_request(url, thread_id, stats, headers, timeout):
    """Send a single request and record metrics"""
    try:
        start = time.time()
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        elapsed = time.time() - start
        
        #Detect rate limiting indicators
        rate_limited = (
            response.status_code == 429 or  # Too Many Requests
            response.status_code == 503 or  # Service Unavailable
            'rate limit' in response.text.lower() or
            'too many requests' in response.text.lower()
        )
        
        stats.add_result(response.status_code, elapsed, rate_limited)
        
        #Output based on verbosity
        if rate_limited:
            print(f"{Colors.YELLOW}[{thread_id:02d}] {response.status_code} {elapsed:.2f}s ⚠️ RATE LIMITED{Colors.RESET}")
        elif 200 <= response.status_code < 300:
            print(f"{Colors.GREEN}[{thread_id:02d}] {response.status_code} {elapsed:.2f}s{Colors.RESET}")
        elif 400 <= response.status_code < 500:
            print(f"{Colors.RED}[{thread_id:02d}] {response.status_code} {elapsed:.2f}s{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}[{thread_id:02d}] {response.status_code} {elapsed:.2f}s{Colors.RESET}")
            
    except requests.exceptions.Timeout:
        stats.add_result('TIMEOUT', timeout)
        print(f"{Colors.RED}[{thread_id:02d}] TIMEOUT{Colors.RESET}")
    except requests.exceptions.ConnectionError:
        stats.add_result('CONNECTION_ERROR', 0)
        print(f"{Colors.RED}[{thread_id:02d}] CONNECTION ERROR{Colors.RESET}")
    except Exception as e:
        stats.add_result('ERROR', 0)
        print(f"{Colors.RED}[{thread_id:02d}] ERROR: {e}{Colors.RESET}")

def test_rate_limit(url, num_threads, delay=0, verbose=False, timeout=10):
    """Run concurrent requests to test rate limiting"""
    
    headers = {
        "User-Agent": "Mozilla/5.0 (RateLimit-Tester)",
        "Accept": "*/*"
    }
    
    stats = Stats()
    threads = []
    
    print(f"{Colors.BLUE}[*] Starting {num_threads} concurrent requests to:{Colors.RESET} {url}\n")
    
    start_time = time.time()
    
    #Create and start threads
    for i in range(num_threads):
        thread = threading.Thread(
            target=send_request, 
            args=(url, i, stats, headers, timeout)
        )
        threads.append(thread)
        thread.start()
        
        #Optional delay between thread starts (for controlled bursts)
        if delay > 0:
            time.sleep(delay)
    
    #Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    total_time = time.time() - start_time
    return stats, total_time

def print_summary(stats, total_time):
    """Print final summary and rate limit assessment"""
    summary = stats.get_summary()
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}📊 TEST SUMMARY{Colors.RESET}")
    print(f"{'='*60}")
    
    print(f"\n{Colors.BLUE}Requests:{Colors.RESET}")
    print(f"  Total:      {summary['total']}")
    print(f"  {Colors.GREEN}Success (2xx):{Colors.RESET}  {summary['success']}")
    print(f"  {Colors.RED}Errors (4xx/5xx):{Colors.RESET} {summary['errors']}")
    print(f"  {Colors.YELLOW}Rate Limited:{Colors.RESET}  {summary['rate_limited']}")
    
    print(f"\n{Colors.BLUE}Performance:{Colors.RESET}")
    print(f"  Total Time:     {total_time:.2f}s")
    print(f"  Avg Response:   {summary['avg_time']:.2f}s")
    print(f"  Requests/sec:   {summary['total']/total_time:.2f}" if total_time > 0 else "  Requests/sec: N/A")
    
    #Rate limit assessment
    print(f"\n{Colors.BOLD}Rate Limit Assessment:{Colors.RESET}")
    rate_limit_pct = (summary['rate_limited'] / summary['total'] * 100) if summary['total'] > 0 else 0
    
    if summary['rate_limited'] == 0:
        print(f"  {Colors.GREEN}[✓] No rate limiting detected{Colors.RESET}")
        print(f"  {Colors.YELLOW}💡 Tip: Try increasing threads or adding authentication{Colors.RESET}")
    elif rate_limit_pct < 25:
        print(f"  {Colors.YELLOW}[⚠] Weak rate limiting ({rate_limit_pct:.1f}% blocked){Colors.RESET}")
        print(f"  {Colors.BLUE}💡 Tip: Test with sustained load or authenticated requests{Colors.RESET}")
    elif rate_limit_pct < 75:
        print(f"  {Colors.CYAN}[!] Moderate rate limiting ({rate_limit_pct:.1f}% blocked){Colors.RESET}")
        print(f"  {Colors.BLUE}💡 Tip: Analyze headers for retry-after or limit info{Colors.RESET}")
    else:
        print(f"  {Colors.RED}[🔒] Strong rate limiting ({rate_limit_pct:.1f}% blocked){Colors.RESET}")
        print(f"  {Colors.BLUE}💡 Tip: Check for bypass techniques or enumeration vectors{Colors.RESET}")
    
    #Check for useful headers
    print(f"\n{Colors.BLUE}🔍 Hint: Check response headers for:{Colors.RESET}")
    print(f"  - X-RateLimit-Limit")
    print(f"  - X-RateLimit-Remaining")
    print(f"  - X-RateLimit-Reset")
    print(f"  - Retry-After")
    
    print(f"\n{Colors.BLUE}📝 Note: This tool is for educational and authorized testing only.{Colors.RESET}")

def main():
    banner()
    
    #Argument parser
    parser = argparse.ArgumentParser(
        description='Rate Limit Testing Helper - Educational Purpose',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 multithread_rate_limit.py -u https://api.example.com/login
  python3 multithread_rate_limit.py -u https://api.example.com/otp -t 50
  python3 multithread_rate_limit.py -u https://api.example.com/reset -t 30 -d 0.1 -v
        '''
    )
    parser.add_argument('-u', '--url', required=True, help='Target endpoint URL')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Number of concurrent threads (default: 20)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Delay between thread starts in seconds (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    args = parser.parse_args()
    
    #Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[!] Invalid URL. Must start with http:// or https://{Colors.RESET}")
        sys.exit(1)
    
    #Validate thread count
    if args.threads < 1 or args.threads > 200:
        print(f"{Colors.RED}[!] Thread count must be between 1 and 200{Colors.RESET}")
        sys.exit(1)
    
    #HTTPS warning
    if args.url.startswith('http://'):
        print(f"{Colors.YELLOW}[!] Warning: Target uses HTTP (not HTTPS){Colors.RESET}\n")
    
    #Run test
    try:
        stats, total_time = test_rate_limit(
            url=args.url.strip(),
            num_threads=args.threads,
            delay=args.delay,
            verbose=args.verbose,
            timeout=args.timeout
        )
        print_summary(stats, total_time)
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Interrupted by user. Exiting...{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
