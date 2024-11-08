from colorama import Fore
from datetime import datetime
import requests
import argparse
import concurrent.futures
import urllib3

urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='Heapdump scanner')
parser.add_argument('--url', help='URL to scan')
parser.add_argument('--file', help='File containing domains')
parser.add_argument('--timeout', help='Timeout for requests', default=5)
parser.add_argument('--workers', help='Number of workers', default=10)
args = parser.parse_args()

actuator_endpoints = [
    "/actuator/heapdump",
    "/actuator/prometheus",
    "/actuator/metrics",
    "/actuator/info",
    "/actuator/health",
    "/actuator/logfile",
    "/actuator/loggers",
    "/actuator/threaddump",
    "/actuator/mappings",
    "/actuator/conditions",
    "/actuator/httptrace",
    "/actuator/auditevents",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/caches",
    "/actuator/scheduledtasks",
    "/actuator/sessions",
    "/actuator/shutdown",
    "/actuator/threaddump",
    "/actuator/trace",
]

def scanner(url: str) -> tuple[bool, str]:
    s = requests.Session()
    for endpoint in actuator_endpoints:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        r = s.get(f"{url}{endpoint}", timeout=int(args.timeout), headers=headers, verify=False)
        if r.status_code == 200:
            content_type = r.headers.get('Content-Type', '')
            
            # Binary content endpoints
            if endpoint == "/actuator/heapdump" and 'application/octet-stream' in content_type:
                    return True, endpoint
            
            # Plain text endpoints
            elif endpoint == "/actuator/logfile" and 'text/plain' in content_type:
                return True, endpoint
            
            # Prometheus endpoint
            elif endpoint == "/actuator/prometheus" and 'text/plain' in content_type:
                return True, endpoint
            
            # JSON endpoints (both standard and actuator-specific formats)
            elif any(ct in content_type for ct in [
                'application/json',
                'application/vnd.spring-boot.actuator.v1+json',
                'application/vnd.spring-boot.actuator.v2+json',
                'application/vnd.spring-boot.actuator.v3+json'
            ]) and endpoint in [
                "/actuator/metrics",
                "/actuator/info",
                "/actuator/health",
                "/actuator/loggers",
                "/actuator/threaddump",
                "/actuator/mappings",
                "/actuator/conditions",
                "/actuator/httptrace",
                "/actuator/auditevents",
                "/actuator/env",
                "/actuator/beans",
                "/actuator/caches",
                "/actuator/scheduledtasks",
                "/actuator/sessions",
                "/actuator/shutdown",
                "/actuator/trace"
            ]:
                # Additional validation for JSON endpoints
                try:
                    response_json = r.json()
                    if "404" in response_json.lower() or "not found" in response_json.lower():
                        return False, endpoint
                    if isinstance(response_json, (dict, list)) and response_json:  # Ensure non-empty response
                        return True, endpoint
                except:
                    pass
                    
        if r.status_code == 404:
                return False, endpoint
    return False, ""

def save_result(domain: str, endpoint: str):
    """Save valid results to a file"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"valid_actuators_{timestamp}.txt"
    
    with open(filename, 'a') as f:
        f.write(f"{domain} - {endpoint}\n")

def file_scanner(domain: str) -> bool:
    try:
        success, endpoint = scanner(domain)
        if success:
            print(f"{Fore.GREEN}[+] {Fore.WHITE}{domain} - {Fore.CYAN}{endpoint}{Fore.RESET}")
            save_result(domain, endpoint)
        else:
            print(f"{Fore.RED}[-] {Fore.WHITE}{domain}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] {Fore.WHITE}{domain}{Fore.RESET}")

if __name__ == "__main__":
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"valid_actuators_{timestamp}.txt"
    print(f"{Fore.CYAN}[*] Results will be saved to: {Fore.WHITE}{filename}{Fore.RESET}\n")

    if args.file:
        print(f"{Fore.CYAN}[*] Scanning {Fore.WHITE}{args.file}{Fore.RESET}\n")
        try:
            with open(args.file, 'r') as f:
                domains = [x.strip() for x in f.readlines()]
            with concurrent.futures.ThreadPoolExecutor(max_workers=int(args.workers)) as executor:
                executor.map(file_scanner, domains)
        except Exception as e:
            print(f"{Fore.RED}[-] Error reading file {args.file}: {str(e)}{Fore.RESET}")
    elif args.url:
        print(f"{Fore.CYAN}[*] Scanning {Fore.WHITE}{args.url}{Fore.RESET}\n")
        success, endpoint = scanner(args.url)
        if success:
            print(f"{Fore.GREEN}[+] {Fore.WHITE}{args.url} - {endpoint}{Fore.RESET}")
            save_result(args.url, endpoint)