from colorama import Fore
import requests
import argparse
import concurrent.futures
from tqdm import tqdm
import urllib.parse
import sys
import os

# Try to import banner
try:
    from banner import print_banner
except ImportError:
    def print_banner():
        print(f"{Fore.CYAN}SpringActuator Scanner - Spring Boot Actuator Endpoint Scanner{Fore.WHITE}")

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="Spring Boot Actuator Scanner - Detects exposed actuator endpoints")
parser.add_argument("-u", "--url", type=str, required=True, help="Target URL")
parser.add_argument("-w", "--wordlist", type=str, help="Custom wordlist for additional endpoints")
parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
parser.add_argument("-b", "--bypass", action="store_true", help="Enable WAF bypass techniques using URL encoding")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
args = parser.parse_args()

api_endpoints = [
    "/v1/actuator/heapdump",
    "/v1/actuator/prometheus",
    "/v1/actuator/metrics",
    "/v1/actuator/info",
    "/v1/actuator/health",
    "/v1/actuator/threaddump",
    "/v1/actuator/mappings",
    "/v1/actuator/conditions",
    "/v1/actuator/httptrace",
    "/v1/actuator/auditevents",
    "/v1/actuator/env",
    "/v1/actuator/beans",
    "/v1/actuator/caches",
    "/v2/actuator/heapdump",
    "/v2/actuator/prometheus",
    "/v2/actuator/metrics",
    "/v2/actuator/info",
    "/v2/actuator/health",
    "/v2/actuator/threaddump",
    "/v2/actuator/mappings",
    "/v2/actuator/conditions",
    "/v2/actuator/httptrace",
    "/v2/actuator/auditevents",
    "/v2/actuator/env",
    "/v2/actuator/beans",
    "/v2/actuator/caches",
    "/v2/actuator/scheduledtasks",
    "/v2/actuator/sessions",
    "/v2/actuator/shutdown",
    "/v2/actuator/trace"
]


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
    "/actuator/trace"
]

# Generate encoded variations of endpoints for WAF bypass
def generate_encoded_variations(endpoint):
    variations = [endpoint]  # Original endpoint
    
    # Standard URL encoding
    variations.append(urllib.parse.quote(endpoint))
    
    # Double URL encoding
    variations.append(urllib.parse.quote(urllib.parse.quote(endpoint)))
    
    # Partial URL encoding (encode only slashes)
    variations.append(endpoint.replace("/", "%2F"))
    
    # Partial URL encoding (encode only 'actuator')
    if 'actuator' in endpoint:
        variations.append(endpoint.replace("actuator", "%61%63%74%75%61%74%6F%72"))
    
    # Mixed case variations with encoding
    if 'actuator' in endpoint:
        mixed_case = endpoint.replace("actuator", "AcTuAtOr")
        variations.append(mixed_case)
        variations.append(urllib.parse.quote(mixed_case))
    
    return variations

# Wordlist
def wordlist(file: str) -> list:
    with open(file, 'r') as f:
        dirs = [x.strip() for x in f.readlines()]
        return dirs

# Try finding directory and filenames to use for actuator endpoints
def check_endpoint(url, endpoint):
    s = requests.Session()
    try:
        full_url = f"{url}/{endpoint}" if not endpoint.startswith('/') else f"{url}{endpoint}"
        r = s.head(full_url, verify=False, timeout=5)
        if r.status_code == 200:
            return full_url
        # Also try with GET for endpoints that might not respond to HEAD
        r = s.get(full_url, verify=False, timeout=5)
        if r.status_code == 200:
            return full_url
    except Exception:
        pass
    return None

def dirbrute_endpoints(url: str, file: str, threads=10, bypass=False) -> list:
    endpoints = wordlist(file)
    results = []
    all_endpoints = []
    
    # Generate encoded variations if bypass mode is enabled
    if bypass:
        for endpoint in endpoints:
            all_endpoints.extend(generate_encoded_variations(endpoint))
        print(f"{Fore.CYAN}Brute forcing endpoints with WAF bypass (URL encoding) using {threads} threads...{Fore.WHITE}")
    else:
        all_endpoints = endpoints
        print(f"{Fore.CYAN}Brute forcing endpoints with {threads} threads...{Fore.WHITE}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_endpoint = {executor.submit(check_endpoint, url, endpoint): endpoint for endpoint in all_endpoints}
        
        with tqdm(total=len(all_endpoints), desc="Scanning endpoints") as pbar:
            for future in concurrent.futures.as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                        print(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                except Exception as e:
                    if args.verbose:
                        print(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                finally:
                    pbar.update(1)
    
    return results

def check_endpoint_for_scan(base_url, endpoint):
    s = requests.Session()
    try:
        full_url = f"{base_url}{endpoint}"
        r = s.get(full_url, verify=False, timeout=5)
        if r.status_code == 200:
            return full_url
    except Exception:
        pass
    return None

def check_endpoints(url: str) -> tuple:
    # Store the original protocol
    protocol = "https://" if url.startswith("https://") else "http://"
    
    # Extract domain without protocol
    if "https://" in url:
        url_api = url.replace("https://", "")
    elif "http://" in url:
        url_api = url.replace("http://", "")
    elif "https://www." in url:
        url_api = url.replace("https://www.", "")
    elif "http://www." in url:
        url_api = url.replace("http://www.", "")
    else:
        url_api = url  

    if url_api.endswith("/"):
        url_api = url_api[:-1]
    
    if url.endswith("/"):
        url = url[:-1]
        
    check_api_subdomain = f"{protocol}api.{url_api}"
    
    s = requests.Session()

    try:
        r = s.get(f"{protocol}{url_api}", verify=False, timeout=5)
        if r.status_code == 200:
            return True, f"{protocol}{url_api}"
    except Exception as e:
        if args.verbose:
            print(f"Error checking base domain: {e}")
        pass
    
    try:
        r_api = s.get(f"{url}/api", verify=False, timeout=5)
        if r_api.status_code == 200:
            return True, f"{url}/api"
    except Exception as e:
        if args.verbose:
            print(f"Error checking API endpoint: {e}")
        pass

    return False, None

def scan(url: str, threads=10, bypass=False) -> list:
    success, endpoint_url = check_endpoints(url)
    results = []
    
    if success:
        if "api." in endpoint_url:
            all_endpoints = []
            
            # Generate encoded variations if bypass mode is enabled
            if bypass:
                print(f"{Fore.CYAN}Checking API subdomain endpoints with WAF bypass (URL encoding) using {threads} threads...{Fore.WHITE}")
                for endpoint in actuator_endpoints:
                    all_endpoints.extend(generate_encoded_variations(endpoint))
            else:
                print(f"{Fore.CYAN}Checking API subdomain endpoints with {threads} threads...{Fore.WHITE}")
                all_endpoints = actuator_endpoints
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_endpoint = {executor.submit(check_endpoint_for_scan, endpoint_url, endpoint): endpoint 
                                     for endpoint in all_endpoints}
                
                with tqdm(total=len(all_endpoints), desc="Scanning actuator endpoints") as pbar:
                    for future in concurrent.futures.as_completed(future_to_endpoint):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                                print(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                        except Exception as e:
                            endpoint = future_to_endpoint[future]
                            if args.verbose:
                                print(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                        finally:
                            pbar.update(1)
                            
        elif "/api" in endpoint_url:
            all_endpoints = []
            
            # Generate encoded variations if bypass mode is enabled
            if bypass:
                print(f"{Fore.CYAN}Checking API endpoints with WAF bypass (URL encoding) using {threads} threads...{Fore.WHITE}")
                for endpoint in api_endpoints:
                    all_endpoints.extend(generate_encoded_variations(endpoint))
            else:
                print(f"{Fore.CYAN}Checking API endpoints with {threads} threads...{Fore.WHITE}")
                all_endpoints = api_endpoints
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_endpoint = {executor.submit(check_endpoint_for_scan, endpoint_url, endpoint): endpoint 
                                     for endpoint in all_endpoints}
                
                with tqdm(total=len(all_endpoints), desc="Scanning API endpoints") as pbar:
                    for future in concurrent.futures.as_completed(future_to_endpoint):
                        try:
                            result = future.result()
                            if result:
                                results.append(result)
                                print(f"{Fore.GREEN}Found: {result}{Fore.WHITE}")
                        except Exception as e:
                            endpoint = future_to_endpoint[future]
                            if args.verbose:
                                print(f"{Fore.RED}Error checking {endpoint}: {e}{Fore.WHITE}")
                        finally:
                            pbar.update(1)
    
    return results

if __name__ == "__main__":
    # Display the banner
    print_banner()
    
    print(f"{Fore.CYAN}Scanning {args.url} for Spring Boot Actuator endpoints...{Fore.WHITE}")
    if args.bypass:
        print(f"{Fore.YELLOW}WAF bypass mode enabled - using URL encoding techniques{Fore.WHITE}")
    
    all_results = []
    
    actuator_results = scan(args.url, args.threads, args.bypass)
    all_results.extend(actuator_results)
    
    if args.wordlist:
        wordlist_results = dirbrute_endpoints(args.url, args.wordlist, args.threads, args.bypass)
        all_results.extend(wordlist_results)
    
    if all_results:
        print(f"\n{Fore.GREEN}Found {len(all_results)} vulnerable endpoint(s):{Fore.WHITE}")
        for result in all_results:
            print(f"{Fore.GREEN}- {result}{Fore.WHITE}")
    else:
        print(f"{Fore.RED}No vulnerable endpoints found{Fore.WHITE}")
        if not args.bypass:
            print(f"{Fore.YELLOW}Try running with the -b/--bypass flag to attempt WAF bypass with URL encoding{Fore.WHITE}")

    
    
    



