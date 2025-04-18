import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore
from urllib.parse import urlparse, urlencode, parse_qs, quote_plus
from alive_progress import alive_bar
from ratelimit import limits, sleep_and_retry
import os
import re
import random
import string
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.utils import header

# Define rate limit: 5 calls per second
CALLS = 5
RATE_LIMIT = 1

@sleep_and_retry
@limits(calls=CALLS, period=RATE_LIMIT)
def rate_limited_request(url, headers, timeout):
    return requests.get(url, verify=False, headers=headers, timeout=timeout)

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encode_payload(payload):
    encodings = [
        lambda x: x,  # No encoding
        lambda x: quote_plus(x),  # URL encoding
        lambda x: html.escape(x),  # HTML entity encoding
        lambda x: ''.join(f'%{ord(c):02X}' for c in x),  # Full URL encoding
        lambda x: ''.join(f'&#x{ord(c):02X};' for c in x),  # Hex entity encoding
        lambda x: ''.join(f'\\u{ord(c):04X}' for c in x),  # Unicode escape
    ]
    return random.choice(encodings)(payload)

def print_vulnerability(vuln):
    if vuln['execution_likelihood'] == 'High':
        print(f"\n{Fore.RED}High likelihood XSS vulnerability found:{Fore.RESET}")
        print(f"URL: {Fore.CYAN}{vuln['url']}{Fore.RESET}")
        print(f"Parameter: {Fore.YELLOW}{vuln['parameter']}{Fore.RESET}")
        print(f"Payload: {Fore.MAGENTA}{vuln['payload']}{Fore.RESET}")
        print(f"Test URL: {Fore.BLUE}{vuln['test_url']}{Fore.RESET}")

def xss_scan_url(url, payloads, bar):
    print(f"{Fore.CYAN}Scanning for XSS vulnerabilities: {Fore.GREEN}{url}{Fore.RESET}")
    
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    vulnerabilities = []
    
    for param in params:
        for payload in payloads:
            random_string = generate_random_string()
            test_payload = payload.replace("XSS", random_string)
            encoded_payload = encode_payload(test_payload)
            
            test_params = params.copy()
            test_params[param] = [encoded_payload]
            test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
            
            try:
                response = rate_limited_request(test_url, headers=header, timeout=10)
                response_text = response.text.lower()
                
                if random_string.lower() in response_text:
                    vulnerability = {
                        "url": url,
                        "parameter": param,
                        "payload": encoded_payload,
                        "test_url": test_url
                    }
                    pattern_script = r'<script>.*?alert\([\'"]{}[\'"]\).*?</script>'.format(re.escape(random_string))
                    pattern_event = r'on\w+\s*=.*?alert\([\'"]{}[\'"]\)'.format(re.escape(random_string))
                    if re.search(pattern_script, response_text, re.IGNORECASE | re.DOTALL) or \
                        re.search(pattern_event, response_text, re.IGNORECASE):
                        vulnerability["execution_likelihood"] = "High"
                        vulnerabilities.append(vulnerability)
                        print_vulnerability(vulnerability)
            except requests.RequestException as e:
                print(f"{Fore.YELLOW}Error scanning {test_url}: {str(e)}{Fore.RESET}")
            finally:
                bar()  # Increment the progress bar for each payload scanned
    
    return vulnerabilities

def xss_scanner(args):
    target = args.xss_scan
    if os.path.isfile(target):
        with open(target, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
        
        with open("payloads/xss.txt", "r") as f:
            payloads = [x.strip() for x in f.readlines()]
        
        total_payloads = 0
        # Calculate total payloads based on number of URLs and number of payloads per URL
        for url in urls:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            total_payloads += len(params) * len(payloads)
        
        all_vulnerabilities = []
        with alive_bar(total_payloads, title="Scanning XSS Vulnerabilities") as bar:
            with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                future_to_url = {executor.submit(xss_scan_url, url, payloads, bar): url for url in urls}
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        vulnerabilities = future.result()
                        all_vulnerabilities.extend(vulnerabilities)
                    except Exception as exc:
                        print(f'{Fore.RED}Error scanning {url}: {exc}{Fore.RESET}')
        
        return all_vulnerabilities
    else:
        target_url = target
        with open("payloads/xss.txt", "r") as f:
            payloads = [x.strip() for x in f.readlines()]
        
        params = parse_qs(urlparse(target_url).query)
        total_payloads = len(params) * len(payloads)
        
        all_vulnerabilities = []
        with alive_bar(total_payloads, title="Scanning XSS Vulnerabilities") as bar:
            vulnerabilities = xss_scan_url(target_url, payloads, bar)
            all_vulnerabilities.extend(vulnerabilities)
        
        return all_vulnerabilities
