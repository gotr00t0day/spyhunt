import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from alive_progress import alive_bar
import threading
import concurrent.futures
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.features.forbidden_pages import save_forbidden_pages
from core.features.not_found import get_results
from core.features.api_fuzzer import check_endpoint
from core.features.directorybrute import filter_wordlist, dorequests
from core.features.param_miner import scan_common_parameters, extract_parameters_from_html, brute_force_parameter
from core.features.custom_headers import send_request, load_headers_from_file
from core.features.automoussystemnumber import process_asn
from core.features.autorecon import main_autorecon

def run(args):
        
    if args.forbidden_pages:
        try:
            s = requests.Session()
            with open(f"{args.forbidden_pages}") as f:
                pages = [x.strip() for x in f.readlines()]

            for page in pages:
                r = s.get(page, verify=False, timeout=10)
                if r.status_code == 403:
                    print(f"{Fore.RED}{page} [{r.status_code}]{Style.RESET_ALL}")
                    save_forbidden_pages(page)
                else:
                    pass
        except requests.exceptions.ReadTimeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.RequestException:
            pass

    if args.not_found:
        session = requests.Session()
        session.headers.update(header)
        with open(args.not_found, "r") as f:
            links = (f"{x.strip()}" for x in f.readlines())
            output_file = "results.txt"
            get_results(links, output_file, session)

    if args.api_fuzzer:
        with open("core/groups/payloads/api-endpoints.txt", "r") as file:
            api_endpoints = [x.strip() for x in file.readlines()]
        
        print(f"Scanning {len(api_endpoints)} endpoints for {args.api_fuzzer}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_endpoint, endpoint, args) for endpoint in api_endpoints]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    if result.startswith(Fore.GREEN):
                        print(result)
                else:
                    pass

    if args.directorybrute:
        if args.wordlist:
            if args.threads:
                with open(args.wordlist, "r") as f:
                    wordlist_ = [x.strip() for x in f.readlines()]
                
                is_file_only = bool(args.extensions)
                
                filtered_wordlist = filter_wordlist(wordlist_, args.extensions)
                
                excluded_codes = set(int(code.strip()) for code in args.exclude.split(',') if code.strip())
                
                print(f"Target: {Fore.CYAN}{args.directorybrute}{Fore.RESET}\n"
                    f"Wordlist: {Fore.CYAN}{args.wordlist}{Fore.RESET}\n"
                    f"Extensions: {Fore.CYAN}{args.extensions or 'All'}{Fore.RESET}\n"
                    f"Excluded Status Codes: {Fore.CYAN}{', '.join(map(str, excluded_codes)) or 'None'}{Fore.RESET}\n")

                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

                print_lock = threading.Lock()

                with alive_bar(len(filtered_wordlist), title="Scanning", bar="classic", spinner="classic") as bar:
                    with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
                        futures = [executor.submit(dorequests, wordlist, args.directorybrute, headers, is_file_only, excluded_codes, bar, print_lock) 
                                for wordlist in filtered_wordlist]
                        
                        for future in as_completed(futures):
                            future.result()

    if args.param_miner:
        try:
            #main(args.param_miner, args.wordlist, args.concurrency)
            url = args.param_miner
            wordlist = args.wordlist
            threads = args.concurrency
            print(f"{Fore.BLUE}[*] Starting parameter mining on: {url}{Style.RESET_ALL}")
            
            original_response = requests.get(url, timeout=5)
            
            print(f"{Fore.MAGENTA}[*] Scanning for common parameters...{Style.RESET_ALL}")
            common_params = scan_common_parameters(url)
            
            print(f"{Fore.MAGENTA}[*] Extracting parameters from HTML and JavaScript...{Style.RESET_ALL}")
            extracted_params = extract_parameters_from_html(url)
            
            with open(wordlist, 'r') as file:
                wordlist_params = [line.strip() for line in file]
            all_params = list(set(wordlist_params + extracted_params + common_params))
            
            print(f"{Fore.BLUE}[*] Testing {len(all_params)} unique parameters...{Style.RESET_ALL}")
            
            reflected_params = []
            potential_params = []
            status_changed_params = []
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [executor.submit(brute_force_parameter, url, param, original_response) for param in all_params]
                for future in as_completed(futures):
                    result, category = future.result()
                    if result:
                        if category == "reflected":
                            reflected_params.append(result)
                        elif category == "potential":
                            potential_params.append(result)
                        elif category == "status_changed":
                            status_changed_params.append(result)
            
            print(f"\n{Fore.GREEN}[+] Reflected parameters: {', '.join(reflected_params)}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[*] Potential parameters: {Fore.YELLOW}{', '.join(potential_params)}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[*] Status-changing parameters: {Fore.CYAN}{', '.join(status_changed_params)}{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"{Fore.RED}Scan interrupted by user.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")

    if args.custom_headers:
        if args.custom_headers:
                if args.verbose:
                    print(f"{Fore.CYAN}Verbose mode enabled{Style.RESET_ALL}")
                url = args.custom_headers
                verbose = args.verbose
                session = requests.Session()
                
                while True:
                    print(f"\n{Fore.YELLOW}Current URL: {url}{Style.RESET_ALL}")
                    print(f"\n{Fore.YELLOW}Options:{Style.RESET_ALL}")
                    print("1. Send GET request with default headers")
                    print("2. Send GET request with custom headers")
                    print("3. Send POST request")
                    print("4. Send request with custom method and headers")
                    print("5. Change URL")
                    print("6. Load headers from file")
                    print("7. Set authentication")
                    print("8. Set proxy")
                    print("9. Toggle redirect following")
                    print("10. Save last response to file")
                    print("11. Exit")
                    
                    choice = input(f"{Fore.CYAN}Enter your choice (1-11): {Style.RESET_ALL}")
                    
                    if choice == '1':
                        send_request(url, verbose=verbose)
                    elif choice == '2':
                        custom_headers = {}
                        print(f"{Fore.YELLOW}Enter custom headers (one per line, format 'Key: Value'). Type 'done' when finished.{Style.RESET_ALL}")
                        while True:
                            header = input()
                            if header.lower() == 'done':
                                break
                            key, value = header.split(': ', 1)
                            custom_headers[key] = value
                        send_request(url, custom_headers=custom_headers, verbose=verbose)
                    elif choice == '3':
                        data = input(f"{Fore.CYAN}Enter POST data (JSON format): {Style.RESET_ALL}")
                        send_request(url, method='POST', data=json.loads(data), verbose=verbose)
                    elif choice == '4':
                        method = input(f"{Fore.CYAN}Enter HTTP method: {Style.RESET_ALL}").upper()
                        custom_headers = {}
                        print(f"{Fore.YELLOW}Enter custom headers (one per line, format 'Key: Value'). Type 'done' when finished.{Style.RESET_ALL}")
                        while True:
                            header = input()
                            if header.lower() == 'done':
                                break
                            key, value = header.split(': ', 1)
                            custom_headers[key] = value
                        send_request(url, method=method, custom_headers=custom_headers, verbose=verbose)
                    elif choice == '5':
                        url = input(f"{Fore.CYAN}Enter the new URL to check: {Style.RESET_ALL}")
                    elif choice == '6':
                        filename = input(f"{Fore.CYAN}Enter the filename to load headers from: {Style.RESET_ALL}")
                        custom_headers = load_headers_from_file(filename)
                        send_request(url, custom_headers=custom_headers, verbose=verbose)
                    elif choice == '7':
                        username = input(f"{Fore.CYAN}Enter username: {Style.RESET_ALL}")
                        password = input(f"{Fore.CYAN}Enter password: {Style.RESET_ALL}")
                        send_request(url, auth=(username, password), verbose=verbose)
                    elif choice == '8':
                        proxy = input(f"{Fore.CYAN}Enter proxy URL: {Style.RESET_ALL}")
                        send_request(url, proxies={'http': proxy, 'https': proxy}, verbose=verbose)
                    elif choice == '9':
                        allow_redirects = input(f"{Fore.CYAN}Allow redirects? (y/n): {Style.RESET_ALL}").lower() == 'y'
                        send_request(url, allow_redirects=allow_redirects, verbose=verbose)
                    elif choice == '10':
                        filename = input(f"{Fore.CYAN}Enter filename to save response: {Style.RESET_ALL}")
                        response = send_request(url, verbose=verbose)
                        if response:
                            with open(filename, 'w') as f:
                                json.dump(response.json(), f, indent=2)
                            print(f"{Fore.GREEN}Response saved to {filename}{Style.RESET_ALL}")
                    elif choice == '11':
                        print(f"{Fore.GREEN}Exiting. Goodbye!{Style.RESET_ALL}")
                        break
                    else:
                        print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

    if args.automoussystemnumber:
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
            future_to_asn = {executor.submit(process_asn, asn): asn for asn in args.automoussystemnumber}
            for future in concurrent.futures.as_completed(future_to_asn):
                asn, ip_ranges = future.result()
                results[asn] = ip_ranges

        total_ranges = sum(len(ranges) for ranges in results.values())
        print(f"\nFound a total of {total_ranges} IP ranges across {len(args.automoussystemnumber)} ASNs:")

        if args.save:
            with open(args.save, 'w') as f:
                for asn, ranges in results.items():
                    if ranges:
                        f.write(f"AS{asn}:\n")
                        for range in ranges:
                            f.write(f"{range}\n")
                        f.write("\n")
            print(f"Results saved to {args.save}")
        else:
            for asn, ranges in results.items():
                if ranges:
                    print(f"\nAS{asn}:")
                    for range in ranges:
                        print(range)

    if args.autorecon:
        target_url = args.autorecon
        asyncio.run(main_autorecon(target_url))
