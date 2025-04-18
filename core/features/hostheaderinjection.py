from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(action='ignore',module='bs4')

import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
import random

def setup_proxies(proxy=None, proxy_file=None):
    """Setup proxy configuration"""
    proxies = []
    if proxy:
        if not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
            proxy = f"http://{proxy}"
        proxies.append({'http': proxy, 'https': proxy})
        
    if proxy_file:
        try:
            with open(proxy_file, 'r') as f:
                for line in f:
                    if line.strip():
                        proxy = line.strip()
                        if not proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                            proxy = f"http://{proxy}"
                        proxies.append({'http': proxy, 'https': proxy})
        except Exception as e:
            print(f"{Fore.RED}Error loading proxy file: {str(e)}{Style.RESET_ALL}")
    return proxies

def check_host_header_injection(domainlist, args):
    session = requests.Session()
    headers = {
        "X-Forwarded-Host": "evil.com",
        "Host": "evil.com",
        "X-Forwarded-For": "evil.com",
        "X-Client-IP": "evil.com",
        "X-Remote-IP": "evil.com",
        "X-Remote-Addr": "evil.com",
        "X-Host": "evil.com"
    }

    # Get proxy list
    proxies = setup_proxies(args.proxy, args.proxy_file)
    current_proxy = None

    try:
        # Select proxy if available
        if proxies:
            current_proxy = random.choice(proxies)

        # Normal request with proxy
        normal_resp = session.get(
            domainlist, 
            verify=False, 
            timeout=5,
            proxies=current_proxy
        )
        normal_content = normal_resp.text

        for header_name, header_value in headers.items():
            try:
                resp = session.get(
                    domainlist, 
                    verify=False, 
                    headers={header_name: header_value}, 
                    timeout=5,
                    proxies=current_proxy
                )
                
                if resp.status_code in {301, 302, 303, 307, 308}:
                    location = resp.headers.get('Location', '').lower()
                    if location == "evil.com":
                        print(f"{Fore.RED}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.YELLOW}(Redirect to evil.com in Location header)")
                        return
                    
                if resp.text != normal_content:
                    if 'evil.com' in resp.text.lower():
                        soup = BeautifulSoup(resp.text, 'html.parser')
                        title = soup.title.string
                        if "Evil.Com" in title:
                            print(f"{Fore.RED}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.YELLOW}(evil.com found in response body)")
                            print(f"{Fore.YELLOW}Title: {Fore.GREEN}{title}")
                            return
                        else:
                            pass

            except requests.exceptions.ProxyError:
                if proxies:
                    current_proxy = random.choice(proxies)
                continue
            except requests.exceptions.ConnectTimeout:
                print(f"{Fore.RED}Proxy connection timeout{Style.RESET_ALL}")
                continue

        print(f"{Fore.CYAN}Not Vulnerable: {Fore.GREEN}{domainlist}")

    except requests.exceptions.RequestException as e:
        if "proxy" in str(e).lower():
            pass
        pass
