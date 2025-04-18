import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore

def check_cors(domainlist):
    try:
        payload = [domainlist, "evil.com"]
        header = {'Origin': ', '.join(payload)}
        session = requests.Session()
        session.max_redirects = 10
        resp = session.get(domainlist, verify=False, headers=header, timeout=(5, 10))

        allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
        allowed_methods = resp.headers.get("Access-Control-Allow-Credentials", "")
        if allow_origin == "evil.com" and allowed_methods == "true":
            print(f"{Fore.YELLOW}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{', '.join(payload)}")
            return
        print(f"{Fore.CYAN}NOT VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{', '.join(payload)}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.LIGHTBLACK_EX}Error processing {domainlist}: {e}{Fore.RESET}")
