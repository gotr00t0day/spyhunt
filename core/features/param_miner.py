import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
import re
import random
import string

def generate_random_string(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def detect_reflection(response, payload):
    return payload in response.text or payload in response.headers.values()

def analyze_response_difference(original_response, modified_response):
    if abs(len(original_response.content) - len(modified_response.content)) > 50:
        return True
    return False

def brute_force_parameter(url, param, original_response):
    try:
        payload = generate_random_string()
        test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
        response = requests.get(test_url, timeout=5, allow_redirects=False)
        
        if detect_reflection(response, payload):
            print(f"{Fore.GREEN}[+] Reflected parameter found: {param}{Style.RESET_ALL}")
            return param, "reflected"
        
        if analyze_response_difference(original_response, response):
            print(f"{Fore.WHITE}[*] Potential parameter found (response changed): {Fore.YELLOW}{param}{Style.RESET_ALL}")
            return param, "potential"
        
        if response.status_code != original_response.status_code:
            print(f"{Fore.WHITE}[*] Status code changed for parameter: {Fore.CYAN}{param} {Fore.YELLOW}({original_response.status_code} -> {response.status_code}){Style.RESET_ALL}")
            return param, "status_changed"
        
    except requests.RequestException:
        pass
    return None, None

def scan_common_parameters(url):
    common_params = ['id', 'page', 'search', 'q', 'query', 'file', 'filename', 'path', 'dir']
    found_params = []
    for param in common_params:
        result, _ = brute_force_parameter(url, param, requests.get(url, timeout=5))
        if result:
            found_params.append(result)
    return found_params

def extract_parameters_from_html(url):
    try:
        response = requests.get(url, timeout=5)
        form_params = re.findall(r'name=["\']([^"\']+)["\']', response.text)
        js_params = re.findall(r'(?:get|post)\s*\(\s*["\'][^"\']*\?([^"\'&]+)=', response.text)
        return list(set(form_params + js_params))
    except requests.RequestException:
        return []
