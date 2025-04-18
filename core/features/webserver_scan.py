import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from urllib.parse import urljoin

def get_server_info(url, path=''):
    full_url = urljoin(url, path)
    try:
        response = requests.get(full_url, allow_redirects=False, timeout=10)
        return response.headers, response.status_code, response.text
    except requests.RequestException:
        return {}, None, ''

def analyze_headers(headers):
    server_info = {}
    for header, value in headers.items():
        if header.lower() == 'server':
            server_info['Server'] = value
        elif header.lower() == 'x-powered-by':
            server_info['X-Powered-By'] = value
        elif header.lower() == 'x-aspnet-version':
            server_info['ASP.NET'] = value
        elif header.lower() == 'x-generator':
            server_info['Generator'] = value
    return server_info

def check_specific_files(url):
    files_to_check = {
        '/favicon.ico': {'Apache': 'Apache', 'Nginx': 'Nginx'},
        '/server-status': {'Apache': 'Apache Status'},
        '/nginx_status': {'Nginx': 'Nginx Status'},
        '/web.config': {'IIS': 'IIS Config'},
        '/phpinfo.php': {'PHP': 'PHP Version'}
    }
    
    results = {}
    for file, signatures in files_to_check.items():
        headers, status, content = get_server_info(url, file)
        if status == 200:
            for server, signature in signatures.items():
                if signature in content:
                    results[server] = f"Detected via {file}"
    return results

def detect_web_server(url):
    if not url.startswith('http'):
        url = 'http://' + url

    print(f"Scanning {Fore.GREEN}{url}{Fore.WHITE}...{Style.RESET_ALL}")

    headers, status, content = get_server_info(url)
    
    if status is None:
        print(f"{Fore.RED}Error: Unable to connect to the server{Style.RESET_ALL}")
        return

    server_info = analyze_headers(headers)
    
    if 'Server' not in server_info:
        if 'Set-Cookie' in headers and 'ASPSESSIONID' in headers['Set-Cookie']:
            server_info['Likely'] = 'IIS'
        elif 'Set-Cookie' in headers and 'PHPSESSID' in headers['Set-Cookie']:
            server_info['Likely'] = 'PHP'
    
    file_results = check_specific_files(url)
    server_info.update(file_results)

    if server_info:
        for key, value in server_info.items():
            print(f"{Fore.GREEN}{key}:{Style.RESET_ALL} {Fore.YELLOW}{value}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Unable to determine web server{Style.RESET_ALL}")

    if 'CF-RAY' in headers:
        print(f"{Fore.GREEN}Cloudflare detected{Style.RESET_ALL}")
    
    if 'X-Varnish' in headers:
        print(f"{Fore.GREEN}Varnish Cache detected{Style.RESET_ALL}")
