import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
import time
import json

def print_headers(headers):
    print(f"{Fore.CYAN}Headers:{Style.RESET_ALL}")
    for key, value in headers.items():
        print(f"{Fore.GREEN}{key}: {Fore.YELLOW}{value}{Style.RESET_ALL}")

def extract_links(content, base_url):
    soup = BeautifulSoup(content, 'html.parser')
    links = [urljoin(base_url, link.get('href')) for link in soup.find_all('a', href=True)]
    return links

def send_request(url, method='GET', custom_headers=None, data=None, params=None, auth=None, proxies=None, allow_redirects=True, verbose=False):
    try:
        start_time = time.time()
        response = requests.request(
            method=method,
            url=url,
            headers=custom_headers,
            data=data,
            params=params,
            auth=auth,
            proxies=proxies,
            allow_redirects=allow_redirects,
            timeout=10
        )
        end_time = time.time()

        print(f"\n{Fore.MAGENTA}Status Code: {response.status_code}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Response Time: {end_time - start_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Response Size: {len(response.content)} bytes{Style.RESET_ALL}")
        
        print("\n--- Request Details ---")
        print(f"{Fore.CYAN}Method: {method}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}URL: {url}{Style.RESET_ALL}")
        print_headers(response.request.headers)
        
        if data:
            print(f"\n{Fore.CYAN}Request Data:{Style.RESET_ALL}")
            print(json.dumps(data, indent=2))
        
        print("\n--- Response Details ---")
        print_headers(response.headers)
        
        if verbose:
            print(f"\n{Fore.CYAN}Response Content:{Style.RESET_ALL}")
            print(response.text)
        
        links = extract_links(response.text, url)
        print(f"\n{Fore.CYAN}Links found in the response:{Style.RESET_ALL}")
        for link in links:
            print(link)

        return response
    except requests.RequestException as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return None

def load_headers_from_file(filename):
    with open(filename, 'r') as f:
        return json.load(f)
