from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(action='ignore',module='bs4')

import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from urllib.parse import urlparse, urljoin, parse_qs
from alive_progress import alive_bar
from modules.ss3sec import S3Scanner
from datetime import datetime
import waybackpy
import socket
import re
import shodan
import aiohttp
import ssl
from core.utils import scan, header

async def fetch(session, url):
    parsed_url = urlparse(url)
    if not all([parsed_url.scheme, parsed_url.netloc]):
        print(f"Invalid URL: {url}")
        return None
    try:
        async with session.get(url) as response:
            return await response.text()
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None
    
async def waybackpy(target):
    waybackurls = scan(f"waybackurls {target} | anew")
    return waybackurls

async def portscan(target):
    if target.startswith("http://") or target.startswith("https://"):
        target = target.replace("http://", "").replace("https://", "")
    if target.startswith("www."):
        target = target[4:]
    if target.startswith("https://www."):
        target = target[8:]
    if target.endswith("/"):
        target = target[:-1]
    ports = scan(f"naabu -host {target} -silent")
    return ports

async def dnsscan(target):
    dnsscan = scan(f"echo {target} | dnsx -silent -recon -j dnsscan.json")
    return dnsscan

async def ssl_vuln_scan(target):
    TLS_VERSION = []
    TLS_VULN_VERSION = ["TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"]

    def check_ssl(domain: str, port: int = 443):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    TLS_VERSION.append(ssock.version())
                    return f"TLS Version: {ssock.version()}\nCipher Suite: {ssock.cipher()[0]}\nIssuer: {cert['issuer'][0][0]}\nSubject: {cert['subject'][0][0]}\nValid From: {datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d %H:%M:%S')}\nValid To: {datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d %H:%M:%S')}"
        except Exception as e:
            print(f"Error checking SSL: {e}")


    def save_ssl_info(domain: str, info: str, port: int = 443):
        if info:
            with open('ssl_info.txt', 'w') as f:
                f.write(info)

    if "http://" in target or "https://" in target:
        target = target.replace("http://", "").replace("https://", "")
    if "www." in target:
        target = target[4:]
    if "https://www." in target:
        target = target[8:]
    if target.endswith("/"):
        target = target[:-1]

    info = check_ssl(target)
    if TLS_VERSION in TLS_VULN_VERSION:
        print(f"{TLS_VERSION}: VULNERABLE!")
        print(f"Mitigation: Please update your SSL/TLS version to a more secure version.")
    save_ssl_info(target, info)
    return info

async def headers_info(target: str):
    try:
        s = requests.Session()
        r = s.get(target, verify=False, headers=header)
    except Exception as e:
        print(f"Error fetching {target}: {e}")
        return []
    http_headers = []
    for k,v in r.headers.items():
        http_headers.append(f"{k}: {v}")    
    return http_headers

async def server_info(target):
    s = requests.Session()
    r = s.get(target, verify=False, headers=header)
    return r.headers.get("Server")

async def crawl_site(target):
    print(f"{Fore.MAGENTA}Crawling {Fore.CYAN}{target}{Style.RESET_ALL} for links...")
    
    connector = aiohttp.TCPConnector(ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        response_text = await fetch(session, target)
        if response_text:
            soup = BeautifulSoup(response_text, 'html.parser')
            links = set() 
            for link in soup.find_all('a', href=True):
                full_url = link['href']
                if not full_url.startswith('http'):
                    full_url = urlparse(target)._replace(path=full_url).geturl()
                parsed_url = urlparse(full_url)
                if all([parsed_url.scheme, parsed_url.netloc]):
                    links.add(full_url)
                else:
                    print(f"Invalid link found: {full_url}")
            return links 
    return set() 

async def extract_js_files(links, target):
    print(f"{Fore.MAGENTA}Extracting JavaScript files from links...{Style.RESET_ALL}")
    js_files = set() 
    target_parsed = urlparse(target)  
    async with aiohttp.ClientSession() as session:
        for link in links:
            try:
                response = await fetch(session, link)  
                if response:
                    soup = BeautifulSoup(response, 'html.parser')
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(link, script['src'])
                        js_parsed = urlparse(js_url)
                        if js_parsed.netloc == target_parsed.netloc:
                            js_files.add(js_url)
            except Exception as e:
                print(f"Error extracting JS from {link}: {e}")
    return js_files

def extract_parameters(links):
    print(f"{Fore.MAGENTA}Extracting parameters from links...{Style.RESET_ALL}")
    parameters = {}
    for link in links:
        parsed_url = urlparse(link)
        query_params = parse_qs(parsed_url.query)
        if query_params:
            parameters[link] = query_args
    return parameters

def shodan_search(target, api):
    shodan_api = shodan.Shodan(api)
    print(f"{Fore.MAGENTA}Searching Shodan for {Fore.CYAN}{target}{Style.RESET_ALL}...")
    results = []
    try:
        # Perform the Shodan search
        results = shodan_api.search(target)
        print(f"Found {results['total']} results for {target}.")
        
        # Extract subdomains, port numbers, and services
        extracted_data = []
        for match in results['matches']:
            ip = match['ip_str']
            port = match['port']
            services = match.get('product', 'Unknown')  # Get the service/product name
            extracted_data.append(f"IP: {ip}, Port: {port}, Service: {services}")
        
        return extracted_data
    except Exception as e:
        print(f"Error searching Shodan: {e}")
        return []

async def main_autorecon(target):
    print(f"{Fore.MAGENTA}Running autorecon for {Fore.CYAN}{target}{Style.RESET_ALL}\n")
    shodankey = input(f"{Fore.CYAN}Enter your Shodan API key: {Style.RESET_ALL}")
    print("\n")
    with alive_bar(11, title='Running autorecon') as bar:
        site_links = await crawl_site(target)
        print(f"{Fore.MAGENTA}Found {Fore.CYAN}{len(site_links)}{Style.RESET_ALL} links from crawling.")
        with open('site_links.txt', 'w') as f:
            for link in site_links:
                f.write(f"{link}\n")
        bar()  # Update after crawling site

        all_links = site_links  # Only site links now

        # Extract JavaScript files, passing the 
        js_files = await extract_js_files(all_links, target)
        print(f"{Fore.MAGENTA}Found {Fore.CYAN}{len(js_files)}{Style.RESET_ALL} JavaScript files.")
        with open('js_files.txt', 'w') as f:
            for js_file in js_files:
                f.write(f"{js_file}\n")
        bar()  # Update after extracting JS files

        #Wayback urls 
        waybackurls = await waybackpy(target)
        with open('waybackurls.txt', 'w') as f:
            f.write(f"{waybackurls}\n")
        
        with open('waybackurls.txt', 'r') as f:
            waybackurls_lines = [line.strip() for line in f if line.strip()]
            print(f"{Fore.MAGENTA}Found {Fore.CYAN}{len(waybackurls_lines)}{Style.RESET_ALL} waybackurls.")
        bar()  # Update after waybackurls

        #Naabu portscan
        ports = await portscan(target)
        with open('ports.txt', 'w') as f:
            f.write(f"{ports}\n")

        with open('ports.txt', 'r') as f:
            ports_lines = [line.strip() for line in f if line.strip()]
            numbers = []
            for port in ports_lines:
                found_numbers = re.findall(r'[-+]?\d*\.\d+|\d+', port)
                numbers.extend(found_numbers)     
            print(f"{Fore.MAGENTA}Found {Fore.CYAN}{len(ports_lines)}{Style.RESET_ALL} Open Ports.")
            print(f"{Fore.MAGENTA}Open Ports: {Fore.CYAN}{', '.join(map(str, numbers))}{Style.RESET_ALL}")
        bar()  # Update after ports scan

        #Get headers
        getheaders = await headers_info(target)
        target2 = target.replace("https://", "").replace("http://", "").replace("www.", "")
        with open(f"headers.txt", "w") as f:
            for header in getheaders:
                f.write(f"{header}\n")
        bar()

        #Server info
        serverinfo = await server_info(target)
        print(f"{Fore.MAGENTA}Server: {Fore.CYAN}{serverinfo}{Style.RESET_ALL}")
        bar()

        #Dnsscan
        dns = await dnsscan(target)
        with open('dnsscan.json', 'w') as f:
            f.write(f"{dns}\n")
        print(f"{Fore.MAGENTA}DNS Scan: {Fore.CYAN}DONE!{Style.RESET_ALL}")
        dns_output = scan(f"python3 dnsparser.py -dns dnsscan.json")
        with open('dns_output.txt', 'w') as f:
            f.write(f"{dns_output}\n")
        bar()  # Update after dnsscan

        parameters = extract_parameters(all_links)
        links_params = set()
        for links in parameters:
            links_params.add(links)
        with open('links_params.txt', 'w') as f:
            for link in links_params:
                f.write(f"{link}\n")
        bar()  # Update after extracting parameters

        # Print parameters for each link
        for link in links_params:
            print(f"{Fore.MAGENTA}Found {Fore.CYAN}{len(links_params)}{Style.RESET_ALL} Links with Parameters")

        # Perform Shodan search and save results to a file
        shodan_results = shodan_search(target, shodankey)
        with open('shodan_results.txt', 'w') as f:
            for result in shodan_results:
                f.write(f"{result}\n")
        bar()  # Update after Shodan search

        ssl_scan = await ssl_vuln_scan(target)  
        print(f"{Fore.MAGENTA}TLS/SSL Scan: {Fore.CYAN}ssl_info.txt{Style.RESET_ALL}")
        bar()

        scanner = S3Scanner()
        s3_results = await scanner.scan(target)
        scanner.save_results(target)
        bar()
