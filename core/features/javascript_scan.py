from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(action='ignore',module='bs4')

import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from urllib.parse import urlparse, urljoin
import re

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def get_js_files(url):
    js_files = set()
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find <script> tags with src attribute
        for script in soup.find_all('script', src=True):
            script_url = urljoin(url, script['src'])
            if is_valid_url(script_url):
                js_files.add(script_url)
        
        # Find JavaScript files in <link> tags
        for link in soup.find_all('link', rel='stylesheet'):
            if 'href' in link.attrs:
                css_url = urljoin(url, link['href'])
                if is_valid_url(css_url):
                    css_response = requests.get(css_url, timeout=10)
                    js_urls = re.findall(r'url\([\'"]?(.*?\.js)[\'"]?\)', css_response.text)
                    for js_url in js_urls:
                        full_js_url = urljoin(css_url, js_url)
                        if is_valid_url(full_js_url):
                            js_files.add(full_js_url)
        
        # Find JavaScript files mentioned in inline scripts
        for script in soup.find_all('script'):
            if script.string:
                js_urls = re.findall(r'[\'"]([^\'"]*\.js)[\'"]', script.string)
                for js_url in js_urls:
                    full_js_url = urljoin(url, js_url)
                    if is_valid_url(full_js_url):
                        js_files.add(full_js_url)
        
    except requests.RequestException as e:
        print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
    
    return js_files

def analyze_js_file(js_url):
    try:
        response = requests.get(js_url, timeout=10)
        content = response.text
        size = len(content)
        
        # Analysis patterns
        interesting_patterns = {
            'API Keys': r'(?i)(?:api[_-]?key|apikey)["\s:=]+(["\'][a-zA-Z0-9_\-]{20,}["\'])',
            'Passwords': r'(?i)(?:password|passwd|pwd)["\s:=]+(["\'][^"\']{8,}["\'])',
            'Tokens': r'(?i)(?:token|access_token|auth_token)["\s:=]+(["\'][a-zA-Z0-9_\-]{20,}["\'])',
            'Sensitive Functions': r'(?i)(eval|setTimeout|setInterval)\s*\([^)]+\)',
        }
        
        findings = {}
        for name, pattern in interesting_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                findings[name] = matches
        
        return js_url, size, findings
    except requests.RequestException as e:
        return js_url, None, f"Error: {e}"
