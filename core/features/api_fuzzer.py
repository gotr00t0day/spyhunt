from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(action='ignore',module='bs4')

import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore
from core.utils import header

def check_endpoint(endpoint, args):
    error_patterns = [
        "404",
        "Page Not Found",
        "Not Found",
        "Error 404",
        "404 Not Found",
        "The page you requested was not found",
        "The requested URL was not found",
        "This page does not exist",
        "The requested page could not be found",
        "Sorry, we couldn't find that page",
        "Page doesn't exist"
    ]
    s = requests.Session()
    url = f"{args.api_fuzzer}/{endpoint}"
    try:
        r = s.get(url, verify=False, headers=header, timeout=5)

        # Check response text for error patterns
        page_text = r.text.lower()
        found_patterns = []
        for pattern in error_patterns:
            if pattern.lower() in page_text:
                found_patterns.append(pattern)
        if found_patterns:
            return f"{Fore.RED}{url} - {', '.join(found_patterns)}"

        # Check beautifulsoup for error patterns
        soup = BeautifulSoup(r.text, "html.parser")
        if soup.find("title") and "404" in soup.find("title").text.lower():
            pass
        elif soup.find("title") and "Page Not Found" in soup.find("title").text.lower():
            pass
        elif r.status_code == 403:
            pass
        elif r.status_code == 200:
            return f"{Fore.GREEN}{url}"
        elif r.status_code == 404:
            pass
        else:
            return f"{Fore.RED}{url} [{r.status_code}]"
    except requests.RequestException:
        return f"{Fore.YELLOW}{url} [Error]"
