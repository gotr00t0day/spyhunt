from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(action='ignore',module='bs4')

from colorama import Fore, Style
from urllib.parse import urlparse, urljoin
import re
import asyncio
import aiohttp


async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                return await response.text()
            elif response.status == 404:
                # Silently ignore 404 errors
                return None
            else:
                print(f"{Fore.YELLOW}Warning: {url} returned status code {response.status}{Style.RESET_ALL}")
                return None
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
    except asyncio.TimeoutError:
        print(f"{Fore.RED}Timeout error fetching {url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Unexpected error fetching {url}: {e}{Style.RESET_ALL}")
    return None

def is_valid_url(url):
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)
    except Exception as e:
        print(f"{Fore.RED}Error parsing URL {url}: {e}{Style.RESET_ALL}")
        return False

def is_same_domain(url, domain):
    try:
        return urlparse(url).netloc == domain
    except Exception as e:
        print(f"{Fore.RED}Error comparing domains for {url}: {e}{Style.RESET_ALL}")
        return False

async def get_js_links(session, url, domain):
    js_links = set()
    new_links = set()
    html = await fetch(session, url)
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for script in soup.find_all('script', src=True):
                script_url = urljoin(url, script['src'])
                if is_valid_url(script_url) and is_same_domain(script_url, domain):
                    js_links.add(script_url)
            
            for script in soup.find_all('script'):
                if script.string:
                    js_urls = re.findall(r'[\'"]([^\'"]*\.js)[\'"]', script.string)
                    for js_url in js_urls:
                        full_js_url = urljoin(url, js_url)
                        if is_valid_url(full_js_url) and is_same_domain(full_js_url, domain):
                            js_links.add(full_js_url)
            
            new_links = set(urljoin(url, link['href']) for link in soup.find_all('a', href=True))
        except Exception as e:
            print(f"{Fore.RED}Error parsing HTML from {url}: {e}{Style.RESET_ALL}")
    
    return js_links, new_links

async def crawl_website(url, max_depth, concurrency):
    try:
        domain = urlparse(url).netloc
        visited = set()
        to_visit = {url}
        js_files = set()
        semaphore = asyncio.Semaphore(concurrency)

        async def bounded_get_js_links(session, url, domain):
            async with semaphore:
                return await get_js_links(session, url, domain)

        async with aiohttp.ClientSession() as session:
            for depth in range(int(max_depth) + 1):
                if not to_visit:
                    break

                tasks = [bounded_get_js_links(session, url, domain) for url in to_visit]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                visited.update(to_visit)
                to_visit = set()

                for result in results:
                    if isinstance(result, Exception):
                        print(f"{Fore.RED}Error during crawl: {result}{Style.RESET_ALL}")
                        continue
                    js_links, new_links = result
                    js_files.update(js_links)
                    to_visit.update(link for link in new_links 
                                    if is_valid_url(link) and is_same_domain(link, domain) and link not in visited)

                print(f"{Fore.CYAN}Depth {depth}: Found {len(js_files)} JS files, {len(to_visit)} new URLs to visit{Style.RESET_ALL}")

        return js_files
    except Exception as e:
        print(f"{Fore.RED}Unexpected error during crawl: {e}{Style.RESET_ALL}")
        return set()

async def main_j(args):
    try:
        print(f"{Fore.CYAN}Crawling {Fore.GREEN}{args.j}{Fore.CYAN} for JavaScript files...{Style.RESET_ALL}\n")
        js_files = await crawl_website(args.j, args.depth, args.concurrency)

        if js_files:
            print(f"\n{Fore.YELLOW}Found {len(js_files)} JavaScript files:{Style.RESET_ALL}")
            for js_file in sorted(js_files):
                print(js_file)

            if args.save:
                try:
                    with open(args.save, 'w') as f:
                        for js_file in sorted(js_files):
                            f.write(f"{js_file}\n")
                    print(f"\n{Fore.GREEN}Results saved to {args.save}{Style.RESET_ALL}")
                except IOError as e:
                    print(f"{Fore.RED}Error saving results to file: {e}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No JavaScript files found.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Unexpected error in main function: {e}{Style.RESET_ALL}")