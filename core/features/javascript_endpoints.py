from colorama import Fore, Style
import re
import asyncio
import aiohttp

async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                return await response.text()
            else:
                pass
                return None
    except aiohttp.ClientError as e:
        print(f"{Fore.RED}Error fetching {url}: {e}{Style.RESET_ALL}")
    except asyncio.TimeoutError:
        print(f"{Fore.RED}Timeout error fetching {url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Unexpected error fetching {url}: {e}{Style.RESET_ALL}")
    return None

def find_endpoints(js_content):
    # This regex pattern looks for common endpoint patterns in JavaScript
    endpoint_pattern = r'(?:"|\'|\`)(/(?:api/)?[\w-]+(?:/[\w-]+)*(?:\.\w+)?)'
    endpoints = set(re.findall(endpoint_pattern, js_content))
    return endpoints

async def analyze_js_file(session, js_url):
    js_content = await fetch(session, js_url)
    if js_content:
        endpoints = find_endpoints(js_content)
        return js_url, endpoints
    return js_url, set()

async def process_js_files(file_path, concurrency):
    js_files = {}
    
    try:
        with open(file_path, 'r') as file:
            js_urls = [line.strip() for line in file if line.strip()]

        async with aiohttp.ClientSession() as session:
            semaphore = asyncio.Semaphore(concurrency)
            
            async def bounded_analyze_js_file(js_url):
                async with semaphore:
                    return await analyze_js_file(session, js_url)
            
            tasks = [bounded_analyze_js_file(js_url) for js_url in js_urls]
            results = await asyncio.gather(*tasks)

            for js_url, endpoints in results:
                js_files[js_url] = endpoints

    except Exception as e:
        print(f"{Fore.RED}Error processing JS file list: {e}{Style.RESET_ALL}")

    return js_files

async def main_javascript_endpoints(args):
    print(f"{Fore.CYAN}Analyzing JavaScript files from {Fore.GREEN}{args.javascript_endpoints}{Style.RESET_ALL}\n")
    js_files = await process_js_files(args.javascript_endpoints, args.concurrency)

    if js_files:
        print(f"\n{Fore.YELLOW}Analyzed {len(js_files)} JavaScript files:{Style.RESET_ALL}")
        for js_url, endpoints in js_files.items():
            print(f"\n{Fore.CYAN}{js_url}{Style.RESET_ALL}")
            if endpoints:
                print(f"{Fore.GREEN}Endpoints found:{Style.RESET_ALL}")
                for endpoint in sorted(endpoints):
                    print(f"  {endpoint}")
            else:
                print(f"{Fore.YELLOW}No endpoints found{Style.RESET_ALL}")

        if args.save:
            try:
                with open(args.save, 'w') as f:
                    for js_url, endpoints in js_files.items():
                        f.write(f"{js_url}\n")
                        if endpoints:
                            f.write("Endpoints:\n")
                            for endpoint in sorted(endpoints):
                                f.write(f"  {endpoint}\n")
                        else:
                            f.write("No endpoints found\n")
                        f.write("\n")
                print(f"\n{Fore.GREEN}Results saved to {args.save}{Style.RESET_ALL}")
            except IOError as e:
                print(f"{Fore.RED}Error saving results to file: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No JavaScript files were successfully analyzed.{Style.RESET_ALL}")
