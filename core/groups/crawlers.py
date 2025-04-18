from colorama import Fore, init, Style
import sys
import asyncio
from concurrent.futures import ThreadPoolExecutor
from core.features.j import main_j
from core.features.javascript_scan import get_js_files, analyze_js_file
from core.features.javascript_endpoints import main_javascript_endpoints
from core.features.haveibeenpwned import check_password_pwned
from core.utils import commands

def run(args):
    
    if args.webcrawler:
        if args.save:
            print(Fore.CYAN + f"Saving output to {args.save}")
            commands(f"echo {args.webcrawler} | hakrawler >> {args.save}")
        else:
            commands(f"echo {args.webcrawler} | hakrawler")

    if args.waybackurls:
        if args.save:
            print(Fore.CYAN + f"Saving output to {args.save}")
            commands(f"waybackurls {args.waybackurls} | anew >> {args.save}")
            print(Fore.GREEN + "DONE!")
        else:
            commands(f"waybackurls {args.waybackurls}")

    if args.j:
        init(autoreset=True)
        try:
            asyncio.run(main_j(args))
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}Crawl interrupted by user.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
            sys.exit(1)

    if args.paramspider:
        commands(f"paramspider -d {args.paramspider}")

    if args.javascript_scan:
        init(autoreset=True)
        print(f"Scanning {Fore.GREEN}{args.javascript_scan} {Fore.WHITE}for JavaScript files...{Style.RESET_ALL}")
        
        js_files = get_js_files(args.javascript_scan)
        if not js_files:
            print(f"{Fore.YELLOW}No JavaScript files found.{Style.RESET_ALL}")
        else:            
            print(f"{Fore.GREEN}Found {len(js_files)} JavaScript files. Analyzing...{Style.RESET_ALL}\n")
            
            with ThreadPoolExecutor(max_workers=args.threads) as executor:
                results = list(executor.map(analyze_js_file, js_files))
            
            for url, size, findings in results:
                print(f"{Fore.MAGENTA}File: {url}{Style.RESET_ALL}")
                if size is not None:
                    print(f"Size: {size} bytes")
                    if findings:
                        print("Potential sensitive information:")
                        for name, matches in findings.items():
                            print(f"  - {name}:")
                            for match in matches[:5]:  # Limit to first 5 matches to avoid overwhelming output
                                print(f"    {match}")
                            if len(matches) > 5:
                                print(f"    ... and {len(matches) - 5} more")
                    else:
                        print("No potential sensitive information found.")
                else:
                    print(f"{Fore.RED}{findings}{Style.RESET_ALL}")
                print()

    if args.javascript_endpoints:
        init(autoreset=True)
        asyncio.run(main_javascript_endpoints(args))

    if args.haveibeenpwned:
        print(f"{Fore.CYAN}HAVE I BEEN PWNED!{Style.RESET_ALL}\n")
        print(f"Checking password: {Fore.GREEN}{args.haveibeenpwned}{Style.RESET_ALL}\n")
        password_to_check = args.haveibeenpwned
        check_password_pwned(password_to_check)
