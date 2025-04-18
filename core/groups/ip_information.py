from colorama import Fore, Style
import sys
from core.features.ipinfo import scan_ip_info

def run(args):
    # Add to main argument handling
    if args.ipinfo:
        if not args.token:
            print(f"{Fore.RED}Error: IPinfo API token required. Use --token to provide it.{Style.RESET_ALL}")
            sys.exit(1)
        scan_ip_info(args)