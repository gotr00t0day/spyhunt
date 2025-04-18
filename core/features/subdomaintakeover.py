import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
import dns.resolver
import whois

COMMON_SERVICES = [
    "GitHub, Inc.", "GitLab Inc.", "Bitbucket", "Heroku, Inc.",
    "Firebase", "Netlify, Inc.", "Surge", "Automattic Inc.",
    "Amazon CloudFront", "Microsoft Azure", "Google LLC"
]

def check_subdomain(subdomain):
    potential_takeover = set()
    url = f"https://{subdomain}"
    try:
        response = requests.get(url)
        if response.status == 404:
            print(f"[Potential Takeover] {subdomain} - 404 Not Found")
            potential_takeover.add(subdomain)
            # Save potential takeovers to a file for further analysis
            with open('potential_takeover.txt', 'w') as f:
                for sub in potential_takeover:
                    f.write(f"{sub}\n")
        elif response.status == 200:
            print(f"[Active] {subdomain} - 200 OK")
        else:
            print(f"[Other] {subdomain} - Status Code: {response.status}")
    except requests.RequestException:
        pass

def check_dns(args, subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            target = str(rdata.target).rstrip('.')
            print(f"{Fore.MAGENTA}[CNAME] {Fore.CYAN}{subdomain}{Style.RESET_ALL} points to {Fore.GREEN}{target}{Style.RESET_ALL}")
            check_whois(args, target)  # Check WHOIS for the CNAME target
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass  # No CNAME record found
    except Exception as e:
        print(f"{Fore.RED}[DNS Error] {Fore.CYAN}{subdomain} - {Fore.RED}{e}{Style.RESET_ALL}")

def check_whois(args, target):
    vuln_subs = set()
    try:
        w = whois.whois(target)
        org_name = w.org if w.org else "Unknown"
        print(f"{Fore.MAGENTA}[WHOIS] {Fore.CYAN}{target}{Style.RESET_ALL} - Organization: {Fore.GREEN}{org_name}{Style.RESET_ALL}")
        for service in COMMON_SERVICES:
            if service.lower() in org_name.lower():
                vuln_subs.add(target)
                print(f"{Fore.YELLOW}[Potential Takeover] {Fore.CYAN}{target} is associated with {Fore.GREEN}{org_name} - Common service{Style.RESET_ALL}")
                break
        with open(f'{args.save}', 'w') as f:
            for sub in vuln_subs:
                f.write(f"{sub}\n")
    except Exception as e:
        print(f"{Fore.RED}[WHOIS Error] {Fore.CYAN}{target} - {Fore.RED}{e}{Style.RESET_ALL}")

def check_subdomain_takeover(args, subdomain):
    check_dns(args, subdomain)  
    check_subdomain(subdomain)  

def load_subdomains(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[Error] {Fore.CYAN}{file_path} - {Fore.RED}File not found{Style.RESET_ALL}")
        return []

