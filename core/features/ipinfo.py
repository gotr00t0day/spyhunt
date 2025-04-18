import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
import ipinfo
import socket
from ipaddress import ip_network

# Add new function for IP info scanning
def scan_ip_info(args):
    target = args.ipinfo
    token = args.token
    """Get IP ranges and ASN information using IPinfo API"""
    try:
        # First resolve domain to IP if target is a domain
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(f"{Fore.CYAN}Resolved {target} to {ip}{Style.RESET_ALL}\n")
        except socket.gaierror:
            print(f"{Fore.RED}Could not resolve {target} to IP address{Style.RESET_ALL}")
            return None

        handler = ipinfo.getHandler(token)
        print(f"{Fore.MAGENTA}Gathering IP information for {Fore.CYAN}{target}{Style.RESET_ALL}\n")
        
        # Get initial IP info using resolved IP
        details = handler.getDetails(ip)
        
        # Print findings
        print(f"{Fore.GREEN}IP Information:{Style.RESET_ALL}")
        print(f"IP: {Fore.CYAN}{details.ip}{Style.RESET_ALL}")
        if hasattr(details, 'hostname') and details.hostname:
            print(f"Hostname: {Fore.CYAN}{details.hostname}{Style.RESET_ALL}")
        if hasattr(details, 'org') and details.org:
            print(f"Organization: {Fore.CYAN}{details.org}{Style.RESET_ALL}")
        if hasattr(details, 'country') and details.country:
            print(f"Country: {Fore.CYAN}{details.country}{Style.RESET_ALL}")
        if hasattr(details, 'city') and details.city:
            print(f"City: {Fore.CYAN}{details.city}{Style.RESET_ALL}")

        # Get ASN information
        if hasattr(details, 'org') and details.org:
            try:
                org_parts = details.org.split()
                if org_parts:
                    asn = org_parts[0]  # Get ASN number
                    org_name = ' '.join(org_parts[1:])  # Get organization name
                    
                    print(f"\n{Fore.GREEN}ASN Information:{Style.RESET_ALL}")
                    print(f"ASN: {Fore.CYAN}{asn}{Style.RESET_ALL}")
                    print(f"Organization: {Fore.CYAN}{org_name}{Style.RESET_ALL}")
                    
                    # Try to get IP ranges for this ASN
                    try:
                        ranges = []
                        print(f"\n{Fore.GREEN}IP Ranges:{Style.RESET_ALL}")
                        
                        # Use a separate request to get ranges
                        response = requests.get(f"https://ipinfo.io/{asn}/prefixes?token={token}")
                        if response.status_code == 200:
                            prefixes_data = response.json()
                            if 'prefixes' in prefixes_data:
                                for prefix in prefixes_data['prefixes']:
                                    try:
                                        netw = prefix.get('netblock', '')
                                        if netw:
                                            network = ip_network(netw)
                                            ranges.append({
                                                'range': str(network),
                                                'num_ips': network.num_addresses
                                            })
                                            print(f"{Fore.CYAN}{network}{Fore.YELLOW} ({network.num_addresses} IPs){Style.RESET_ALL}")
                                    except ValueError as e:
                                        print(f"{Fore.RED}Error parsing network {netw}: {e}{Style.RESET_ALL}")
                        
                        # Save ranges if requested
                        if args.save_ranges and ranges:
                            try:
                                with open(args.save_ranges, 'w') as f:
                                    f.write(f"# IP Ranges for {target}\n")
                                    f.write(f"# ASN: {asn}\n")
                                    f.write(f"# Organization: {org_name}\n\n")
                                    for r in ranges:
                                        f.write(f"{r['range']} # {r['num_ips']} IPs\n")
                                print(f"\n{Fore.GREEN}IP ranges saved to {args.save_ranges}{Style.RESET_ALL}")
                            except Exception as e:
                                print(f"{Fore.RED}Error saving IP ranges: {e}{Style.RESET_ALL}")
                    
                    except Exception as e:
                        print(f"{Fore.RED}Error getting IP ranges: {e}{Style.RESET_ALL}")
                        
            except Exception as e:
                print(f"{Fore.RED}Error processing ASN information: {e}{Style.RESET_ALL}")

        return details

    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return None
