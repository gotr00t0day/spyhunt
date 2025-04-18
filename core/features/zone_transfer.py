from colorama import Fore, Style
from datetime import datetime
import dns.resolver
import dns.zone
import dns.query

def get_nameservers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [str(rdata.target).rstrip('.') for rdata in answers]
    except Exception as e:
        print(f"{Fore.RED}Error getting nameservers: {e}{Style.RESET_ALL}")
        return []

def test_zone_transfer(domain, nameserver):
    try:
        # Attempt zone transfer
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
        names = z.nodes.keys()
        records = []
        
        # Get all records
        for n in names:
            record = z[n].to_text(n)
            records.append(record)
            print(f"{Fore.GREEN}[+] {Fore.CYAN}{record}{Style.RESET_ALL}")
        
        # Save results if vulnerable
        if records:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            with open(f'zone_transfer_{domain}_{timestamp}.txt', 'w') as f:
                f.write(f"DNS Zone Transfer Results for {domain}\n")
                f.write(f"Nameserver: {nameserver}\n\n")
                for record in records:
                    f.write(f"{record}\n")
            print(f"\n{Fore.RED}[!] Zone Transfer VULNERABLE!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Results saved to zone_transfer_{domain}_{timestamp}.txt{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Zone transfer failed for {nameserver}: {e}{Style.RESET_ALL}")
