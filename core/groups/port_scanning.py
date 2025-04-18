from colorama import Fore
import json
import nmap3
from core.features.cidr_notation import parse_ports, scan_subnet
from core.features.print_all_ips import extract_ips

def run(args):
        
    if args.nmap:
        print(f"{Fore.WHITE}Scanning {Fore.CYAN}{args.nmap}\n")
        nmap = nmap3.Nmap()
        results = nmap.nmap_version_detection(f"{args.nmap}")

        with open("nmap_results.json", "w") as f:
            json.dump(results, f, indent=4)

        with open('nmap_results.json', 'r') as file:
            data = json.load(file)

        for host, host_data in data.items():
            if host != "runtime" and host != "stats" and host != "task_results":
                ports = host_data.get("ports", [])
                for port in ports:
                    portid = port.get("portid")
                    service = port.get("service", {})
                    product = service.get("product")
                    print(f"{Fore.WHITE}Port: {Fore.CYAN}{portid}, {Fore.WHITE}Product: {Fore.CYAN}{product}")

    if args.cidr_notation:
        if args.ports:
            if args.threads:
                ports = parse_ports(args.ports)
                scan_subnet(args, args.cidr_notation, ports, args.threads)

    if args.print_all_ips:
        print(f"Extracting IPs from {args.print_all_ips}...")
        ips = extract_ips(args.print_all_ips)
        
        print(f"\nExtracted IPs from {args.print_all_ips}:")
        for ip in ips:
            print(f"{Fore.GREEN}{ip}{Fore.RESET}")
        
        print(f"\nTotal IPs: {len(ips)}")

        save = input("Do you want to save these IPs to a file? (y/n): ").lower()
        if save == 'y':
            filename = input("Enter filename to save IPs: ")
            with open(filename, 'w') as f:
                for ip in ips:
                    f.write(f"{ip}\n")
            print(f"IPs saved to {filename}")
