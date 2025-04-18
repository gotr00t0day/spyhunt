from colorama import Fore
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

def scan_ip(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((str(ip), port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return ip, open_ports

def scan_subnet(args, subnet, ports, max_threads=100):
    network = ipaddress.ip_network(subnet, strict=False)
    
    with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
        futures = [executor.submit(scan_ip, ip, ports) for ip in network.hosts()]
        
        for future in as_completed(futures):
            ip, open_ports = future.result()
            if open_ports:
                print(f"IP: {Fore.GREEN}{ip}:{Fore.CYAN}{','.join(map(str, open_ports))}{Fore.RESET}")

def parse_ports(ports):
    if isinstance(ports, list):
        return [int(p) for p in ports]
    return [int(p.strip()) for p in ports.split(',')]
