import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

def extract_ip(ip):
    return str(ip)

def extract_ips(subnet, max_workers=100):
    network = ipaddress.ip_network(subnet, strict=False)
    ips = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(extract_ip, ip) for ip in network.hosts()]
        for future in as_completed(futures):
            ips.append(future.result())
    return ips
