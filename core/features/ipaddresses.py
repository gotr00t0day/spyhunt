from colorama import Fore
import socket

def scan_do(domain: str, ip_list):
    try:
        ips = socket.gethostbyname(domain)
        ip_list.append(ips)
        print(f"{Fore.GREEN} {domain} {Fore.WHITE}- {Fore.CYAN}{ips}")
    except socket.gaierror:
        pass
    except UnicodeError:
        pass

