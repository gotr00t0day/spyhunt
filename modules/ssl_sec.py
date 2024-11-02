import ssl
import socket
from datetime import datetime
from colorama import Fore

TLS_VERSION = []
TLS_VULN_VERSION = ["TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"]

def check_ssl(domain: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                TLS_VERSION.append(ssock.version())
                return f"TLS Version: {Fore.CYAN}{ssock.version()}{Fore.RESET}\nCipher Suite: {Fore.CYAN}{ssock.cipher()[0]}{Fore.RESET}\nIssuer: {Fore.CYAN}{cert['issuer'][0][0]}{Fore.RESET}\nSubject: {Fore.CYAN}{cert['subject'][0][0]}{Fore.RESET}\nValid From: {Fore.CYAN}{datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d %H:%M:%S')}{Fore.RESET}\nValid To: {Fore.CYAN}{datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d %H:%M:%S')}{Fore.RESET}"
    except Exception as e:
        print(f"Error checking SSL: {e}")


def save_ssl_info(domain: str, info: str, port: int = 443):
    with open('ssl_info.txt', 'w') as f:
        f.write(info)

if __name__ == "__main__":
    info = check_ssl("google.com")
    print(info)
    if TLS_VERSION in TLS_VULN_VERSION:
        print(f"{TLS_VERSION}: VULNERABLE!")
        print(f"Mitigation: Please update your SSL/TLS version to a more secure version.")
    save_ssl_info("google.com", info)
