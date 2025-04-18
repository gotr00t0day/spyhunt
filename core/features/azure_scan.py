import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from alive_progress import alive_bar

def check_azure_services(domain):
    azure_endpoints = {
        'Storage': [f'https://{domain}.blob.core.windows.net',
                    f'https://{domain}.file.core.windows.net',
                    f'https://{domain}.queue.core.windows.net'],
        'WebApps': [f'https://{domain}.azurewebsites.net'],
        'Functions': [f'https://{domain}.azurewebsites.net/api'],
        'KeyVault': [f'https://{domain}.vault.azure.net'],
        'Database': [f'https://{domain}.database.windows.net'],
        'ServiceBus': [f'https://{domain}.servicebus.windows.net']
    }
    
    findings = []
    with alive_bar(len(azure_endpoints), title='Scanning Azure Services') as bar:
        for service, urls in azure_endpoints.items():
            for url in urls:
                try:
                    response = requests.get(url, timeout=10, verify=False)
                    if response.status_code != 404:
                        findings.append({
                            'service': service,
                            'url': url,
                            'status': response.status_code,
                            'headers': dict(response.headers)
                        })
                except requests.RequestException:
                    pass
            bar()
    return findings

def check_management_endpoints(domain):
    mgmt_endpoints = [
        f'https://management.{domain}',
        f'https://portal.{domain}',
        f'https://scm.{domain}'
    ]
    findings = []
    
    print(f"\n{Fore.CYAN}Checking for exposed management endpoints...{Style.RESET_ALL}")
    for endpoint in mgmt_endpoints:
        try:
            response = requests.get(endpoint, timeout=5, verify=False)
            if response.status_code != 404:
                findings.append({
                    'endpoint': endpoint,
                    'status': response.status_code
                })
        except requests.RequestException:
            continue
    return findings
