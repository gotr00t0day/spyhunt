import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from alive_progress import alive_bar

def check_aws_services(domain):
    aws_endpoints = {
        'S3': [f'http://{domain}.s3.amazonaws.com', f'https://{domain}.s3.amazonaws.com'],
        'CloudFront': [f'https://{domain}.cloudfront.net'],
        'ELB': [f'{domain}.elb.amazonaws.com', f'{domain}.elb.us-east-1.amazonaws.com'],
        'API Gateway': [f'https://{domain}.execute-api.us-east-1.amazonaws.com'],
        'Lambda': [f'https://{domain}.lambda-url.us-east-1.amazonaws.com'],
        'ECR': [f'https://{domain}.dkr.ecr.us-east-1.amazonaws.com'],
        'ECS': [f'https://{domain}.ecs.us-east-1.amazonaws.com'],
    }
    
    findings = []
    with alive_bar(len(aws_endpoints), title='Scanning AWS Services') as bar:
        for service, urls in aws_endpoints.items():
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

def check_iam_exposure(domain):
    iam_endpoints = [
        f'https://iam.{domain}',
        f'https://sts.{domain}',
        f'https://signin.{domain}'
    ]
    findings = []
    
    print(f"\n{Fore.CYAN}Checking for exposed IAM endpoints...{Style.RESET_ALL}")
    for endpoint in iam_endpoints:
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
