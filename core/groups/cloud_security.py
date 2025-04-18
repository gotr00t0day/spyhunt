from colorama import Fore, init, Style
from datetime import datetime
import json
import asyncio
from core.features.s3_scan import handle_s3_scan
from core.features.gcp_scan import handle_gcp_scan, check_gcp_exposure
from core.features.aws_scan import check_aws_services, check_iam_exposure
from core.features.azure_scan import check_azure_services, check_management_endpoints

def run(args):
    if args.s3_scan:
        asyncio.run(handle_s3_scan(args.s3_scan))

    if args.aws_scan:
        init(autoreset=True)
        target = args.aws_scan
        print(f"\n{Fore.MAGENTA}Starting AWS Security Scan for {Fore.CYAN}{target}{Style.RESET_ALL}")
        
        # Scan AWS services
        aws_findings = check_aws_services(target)
        if aws_findings:
            print(f"\n{Fore.RED}Found exposed AWS services:{Style.RESET_ALL}")
            for finding in aws_findings:
                print(f"\nService: {Fore.YELLOW}{finding['service']}{Style.RESET_ALL}")
                print(f"URL: {Fore.CYAN}{finding['url']}{Style.RESET_ALL}")
                print(f"Status: {finding['status']}")
                
        # Check IAM exposure
        iam_findings = check_iam_exposure(target)
        if iam_findings:
            print(f"\n{Fore.RED}Found exposed IAM endpoints:{Style.RESET_ALL}")
            for finding in iam_findings:
                print(f"Endpoint: {Fore.CYAN}{finding['endpoint']}{Style.RESET_ALL}")
                print(f"Status: {finding['status']}")
                
        # Save results
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        with open(f'aws_scan_{timestamp}.json', 'w') as f:
            json.dump({
                'aws_services': aws_findings,
                'iam_endpoints': iam_findings
            }, f, indent=4)
        print(f"\n{Fore.GREEN}Results saved to aws_scan_{timestamp}.json{Style.RESET_ALL}")

    if args.azure_scan:
        init(autoreset=True)
        target = args.azure_scan
        print(f"\n{Fore.MAGENTA}Starting Azure Security Scan for {Fore.CYAN}{target}{Style.RESET_ALL}")
        
        # Scan Azure services
        azure_findings = check_azure_services(target)
        if azure_findings:
            print(f"\n{Fore.RED}Found exposed Azure services:{Style.RESET_ALL}")
            for finding in azure_findings:
                print(f"\nService: {Fore.YELLOW}{finding['service']}{Style.RESET_ALL}")
                print(f"URL: {Fore.CYAN}{finding['url']}{Style.RESET_ALL}")
                print(f"Status: {finding['status']}")
                
        # Check management endpoints
        mgmt_findings = check_management_endpoints(target)
        if mgmt_findings:
            print(f"\n{Fore.RED}Found exposed management endpoints:{Style.RESET_ALL}")
            for finding in mgmt_findings:
                print(f"Endpoint: {Fore.CYAN}{finding['endpoint']}{Style.RESET_ALL}")
                print(f"Status: {finding['status']}")
                
        # Save results
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        with open(f'azure_scan_{timestamp}.json', 'w') as f:
            json.dump({
                'azure_services': azure_findings,
                'management_endpoints': mgmt_findings
            }, f, indent=4)
        print(f"\n{Fore.GREEN}Results saved to azure_scan_{timestamp}.json{Style.RESET_ALL}")
        
    if args.gcp_scan:
        asyncio.run(handle_gcp_scan(args.gcp_scan))
        check_gcp_exposure(args.gcp_scan)
