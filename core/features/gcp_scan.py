import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from urllib.parse import urlparse
import concurrent.futures
from tqdm import tqdm

async def handle_gcp_scan(target):
    """
    Scan for exposed Google Cloud Platform storage buckets and resources
    
    Args:
        target: Domain or organization name to scan
    """
    try:
        # Clean up the target to extract just the domain
        if target.startswith(('http://', 'https://')):
            parsed_url = urlparse(target)
            target = parsed_url.netloc
        target = target.replace('www.', '')  # Remove www if present
        
        print(f"{Fore.BLUE}[*] Scanning for exposed GCP Storage resources for {target}{Style.RESET_ALL}")
        
        # Common GCP bucket naming patterns
        bucket_patterns = [
            f"{target}",
            f"{target}-storage",
            f"{target}-bucket",
            f"{target}-data",
            f"{target}-assets",
            f"{target}-media",
            f"{target}-backup",
            f"{target}-archive",
            f"{target}-files",
            f"{target}-public",
            f"{target}-private",
            f"{target}-dev",
            f"{target}-prod",
            f"{target}-stage",
            f"{target}-staging",
            f"{target}-test",
            f"{target}-uat",
            f"{target}-content",
            f"{target}-static",
            f"{target}-images",
            f"{target}-docs",
            f"{target}-documents",
            f"{target}-logs",
            f"{target.replace('.', '-')}",
            f"{target.split('.')[0]}"
        ]
        
        # Add variations with company name
        company_name = target.split('.')[0]
        bucket_patterns.extend([
            f"gcp-{company_name}",
            f"storage-{company_name}",
            f"bucket-{company_name}",
            f"{company_name}-gcp"
        ])
        
        found_buckets = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for pattern in bucket_patterns:
                futures.append(executor.submit(check_gcp_bucket, pattern))
            
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Checking GCP buckets"):
                result = future.result()
                if result:
                    found_buckets.append(result)
        
        if found_buckets:
            print(f"{Fore.GREEN}[+] Found {len(found_buckets)} potentially exposed GCP Storage buckets:{Style.RESET_ALL}")
            for bucket in found_buckets:
                print(f"  - {bucket}")
        else:
            print(f"{Fore.YELLOW}[!] No exposed GCP Storage buckets found{Style.RESET_ALL}")
        
        # Check for other GCP services
        await check_gcp_services(target)
    except Exception as e:
        print(f"{Fore.RED}[!] Error during GCP scan: {str(e)}{Style.RESET_ALL}")

def check_gcp_bucket(bucket_name):
    """
    Check if a GCP Storage bucket exists and is publicly accessible
    
    Args:
        bucket_name: Name of the bucket to check
        
    Returns:
        Bucket URL if found and accessible, None otherwise
    """
    try:
        bucket_url = f"https://storage.googleapis.com/{bucket_name}/"
        
        response = requests.get(bucket_url, timeout=10)
        
        # Check if bucket exists
        if response.status_code == 200:
            # Check if we can list bucket contents
            if "ListBucketResult" in response.text:
                print(f"{Fore.RED}[!] Found publicly accessible GCP bucket: {bucket_url}{Style.RESET_ALL}")
                return bucket_url
            else:
                print(f"{Fore.YELLOW}[!] Found GCP bucket but cannot list contents: {bucket_url}{Style.RESET_ALL}")
                return bucket_url
        
        # Check for access denied (bucket exists but is not public)
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}[!] Found GCP bucket but access is denied: {bucket_url}{Style.RESET_ALL}")
            return None
            
    except requests.exceptions.RequestException:
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking GCP bucket {bucket_name}: {str(e)}{Style.RESET_ALL}")
        return None
    
    return None

async def check_gcp_services(domain):
    """
    Check for exposed GCP services related to the domain
    
    Args:
        domain: Domain to check
    """
    try:
        # Clean up the domain to extract just the domain name
        if domain.startswith(('http://', 'https://')):
            parsed_url = urlparse(domain)
            domain = parsed_url.netloc
        domain = domain.replace('www.', '')  # Remove www if present
        
        print(f"{Fore.BLUE}[*] Checking for exposed GCP services for {domain}{Style.RESET_ALL}")
        
        # Common GCP service endpoints to check
        gcp_services = [
            {"name": "Cloud Run", "url_pattern": f"https://{domain.split('.')[0]}-[a-z0-9]{{16}}.run.app", "regex": True},
            {"name": "App Engine", "url_pattern": f"https://{domain.split('.')[0]}.appspot.com", "regex": False},
            {"name": "Firebase", "url_pattern": f"https://{domain.split('.')[0]}.firebaseapp.com", "regex": False},
            {"name": "Cloud Functions", "url_pattern": f"https://{domain.split('.')[0]}.cloudfunctions.net", "regex": False},
            {"name": "GCP Load Balancer", "url_pattern": f"https://{domain}", "header": "Via", "value": "google"}
        ]
        
        for service in gcp_services:
            if service.get("regex", False):
                # For regex patterns, we need to do DNS enumeration or other techniques
                # This is a simplified placeholder
                print(f"{Fore.YELLOW}[!] Regex-based detection for {service['name']} requires additional enumeration{Style.RESET_ALL}")
                continue
            
            try:
                url = service["url_pattern"]
                response = requests.get(url, timeout=10)
                
                if service.get("header"):
                    # Check for specific header
                    if service["header"] in response.headers and service["value"].lower() in response.headers[service["header"]].lower():
                        print(f"{Fore.GREEN}[+] Found {service['name']}: {url}{Style.RESET_ALL}")
                        continue
                
                # Check based on status code
                if response.status_code < 400:
                    print(f"{Fore.GREEN}[+] Found {service['name']}: {url}{Style.RESET_ALL}")
                
            except requests.exceptions.RequestException:
                # Service endpoint not found or not accessible
                pass
            except Exception as e:
                print(f"{Fore.RED}[!] Error checking {service['name']}: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking GCP services: {str(e)}{Style.RESET_ALL}")

def check_gcp_exposure(domain):
    """
    Check for GCP resource exposure for a domain
    
    Args:
        domain: Domain to check
    """
    try:
        # Clean up the domain to extract just the domain name
        if domain.startswith(('http://', 'https://')):
            parsed_url = urlparse(domain)
            domain = parsed_url.netloc
        domain = domain.replace('www.', '')  # Remove www if present
        
        print(f"{Fore.BLUE}[*] Checking for GCP resource exposure for {domain}{Style.RESET_ALL}")
        
        # Check for common GCP project naming patterns
        project_patterns = [
            f"{domain.split('.')[0]}-project",
            f"{domain.split('.')[0]}-prod",
            f"{domain.split('.')[0]}-dev",
            f"{domain.split('.')[0]}-test",
            f"{domain.split('.')[0]}-staging",
            domain.split('.')[0]
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for pattern in project_patterns:
                futures.append(executor.submit(check_gcp_project, pattern))
            
            for future in tqdm(concurrent.futures.as_completed(futures), 
                             total=len(futures), 
                             desc="Checking GCP projects"):
                try:
                    future.result(timeout=15)  # 15 second timeout per project check
                except concurrent.futures.TimeoutError:
                    print(f"{Fore.YELLOW}[!] Timeout while checking a GCP project{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error checking GCP project: {str(e)}{Style.RESET_ALL}")
                    
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking GCP resource exposure: {str(e)}{Style.RESET_ALL}")

def check_gcp_project(pattern):
    """
    Check a single GCP project pattern
    
    Args:
        pattern: Project pattern to check
    """
    try:
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{pattern}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            print(f"{Fore.RED}[!] Found publicly accessible GCP project: {pattern}{Style.RESET_ALL}")
            try:
                project_data = response.json()
                print(f"  - Project Number: {project_data.get('projectNumber', 'N/A')}")
                print(f"  - Project ID: {project_data.get('projectId', 'N/A')}")
                print(f"  - Name: {project_data.get('name', 'N/A')}")
                print(f"  - Labels: {project_data.get('labels', {})}")
            except ValueError:
                print(f"  - Unable to parse project data")
        elif response.status_code == 403:
            print(f"{Fore.YELLOW}[!] Found GCP project but access is denied: {pattern}{Style.RESET_ALL}")
            
    except requests.exceptions.Timeout:
        print(f"{Fore.YELLOW}[!] Timeout while checking project: {pattern}{Style.RESET_ALL}")
    except requests.exceptions.RequestException:
        pass  # Silently ignore connection errors for non-existent projects
    except Exception as e:
        print(f"{Fore.RED}[!] Error checking project {pattern}: {str(e)}{Style.RESET_ALL}")
