import requests
import concurrent.futures
from urllib.parse import urlparse
import boto3
from botocore.exceptions import ClientError
from colorama import Fore, Style
from datetime import datetime

class S3Scanner:
    def __init__(self):
        self.common_names = [
            'backup', 'backups', 'dev', 'development',
            'prod', 'production', 'stage', 'staging',
            'test', 'testing', 'data', 'assets',
            'media', 'static', 'content', 'uploads',
            'private', 'public', 'files', 'archive'
        ]
        
        self.results = {
            'public': [],
            'private': [],
            'not_found': [],
            'errors': []
        }

    def generate_bucket_names(self, target):
        """Generate potential S3 bucket names based on target domain"""
        domain = urlparse(target).netloc.replace('www.', '')
        company_name = domain.split('.')[0]
        
        bucket_names = set()
        
        # Add base names
        bucket_names.add(domain)
        bucket_names.add(company_name)
        
        # Generate variations
        for name in [domain, company_name]:
            for suffix in self.common_names:
                bucket_names.add(f"{name}-{suffix}")
                bucket_names.add(f"{name}_{suffix}")
                bucket_names.add(f"{name}.{suffix}")
                bucket_names.add(f"{suffix}-{name}")
                bucket_names.add(f"{suffix}_{name}")
                bucket_names.add(f"{suffix}.{name}")
        
        return bucket_names

    def check_bucket_access(self, bucket_name):
        """Check if S3 bucket exists and test its permissions"""
        try:
            # Test bucket URL
            urls = [
                f"http://{bucket_name}.s3.amazonaws.com",
                f"http://s3.amazonaws.com/{bucket_name}"
            ]
            
            for url in urls:
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    # Bucket exists and is listable
                    if 'ListBucketResult' in response.text:
                        self.results['public'].append({
                            'bucket': bucket_name,
                            'url': url,
                            'status': 'Public Listable',
                            'details': self.check_bucket_permissions(bucket_name)
                        })
                        return
                        
                elif response.status_code == 403:
                    # Bucket exists but not listable
                    self.results['private'].append({
                        'bucket': bucket_name,
                        'url': url,
                        'status': 'Private/Protected',
                        'details': self.check_bucket_permissions(bucket_name)
                    })
                    return
                    
                elif response.status_code == 404:
                    self.results['not_found'].append(bucket_name)
                    return

        except Exception as e:
            self.results['errors'].append({
                'bucket': bucket_name,
                'error': str(e)
            })

    def check_bucket_permissions(self, bucket_name):
        """Test specific permissions on the bucket"""
        permissions = []
        
        try:
            s3_client = boto3.client('s3')
            
            # Test ListBucket
            try:
                s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                permissions.append('ListBucket')
            except ClientError:
                pass

            # Test GetObject (try to read a likely file)
            try:
                s3_client.get_object(Bucket=bucket_name, Key='index.html')
                permissions.append('GetObject')
            except ClientError:
                pass

            # Test PutObject
            try:
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key='test.txt',
                    Body='test'
                )
                permissions.append('PutObject')
                # Clean up test file
                s3_client.delete_object(Bucket=bucket_name, Key='test.txt')
            except ClientError:
                pass

        except Exception as e:
            permissions.append(f"Error checking permissions: {str(e)}")

        return permissions

    async def scan(self, target):
        """Main scanning function"""
        print(f"{Fore.CYAN}Starting S3 bucket scan for {target}{Style.RESET_ALL}")
        
        bucket_names = self.generate_bucket_names(target)
        print(f"{Fore.YELLOW}Generated {len(bucket_names)} potential bucket names{Style.RESET_ALL}")

        # Use ThreadPoolExecutor for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.check_bucket_access, bucket_names)

        self.print_results()
        return self.results

    def print_results(self):
        """Print scan results"""
        print(f"{Fore.CYAN}S3 Bucket Scan Results:{Style.RESET_ALL}")
        
        if self.results['public']:
            print(f"{Fore.RED}Public Buckets:{Style.RESET_ALL}")
            for bucket in self.results['public']:
                print(f"{Fore.RED}Bucket: {bucket['bucket']}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}URL: {Fore.CYAN}{bucket['url']}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}Status: {Fore.CYAN}{bucket['status']}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}Permissions: {Fore.CYAN}{', '.join(bucket['details'])}{Style.RESET_ALL}")

        if self.results['private']:
            print(f"{Fore.MAGENTA}Private/Protected Buckets:{Style.RESET_ALL}")
            for bucket in self.results['private']:
                print(f"{Fore.RED}Bucket: {bucket['bucket']}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}URL: {Fore.CYAN}{bucket['url']}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}Status: {Fore.CYAN}{bucket['status']}{Style.RESET_ALL}")
                print(f"{Fore.MAGENTA}Permissions: {Fore.CYAN}{', '.join(bucket['details'])}{Style.RESET_ALL}")

        if self.results['errors']:
            print(f"\n{Fore.RED}Errors:{Style.RESET_ALL}")
            for error in self.results['errors']:
                print(f"{Fore.RED}Bucket: {error['bucket']}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Error: {error['error']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Public Buckets: {Fore.CYAN}{len(self.results['public'])}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Private Buckets: {Fore.CYAN}{len(self.results['private'])}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Not Found: {Fore.CYAN}{len(self.results['not_found'])}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Errors: {Fore.CYAN}{len(self.results['errors'])}{Style.RESET_ALL}")

    def save_results(self, target):
        """Save results to a file"""
        filename = f"s3_scan_{urlparse(target).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(filename, 'w') as f:
            f.write(f"S3 Bucket Scan Results for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            if self.results['public']:
                f.write("Public Buckets:\n")
                for bucket in self.results['public']:
                    f.write(f"\nBucket: {bucket['bucket']}")
                    f.write(f"\nURL: {bucket['url']}")
                    f.write(f"\nStatus: {bucket['status']}")
                    f.write(f"\nPermissions: {', '.join(bucket['details'])}\n")

            if self.results['private']:
                f.write("\nPrivate/Protected Buckets:\n")
                for bucket in self.results['private']:
                    f.write(f"\nBucket: {bucket['bucket']}")
                    f.write(f"\nURL: {bucket['url']}")
                    f.write(f"\nStatus: {bucket['status']}")
                    f.write(f"\nPermissions: {', '.join(bucket['details'])}\n")

            if self.results['errors']:
                f.write("\nErrors:\n")
                for error in self.results['errors']:
                    f.write(f"\nBucket: {error['bucket']}")
                    f.write(f"\nError: {error['error']}\n")

        print(f"\n{Fore.GREEN}Results saved to {filename}{Style.RESET_ALL}")