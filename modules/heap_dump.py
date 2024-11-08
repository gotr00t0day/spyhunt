import re
import json
import binascii
from colorama import Fore, Style
import os
from datetime import datetime
import mmap

class HeapdumpAnalyzer:
    def __init__(self):
        self.patterns = {
            'credentials': [
                r'(?i)password["\s:=]+[^\s;]{3,}',
                r'(?i)secret["\s:=]+[^\s;]{3,}',
                r'(?i)apikey["\s:=]+[^\s;]{3,}',
                r'(?i)api_key["\s:=]+[^\s;]{3,}',
                r'(?i)token["\s:=]+[^\s;]{3,}',
                r'jdbc:[^;\s]+',
                r'(?i)aws_[a-z_]+=\S+',
                r'(?i)private_key["\s:=]+[^\s;]{3,}'
            ],
            'urls': [
                r'https?://[a-zA-Z0-9-._]+[a-zA-Z]{2,}[^\s"\']{3,}',
                r'wss?://[a-zA-Z0-9-._]+[^\s"\']{3,}'
            ],
            'tokens': [
                r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',  # JWT
                r'[a-f0-9]{32}',  # MD5
                r'[A-Za-z0-9+/]{40,}={0,2}'  # Base64
            ],
            'aws': [
                r'AKIA[0-9A-Z]{16}',
                r'[0-9a-zA-Z/+]{40}'  # AWS Secret
            ],
            'email': [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ]
        }
        
        self.findings = {category: set() for category in self.patterns.keys()}
        self.stats = {
            'total_bytes_analyzed': 0,
            'total_findings': 0,
            'start_time': None,
            'end_time': None
        }

    def analyze_chunk(self, chunk):
        """Analyze a chunk of data for patterns"""
        try:
            # Convert bytes to string, ignore decode errors
            text = chunk.decode('utf-8', errors='ignore')
            
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, text)
                    for match in matches:
                        found = match.group().strip()
                        if self.is_valid_finding(found):
                            self.findings[category].add(found)
                            
        except Exception as e:
            print(f"{Fore.RED}Error analyzing chunk: {str(e)}{Style.RESET_ALL}")

    def is_valid_finding(self, finding):
        """Validate findings to reduce false positives"""
        # Skip if too short
        if len(finding) < 4:
            return False
            
        # Skip if looks like a file path
        if '\\' in finding or '/tmp/' in finding:
            return False
            
        # Skip common false positives
        false_positives = [
            'password:',
            'password=',
            'secret:',
            'secret=',
            'null',
            'undefined'
        ]
        
        if finding.lower() in false_positives:
            return False
            
        return True

    def analyze_file(self, filepath, chunk_size=1024*1024):
        """Analyze heapdump file in chunks"""
        self.stats['start_time'] = datetime.now()
        
        try:
            file_size = os.path.getsize(filepath)
            print(f"{Fore.CYAN}Analyzing file: {filepath} ({file_size/1024/1024:.2f} MB){Style.RESET_ALL}")
            
            with open(filepath, 'rb') as f:
                # Memory map the file for better performance
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    for i in range(0, len(mm), chunk_size):
                        chunk = mm[i:i+chunk_size]
                        self.analyze_chunk(chunk)
                        self.stats['total_bytes_analyzed'] += len(chunk)
                        
                        # Show progress
                        progress = (i + chunk_size) / file_size * 100
                        print(f"\rProgress: {progress:.1f}%", end='')
                        
            print("\n")
            self.stats['end_time'] = datetime.now()
            
        except Exception as e:
            print(f"{Fore.RED}Error analyzing file: {str(e)}{Style.RESET_ALL}")

    def generate_report(self):
        """Generate analysis report"""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'statistics': {
                'duration_seconds': duration.total_seconds(),
                'total_mb_analyzed': self.stats['total_bytes_analyzed'] / 1024 / 1024,
                'findings_by_category': {k: len(v) for k, v in self.findings.items()},
                'total_findings': sum(len(v) for v in self.findings.values())
            },
            'findings': {k: list(v) for k, v in self.findings.items()}
        }
        
        return report

    def save_report(self, report, output_dir):
        """Save report to file"""
        os.makedirs(output_dir, exist_ok=True)
        filename = f"heapdump_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(output_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=4)
            print(f"{Fore.GREEN}Report saved to: {filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error saving report: {str(e)}{Style.RESET_ALL}")

    def print_findings(self):
        """Print findings to console"""
        print(f"\n{Fore.CYAN}=== Analysis Results ==={Style.RESET_ALL}\n")
        
        for category, items in self.findings.items():
            if items:
                print(f"{Fore.YELLOW}{category.upper()}{Style.RESET_ALL}")
                for item in sorted(items):
                    print(f"- {item}")
                print()

    def analyze(self, heapdump_path, output_dir='.'):
        """Main analysis function"""
        if not os.path.exists(heapdump_path):
            print(f"{Fore.RED}File not found: {heapdump_path}{Style.RESET_ALL}")
            return
            
        print(f"{Fore.MAGENTA}Starting heapdump analysis...{Style.RESET_ALL}")
        
        self.analyze_file(heapdump_path)
        self.print_findings()
        
        report = self.generate_report()
        self.save_report(report, output_dir)