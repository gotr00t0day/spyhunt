"""
Security Utilities Module for SpyHunt
Provides secure wrappers and utility functions for common operations
"""

import re
import shlex
import subprocess
import logging
import ipaddress
from typing import Optional, List, Dict, Union
from pathlib import Path
from functools import wraps
from time import time, sleep
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass


class InputValidator:
    """Validates user inputs to prevent injection attacks"""
    
    @staticmethod
    def validate_domain(domain: str) -> str:
        """
        Validate domain name format
        
        Args:
            domain: Domain name to validate
            
        Returns:
            Validated domain name
            
        Raises:
            ValueError: If domain format is invalid
        """
        # Remove http(s):// prefix if present
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        
        # Domain regex pattern
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(pattern, domain):
            raise ValueError(f"Invalid domain format: {domain}")
        
        # Additional check for suspicious characters
        if any(char in domain for char in [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r']):
            raise SecurityError(f"Potentially malicious domain input detected: {domain}")
        
        return domain
    
    @staticmethod
    def validate_ip(ip: str) -> str:
        """
        Validate IP address format
        
        Args:
            ip: IP address to validate
            
        Returns:
            Validated IP address
            
        Raises:
            ValueError: If IP format is invalid
        """
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")
    
    @staticmethod
    def validate_url(url: str) -> str:
        """
        Validate URL format
        
        Args:
            url: URL to validate
            
        Returns:
            Validated URL
            
        Raises:
            ValueError: If URL format is invalid
        """
        # Basic URL validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(url):
            raise ValueError(f"Invalid URL format: {url}")
        
        # Check for suspicious patterns
        if any(char in url for char in ['\n', '\r', '\x00']):
            raise SecurityError(f"Potentially malicious URL input detected: {url}")
        
        return url
    
    @staticmethod
    def validate_file_path(filepath: str, base_dir: str = ".") -> Path:
        """
        Validate file path to prevent directory traversal
        
        Args:
            filepath: File path to validate
            base_dir: Base directory to restrict access to
            
        Returns:
            Validated Path object
            
        Raises:
            SecurityError: If path traversal is detected
        """
        try:
            base = Path(base_dir).resolve()
            target = Path(filepath).resolve()
            
            # Ensure target is within base directory
            target.relative_to(base)
            return target
        except (ValueError, RuntimeError):
            raise SecurityError(f"Path traversal detected: {filepath}")
    
    @staticmethod
    def validate_port(port: Union[int, str]) -> int:
        """
        Validate port number
        
        Args:
            port: Port number to validate
            
        Returns:
            Validated port number
            
        Raises:
            ValueError: If port is invalid
        """
        try:
            port = int(port)
            if not 1 <= port <= 65535:
                raise ValueError(f"Port must be between 1 and 65535: {port}")
            return port
        except ValueError as e:
            raise ValueError(f"Invalid port number: {port}") from e


class SecureCommandExecutor:
    """Safely execute system commands without shell injection vulnerabilities"""
    
    @staticmethod
    def execute_command(cmd: Union[str, List[str]], 
                       timeout: int = 300,
                       check: bool = True) -> subprocess.CompletedProcess:
        """
        Execute command safely without shell injection
        
        Args:
            cmd: Command to execute (string or list)
            timeout: Command timeout in seconds
            check: Whether to raise exception on non-zero exit code
            
        Returns:
            CompletedProcess object
            
        Raises:
            subprocess.TimeoutExpired: If command times out
            subprocess.CalledProcessError: If command fails and check=True
        """
        try:
            # Convert string to list for safe execution
            if isinstance(cmd, str):
                cmd = shlex.split(cmd)
            
            logger.debug(f"Executing command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                shell=False,  # NEVER use shell=True
                timeout=timeout,
                capture_output=True,
                text=True,
                check=check
            )
            
            logger.debug(f"Command completed with code {result.returncode}")
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {cmd}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with code {e.returncode}: {cmd}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error executing command: {e}")
            raise


class RateLimiter:
    """Rate limiter for API calls and requests"""
    
    def __init__(self, max_calls: int, period: float):
        """
        Initialize rate limiter
        
        Args:
            max_calls: Maximum number of calls allowed
            period: Time period in seconds
        """
        self.max_calls = max_calls
        self.period = period
        self.calls: List[float] = []
    
    def __call__(self, func):
        """Decorator to rate limit function calls"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time()
            
            # Remove calls outside the time window
            self.calls = [c for c in self.calls if now - c < self.period]
            
            # If limit reached, wait
            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                logger.info(f"Rate limit reached, sleeping for {sleep_time:.2f}s")
                sleep(sleep_time)
                # Re-check after sleeping
                now = time()
                self.calls = [c for c in self.calls if now - c < self.period]
            
            # Record this call
            self.calls.append(time())
            
            # Execute function
            return func(*args, **kwargs)
        
        return wrapper
    
    def wait_if_needed(self):
        """Manually wait if rate limit is reached"""
        now = time()
        self.calls = [c for c in self.calls if now - c < self.period]
        
        if len(self.calls) >= self.max_calls:
            sleep_time = self.period - (now - self.calls[0])
            logger.info(f"Rate limit reached, sleeping for {sleep_time:.2f}s")
            sleep(sleep_time)
        
        self.calls.append(time())


class SecureHTTPSession:
    """Secure HTTP session with connection pooling and retry logic"""
    
    def __init__(self, 
                 max_retries: int = 3,
                 pool_connections: int = 10,
                 pool_maxsize: int = 20,
                 verify_ssl: bool = True,
                 timeout: int = 10):
        """
        Initialize secure HTTP session
        
        Args:
            max_retries: Maximum number of retries
            pool_connections: Number of connection pools
            pool_maxsize: Maximum size of connection pool
            verify_ssl: Whether to verify SSL certificates
            timeout: Default timeout for requests
        """
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        # Configure adapter with connection pooling
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize
        )
        
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        if not verify_ssl:
            logger.warning("SSL verification is disabled - this is insecure!")
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request with default settings"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, **kwargs)
    
    def post(self, url: str, **kwargs) -> requests.Response:
        """Make POST request with default settings"""
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('timeout', self.timeout)
        return self.session.post(url, **kwargs)
    
    def close(self):
        """Close session"""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


class OutputSanitizer:
    """Sanitize output to prevent injection in reports"""
    
    @staticmethod
    def sanitize_html(text: str) -> str:
        """Sanitize text for HTML output"""
        import html
        return html.escape(text)
    
    @staticmethod
    def sanitize_xml(text: str) -> str:
        """Sanitize text for XML output"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&apos;'))
    
    @staticmethod
    def sanitize_text(text: str) -> str:
        """Remove control characters from text"""
        return re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Remove directory separators and dangerous characters
        filename = re.sub(r'[/\\:*?"<>|]', '_', filename)
        # Remove leading/trailing dots and spaces
        filename = filename.strip('. ')
        # Ensure filename is not empty
        if not filename:
            filename = 'output'
        return filename


class SecretDetector:
    """Detect secrets and sensitive information in text"""
    
    PATTERNS = {
        'aws_access_key': r'AKIA[0-9A-Z]{16}',
        'aws_secret_key': r'aws_secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
        'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
        'password': r'password["\']?\s*[:=]\s*["\']?([^\s"\']{8,})',
        'token': r'token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'private_key': r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'github_token': r'gh[pousr]_[a-zA-Z0-9]{36,}',
        'slack_token': r'xox[baprs]-[0-9a-zA-Z]{10,}',
        'stripe_key': r'sk_live_[0-9a-zA-Z]{24,}',
        'google_api': r'AIza[0-9A-Za-z\-_]{35}',
    }
    
    @classmethod
    def detect_secrets(cls, text: str) -> List[Dict[str, any]]:
        """
        Detect secrets in text
        
        Args:
            text: Text to scan for secrets
            
        Returns:
            List of detected secrets with type and matches
        """
        secrets = []
        
        for secret_type, pattern in cls.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Limit matches to prevent output flooding
                limited_matches = matches[:5]
                secrets.append({
                    'type': secret_type,
                    'count': len(matches),
                    'matches': limited_matches
                })
                
                logger.warning(f"Detected {secret_type}: {len(matches)} occurrences")
        
        return secrets


# Convenience functions for quick access
validate_domain = InputValidator.validate_domain
validate_ip = InputValidator.validate_ip
validate_url = InputValidator.validate_url
validate_port = InputValidator.validate_port
validate_file_path = InputValidator.validate_file_path
execute_command = SecureCommandExecutor.execute_command


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.DEBUG)
    
    # Test domain validation
    try:
        valid_domain = validate_domain("example.com")
        print(f"Valid domain: {valid_domain}")
        
        invalid_domain = validate_domain("example.com; rm -rf /")
    except (ValueError, SecurityError) as e:
        print(f"Caught security error: {e}")
    
    # Test command execution
    try:
        result = execute_command("ls -la")
        print(f"Command output: {result.stdout[:100]}")
    except subprocess.SubprocessError as e:
        print(f"Command failed: {e}")
    
    # Test secret detection
    test_text = """
    aws_access_key_id = AKIAIOSFODNN7EXAMPLE
    api_key = "sk_test_EXAMPLE_KEY_NOT_REAL_12345"
    password = "SuperSecret123!"
    """
    
    secrets = SecretDetector.detect_secrets(test_text)
    print(f"\nDetected secrets: {len(secrets)}")
    for secret in secrets:
        print(f"  - {secret['type']}: {secret['count']} occurrences")

