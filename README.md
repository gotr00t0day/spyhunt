# DESCRIPTION

![Spyhunt](https://github.com/gotr00t0day/spyhunt/blob/main/spyhunt_logo_cropped.png)

**SpyHunt v4.0 (Security Hardened)** - A comprehensive network scanning and vulnerability assessment tool designed for security professionals and penetration testers. This tool performs comprehensive reconnaissance and vulnerability assessment on target networks and web applications, combining multiple scanning techniques with various external tools to provide extensive security intelligence.

## 🆕 What's New in v4.0

### **5 New Advanced Vulnerability Scanners**
- ✅ **XXE Scanner** - XML External Entity injection detection
- ✅ **SSRF Scanner** - Server-Side Request Forgery detection  
- ✅ **SSTI Scanner** - Server-Side Template Injection (Jinja2, Twig, Freemarker, Velocity, ERB, Smarty)
- ✅ **NoSQL Injection Scanner** - MongoDB and CouchDB injection detection
- ✅ **CRLF Scanner** - HTTP header injection detection

### **Security Enhancements**
- ✅ **Command Injection Protection** - Secure command execution prevents shell injection attacks
- ✅ **SSL Verification Control** - SSL certificate verification enabled by default (use `--insecure` to disable)
- ✅ **Structured Logging** - All operations logged to `spyhunt.log` with rotation
- ✅ **Input Validation** - Comprehensive validation prevents injection attacks
- ✅ **HTTP Session Management** - Connection pooling and automatic retries for better performance

## Here's a high-level overview of its functionality

1. It imports various libraries for network operations, web scraping, and parallel processing.

2. The script defines a colorful banner and sets up command-line argument parsing for different scanning options.

3. It includes multiple scanning functions for different purposes:
   
   **🆕 Advanced Vulnerability Scanners (v4.0)**
   - **XXE (XML External Entity) Injection** - File disclosure, SSRF via XXE, AWS metadata exposure
   - **SSRF (Server-Side Request Forgery)** - Internal network probing, cloud metadata endpoints, bypass techniques
   - **SSTI (Server-Side Template Injection)** - Jinja2, Twig, Freemarker, Velocity, ERB, Smarty detection
   - **NoSQL Injection** - MongoDB and CouchDB authentication bypass and injection
   - **CRLF Injection** - HTTP header injection, response smuggling, XSS via CRLF
   
   **Reconnaissance & Information Gathering**
   - Subdomain enumeration
   - Technology detection
   - DNS record scanning
   - Web crawling and URL extraction
   - Favicon hash calculation
   - IP address extraction
   - Domain information gathering
   - Shodan integration for additional recon
   - Network vulnerability analysis
   - Wayback machine URL retrieval
   - JavaScript file discovery
   - Port Scanning & CIDR Notation Scanning
   
   **Vulnerability Detection**
   - SQL Injection
   - XSS (Cross-Site Scripting)
   - Host header injection testing
   - CORS misconfiguration
   - HTTP request smuggling detection
   - Subdomain Takeover
   - Open Redirect
   - Directory Traversal
   - Local File Inclusion (LFI) scanning with Nuclei
   - 403 Forbidden bypass attempts
   - Security header analysis
   - JSON Web Token vulnerabilities
   - Heap dump analysis
   - DNS zone transfer
   
   **Fuzzing & Brute Forcing**
   - Directory and file brute-forcing
   - API endpoint fuzzing
   - Parameter mining
   - Login form brute-forcing
   - FTP brute-forcing with proxy support
   - SMB password spraying
   
   **Cloud Security**
   - AWS S3 Bucket Enumeration
   - Azure resource scanning
   - GCP Storage scanning
   
   **Other Features**
   - Custom Headers
   - Google dorking
   - Broken link checking
   - Auto Recon
   - JavaScript file scanning for sensitive info
   - Web Server Detection

   
4. The script uses multithreading and multiprocessing to perform scans efficiently.

5. It includes options to save results to files and customize scan parameters.

6. The tool integrates with external tools and APIs like Shodan, Nmap, and various web-based services.

7. It implements various techniques to bypass restrictions and discover vulnerabilities.

8. The script includes a CIDR notation scanner for port scanning across IP ranges.

# INSTALLATION

```bash

git clone https://github.com/gotr00t0day/spyhunt.git

cd spyhunt

pip3 install -r requirements.txt

sudo python3 install.py

```

# USAGE 

```

usage: spyhunt.py [-h] [-sv filename.txt | -wl filename.txt] [-th 25] [-s domain.com]
                  [-d domains.txt] [-p domains.txt] [-r domains.txt] [-b domains.txt]
                  [-pspider domain.com] [-w https://domain.com] [-j domain.com]
                  [-wc https://domain.com] [-fi https://domain.com] [-fm https://domain.com]
                  [-na https://domain.com] [-ri IP] [-rim IP] [-sc domain.com]
                  [-ph domain.txt] [-co domains.txt] [-hh domain.com] [-sh domain.com]
                  [-ed domain.com] [-smu domain.com] [-ips domain list] [-dinfo domain list]
                  [-isubs domain list] [-nft domains.txt] [-n domain.com or IP]
                  [-api domain.com] [-sho domain.com] [-fp domain.com] [-db domain.com]
                  [-cidr IP/24] [-ps 80,443,8443] [-pai IP/24]
                  [-xss https://example.com/page?param=value]
                  [-sqli https://example.com/page?param=value] [-shodan KEY]
                  [-webserver domain.com] [-javascript domain.com] [-dp DEPTH] [-je file.txt]
                  [-hibp password] [-pm domain.com] [-ch domain.com] [-or domain.com]
                  [-asn AS55555] [-st subdomains.txt] [-ar domain.com] [-jwt token]
                  [-jwt-modify token] [-heapds heapdump.txt] [-heapts domain.com]
                  [-f_p domain.com] [-nl] [-nc domain.com] [-nct template.yaml] [-v]
                  [-c CONCURRENCY] [-gs] [-e EXTENSIONS] [-x EXCLUDE] [-u]
                  [--shodan-api SHODAN_API] [--proxy PROXY] [--proxy-file PROXY_FILE]
                  [--heapdump HEAPDUMP] [--output-dir OUTPUT_DIR] [-aws domain.com]
                  [-az domain.com] [--s3-scan S3_SCAN] [-gcp domain.com] [-zt domain.com]
                  [-ssrfp domains.txt] [--ipinfo TARGET] [--token TOKEN]
                  [--save-ranges FILENAME] [--forbidden_domains FORBIDDEN_DOMAINS]
                  [--brute-user-pass domain.com] [--username_wordlist domain.com]
                  [--password_wordlist domain.com] [-fs HOST[:PORT]]
                  [--ftp-userlist users.txt] [--ftp-passlist passwords.txt]
                  [--ftp-proxylist proxies.txt] [--smb_scan] [--smb_auto]
                  [--spray-userlist SPRAY_USERLIST] [--spray-passlist SPRAY_PASSLIST]
                  [--spray-password SPRAY_PASSWORD] [--smb-target SMB_TARGET]
                  [--smb-user SMB_USER] [--smb-pass SMB_PASS] [--smb-domain SMB_DOMAIN]

options:
  -h, --help            show this help message and exit
  -sv, --save filename.txt
                        save output to file
  -wl, --wordlist filename.txt
                        wordlist to use
  -th, --threads 25     default 25
  -p, --probe domains.txt
                        probe domains.
  -r, --redirects domains.txt
                        links getting redirected
  -fi, --favicon https://domain.com
                        get favicon hashes
  -fm, --faviconmulti https://domain.com
                        get favicon hashes
  -ri, --reverseip IP   reverse ip lookup
  -rim, --reverseipmulti IP
                        reverse ip lookup for multiple ips
  -sc, --statuscode domain.com
                        statuscode
  -sh, --securityheaders domain.com
                        scan for security headers
  -ed, --enumeratedomain domain.com
                        enumerate domains
  -isubs, --importantsubdomains domain list
                        extract interesting subdomains from a list like dev, admin, test and etc..
  -webserver, --webserver_scan domain.com
                        webserver scan
  -v, --verbose         Increase output verbosity
  -c, --concurrency CONCURRENCY
                        Maximum number of concurrent requests
  --shodan-api SHODAN_API
                        Shodan API key for subdomain enumeration
  --proxy PROXY         Use a proxy (e.g., http://proxy.com:8080)
  --proxy-file PROXY_FILE
                        Load proxies from file
  --heapdump HEAPDUMP   Analyze Java heapdump file
  --output-dir OUTPUT_DIR
                        Output directory
  --forbidden_domains FORBIDDEN_DOMAINS
                        File containing list of domains to scan for forbidden bypass

Update:
  -u, --update          Update the script

Nuclei Scans:
  -nl, --nuclei_lfi     Find Local File Inclusion with nuclei
  -nc, --nuclei domain.com
                        scan nuclei on a target
  -nct, --nuclei_template template.yaml
                        use a nuclei template

Vulnerability:
  🆕 ADVANCED SCANNERS (v4.0):
  --xxe, --xxe_scan https://example.com/api/xml
                        Scan for XXE (XML External Entity) vulnerabilities
  --ssrf, --ssrf_scan https://example.com/api?url=test
                        Scan for SSRF (Server-Side Request Forgery) vulnerabilities
  --ssti, --ssti_scan https://example.com/page?template=test
                        Scan for SSTI (Server-Side Template Injection) vulnerabilities
  --nosqli, --nosql_scan https://example.com/api?id=test
                        Scan for NoSQL injection vulnerabilities
  --crlf, --crlf_scan https://example.com/redirect?url=test
                        Scan for CRLF injection vulnerabilities
  --callback-url http://your-server.com
                        Callback URL for out-of-band vulnerability testing
  
  STANDARD SCANNERS:
  -b, --brokenlinks domains.txt
                        search for broken links
  -ph, --pathhunt domain.txt
                        check for directory traversal
  -co, --corsmisconfig domains.txt
                        cors misconfiguration
  -hh, --hostheaderinjection domain.com
                        host header injection
  -smu, --smuggler domain.com
                        enumerate domains
  -fp, --forbiddenpass domain.com
                        Bypass 403 forbidden
  -xss, --xss_scan https://example.com/page?param=value
                        scan for XSS vulnerabilities
  -sqli, --sqli_scan https://example.com/page?param=value
                        scan for SQLi vulnerabilities
  -or, --openredirect domain.com
                        open redirect
  -st, --subdomaintakeover subdomains.txt
                        subdomain takeover
  -jwt, --jwt_scan token
                        analyze JWT token for vulnerabilities
  -jwt-modify, --jwt_modify token
                        modify JWT token
  -heapds, --heapdump_file heapdump.txt
                        file for heapdump scan
  -heapts, --heapdump_target domain.com
                        target for heapdump scan
  -zt, --zone-transfer domain.com
                        Test for DNS zone transfer vulnerability
  -ssrfp, --ssrfparams domains.txt
                        Get SSRF parameters from a list of domains

Security Options:
  --insecure            Disable SSL certificate verification (insecure, not recommended)

Crawlers:
  -pspider, --paramspider domain.com
                        extract parameters from a domain
  -w, --waybackurls https://domain.com
                        scan for waybackurls
  -j domain.com         find javascript files
  -wc, --webcrawler https://domain.com
                        scan for urls and js files
  -javascript, --javascript_scan domain.com
                        scan for sensitive info in javascript files
  -dp, --depth DEPTH    Crawling depth (default: 2)
  -je, --javascript_endpoints file.txt
                        extract javascript endpoints
  -hibp, --haveibeenpwned password
                        check if the password has been pwned

Passive Recon:
  -s domain.com         scan for subdomains
  -d, --dns domains.txt
                        scan a list of domains for dns records
  -na, --networkanalyzer https://domain.com
                        net analyzer
  -ips, --ipaddresses domain list
                        get the ips from a list of domains
  -dinfo, --domaininfo domain list
                        get domain information like codes,server,content length
  -sho, --shodan_ domain.com
                        Recon with shodan
  -shodan, --shodan_api KEY
                        shodan api key
  -gs, --google         Google Search

Fuzzing:
  -nft, --not_found domains.txt
                        check for 404 status code
  -api, --api_fuzzer domain.com
                        Look for API endpoints
  -db, --directorybrute domain.com
                        Brute force filenames and directories
  -pm, --param_miner domain.com
                        param miner
  -ch, --custom_headers domain.com
                        custom headers
  -asn, --automoussystemnumber AS55555
                        asn
  -ar, --autorecon domain.com
                        auto recon
  -f_p, --forbidden_pages domain.com
                        forbidden pages
  -e, --extensions EXTENSIONS
                        Comma-separated list of file extensions to scan
  -x, --exclude EXCLUDE
                        Comma-separated list of status codes to exclude

Port Scanning:
  -n, --nmap domain.com or IP
                        Scan a target with nmap
  -cidr, --cidr_notation IP/24
                        Scan an ip range to find assets and services
  -ps, --ports 80,443,8443
                        Port numbers to scan
  -pai, --print_all_ips IP/24
                        Print all ips

Bruteforcing:
  --brute-user-pass domain.com
                        Bruteforcing username and password input fields
  --username_wordlist domain.com
                        Bruteforcing username and password input fields
  --password_wordlist domain.com
                        Bruteforcing username and password input fields

FTP Scanning:
  -fs, --ftp_scan HOST[:PORT]
                        FTP server to scan (e.g., host or host:port)
  --ftp-userlist users.txt
                        Path to a custom username list for FTP bruteforcing
  --ftp-passlist passwords.txt
                        Path to a custom password list for FTP bruteforcing
  --ftp-proxylist proxies.txt
                        Path to a proxy list for FTP bruteforcing (format: socks5://host:port,
                        socks4://host:port, http://host:port, or just IP:PORT for SOCKS5; only working
                        proxies will be used automatically)

Cloud Security:
  -aws, --aws-scan domain.com
                        Scan for exposed AWS resources
  -az, --azure-scan domain.com
                        Scan for exposed Azure resources
  --s3-scan S3_SCAN     Scan for exposed S3 buckets
  -gcp, --gcp-scan domain.com
                        Scan for exposed GCP Storage resources

IP Information:
  --ipinfo TARGET       Get IP info for a company domain/IP
  --token TOKEN         IPinfo API token
  --save-ranges FILENAME
                        Save IP ranges to file

SMB Automated Pentest:
  --smb_scan            Run SMB scan
  --smb_auto            Run automated SMB pentest
  --spray-userlist SPRAY_USERLIST
                        User list for password spraying
  --spray-passlist SPRAY_PASSLIST
                        Password list for password spraying
  --spray-password SPRAY_PASSWORD
                        Single password to test against userlist
  --smb-target SMB_TARGET
                        Target IP or hostname for SMB automation
  --smb-user SMB_USER   Username for credential testing
  --smb-pass SMB_PASS   Password for credential testing
  --smb-domain SMB_DOMAIN
                        Domain for credential testing

# EXAMPLE

Scan for subdomains and save the output to a file.
```
python3 spyhunt.py -s yahoo.com --save filename.txt
```
Scan for subdomains but also extract subdomains from shodan
```
python3 spyhunt.py -s yahoo.com --shodan API_KEY --save filename.txt
```
Scan a file of domains to extract subdomains
```
python3 spyhunt.py -s domains.txt --save filename.txt
```
Scan for javascript files 
```
python3 spyhunt.py -j yahoo.com --depth 4 --save jsfiles.txt -c 20
```
Scan for dns records
```
python3 spyhunt.py -d domains.txt
```
Scan for FavIcon hashes 
```
python3 spyhunt.py -fi domain.com
```
Web Crawler
```
python3 spyhunt.py -wc https://www.domain.com
```
Web Crawler with depth  
```
python3 spyhunt.py -wc https://www.domain.com --depth 5
```
Broken Links
```
python3 spyhunt.py -b https://www.domain.com
```
Cors Misconfiguration Scan
```
python3 spyhunt.py -co domains.txt
```
Host Header Injection
```
python3 spyhunt.py -hh domains.txt
```
Host Header Injection With proxy
```
python3 spyhunt.py -hh domains.txt --proxy http://proxy.com:8080
```
Directory Brute Forcing
```
python3 spyhunt.py --directorybrute domain.com --wordlist list.txt --threads 50 -e php,txt,html -x 404,403
```
Directory Brute Forcing with no extensions
```
python3 spyhunt.py --directorybrute domain.com --wordlist list.txt --threads 50 -x 404,403
```
Scanning a subnet
```
python3 spyhunt.py --cidr_notation IP/24 --ports 80,443 --threads 200
```
Directory Traversal
```
python3 spyhunt.py -ph domain.com?id=
```   
sql injection
```
python3 spyhunt.py -sqli domain.com?id=1
```   
xss
```
python3 spyhunt.py -xss domain.com?id=1
```
JavaScript file scanning for sensitive info
```
python3 spyhunt.py -javascript domain.com
```
Javascript endpoint fuzzing
```
python3 spyhunt.py -javascript_endpoint domains.txt -c 20 --save filename.txt
```
Modify the headers of the request
```
python3 spyhunt.py -ch domain.com
```
Parameter bruteforcing
```
python3 spyhunt.py -pf domain.com
```
Open Redirect
```
python3 spyhunt.py -or domain.com -v -c 50
```
Haveibeenpwned
```
python3 spyhunt.py -hibp password
```
Subdomain Takeover
```
python3 spyhunt.py -st domains.txt --save vuln_subs.txt -c 50 
```
Auto Recon
```
python3 spyhunt.py -ar domain.com
```
JSON Web Token
```
python3 spyhunt.py -jwt Token
```
JSON Web Token Modification
```
python3 spyhunt.py -jwt-modify Token
```
AWS S3 Bucket Enumeration
```
python3 spyhunt.py --s3-scan bucket.com
```
Heap Dump Analysis 
```
python3 spyhunt.py --heapdump heapdump_file
```
Spring Boot Actuator Scan
```
python3 spyhunt.py --heapdump_target domain.com
```
Heap Dump Scan with file
```
python3 spyhunt.py --heapdump_file heapdump.txt
```
Cloud Aws Scan
```
python3 spyhunt.py --aws_scan domain.com
```
Cloud Azure Scan
```
python3 spyhunt.py --azure_scan domain.com
```
Checks for 403 forbidden domains and saves it to a file 
```
python3 spyhunt.py --forbidden_pages domains.txt
```
Scan a list of domains to bypass 403 forbidden
```
python3 spyhunt.py --forbidden_domains domains.txt
```
Scan google storage
```
python3 spyhunt.py --gcp-scan domain.com
```
Brute Forcing Login Forms With Proxies
```
python3 spyhunt.py --brute-user-pass domain.com/login --username_wordlist usernames --password_wordlist passwords --proxy-file proxies.txt --verbose
```
Brute Forcing Login Forms Witout Proxies
```
python3 spyhunt.py --brute-user-pass domain.com/login --username_wordlist usernames --password_wordlist passwords --verbose
```
Nuclei Scan
```
python3 spyhunt.py --nuclei domain.com --nuclei-template nuclei-templates/cves/CVE-2024-22208.yaml
```
SSRF Params
```
python3 spyhunt.py --ssrfparams links.txt
```
FTP Scan
```
python3 spyhunt.py -fs domain.com
```
FTP Scan with a port
```
python3 spyhunt.py -fs domain.com:2121
```
FTP Scan with userlist and passlist
```
python3 spyhunt.py -fs domain.com --ftp-userlist usernames.txt --ftp-passlist passwords.txt
```
SMB Automated Pentest (Anonymous, Blank Creds, RID Brute)
```
python3 spyhunt.py --smb_auto --smb-target 10.129.228.111
```
SMB Pentest with Specific Credentials
```
python3 spyhunt.py --smb_auto --smb-target 10.129.228.111 --smb-user mhope --smb-pass ""
```
SMB Pentest with Domain Credentials
```
python3 spyhunt.py --smb_auto --smb-target 10.129.228.111 --smb-user mhope --smb-pass "" --smb-domain megabank.local
```
SMB Password Spraying with User and Password Lists
```
python3 spyhunt.py --smb_auto --smb-target 10.129.228.111 --spray-userlist users.txt --spray-passlist passwords.txt
```
SMB Password Spraying with Single Password
```
python3 spyhunt.py --smb_auto --smb-target 10.129.228.111 --spray-userlist users.txt --spray-password "Password1"
```
SMB Full Pentest (Credentials + Password Spray)
```
python3 spyhunt.py --smb_auto --smb-target 10.129.228.111 --smb-user mhope --smb-pass "" --spray-userlist users.txt --spray-password "Welcome1"
```

## 🆕 New Advanced Vulnerability Scanners (v4.0)

### XXE (XML External Entity) Scanner
Test for XXE vulnerabilities in XML endpoints:
```bash
# Basic XXE scan
python3 spyhunt.py --xxe https://example.com/api/xml

# With custom callback URL for out-of-band detection
python3 spyhunt.py --xxe https://example.com/api/xml --callback-url http://your-server.com

# Save results to file
python3 spyhunt.py --xxe https://example.com/api/xml --save xxe_results.json

# With verbose logging
python3 spyhunt.py --xxe https://example.com/api/xml -v
```

**What it detects:**
- Classic XXE with callback
- Blind XXE
- File disclosure (Linux: `/etc/passwd`, Windows: `win.ini`)
- SSRF via XXE
- AWS metadata exposure

### SSRF (Server-Side Request Forgery) Scanner
Test for SSRF vulnerabilities:
```bash
# Basic SSRF scan
python3 spyhunt.py --ssrf "https://example.com/api?url=test"

# With callback domain
python3 spyhunt.py --ssrf "https://example.com/api?url=test" --callback-url http://your-domain.com

# Save results
python3 spyhunt.py --ssrf "https://example.com/fetch?url=test" --save ssrf_results.json
```

**What it detects:**
- Internal network access (127.0.0.1, localhost, 0.0.0.0)
- Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean, Oracle)
- Bypass techniques (octal, hex, decimal encoding, DNS rebinding)
- File disclosure via `file://` protocol
- Port scanning via SSRF

### SSTI (Server-Side Template Injection) Scanner
Test for template injection vulnerabilities:
```bash
# Basic SSTI scan
python3 spyhunt.py --ssti "https://example.com/page?template=test"

# Multiple parameters
python3 spyhunt.py --ssti "https://example.com/render?name=test&title=hello"

# Save results
python3 spyhunt.py --ssti "https://example.com/view?template=test" --save ssti_results.json
```

**Template engines detected:**
- Jinja2 (Python/Flask)
- Twig (PHP/Symfony)
- Freemarker (Java)
- Velocity (Java)
- ERB (Ruby/Rails)
- Smarty (PHP)

### NoSQL Injection Scanner
Test for NoSQL injection in MongoDB and CouchDB:
```bash
# Basic NoSQL injection scan
python3 spyhunt.py --nosqli "https://example.com/api?id=test"

# User authentication endpoint
python3 spyhunt.py --nosqli "https://example.com/api/login?username=test&password=test"

# Save results
python3 spyhunt.py --nosqli "https://example.com/api/users?id=test" --save nosql_results.json
```

**What it detects:**
- Authentication bypass
- Operator injection (`$ne`, `$gt`, `$regex`, `$where`)
- Time-based blind injection
- JavaScript injection in MongoDB

### CRLF Injection Scanner
Test for HTTP header injection vulnerabilities:
```bash
# Basic CRLF scan
python3 spyhunt.py --crlf "https://example.com/redirect?url=test"

# Multiple URL parameters
python3 spyhunt.py --crlf "https://example.com/page?ref=test&return=home"

# Save results
python3 spyhunt.py --crlf "https://example.com/goto?url=test" --save crlf_results.json
```

**What it detects:**
- Set-Cookie header injection
- Location header manipulation
- HTTP response smuggling
- XSS via CRLF injection

### Security Features

#### SSL Verification Control
```bash
# SSL verification ON by default (recommended)
python3 spyhunt.py --xxe https://example.com/api/xml

# Disable SSL verification for testing (not recommended for production)
python3 spyhunt.py --xxe https://self-signed.local/api/xml --insecure
```

#### Logging
All operations are automatically logged to `spyhunt.log`:
```bash
# Enable verbose logging
python3 spyhunt.py --xxe https://example.com/api/xml --verbose

# View logs in real-time
tail -f spyhunt.log

# Search logs
grep "XXE vulnerability" spyhunt.log
```

### Bug Bounty Workflow Example
```bash
# 1. Enumerate subdomains
python3 spyhunt.py -s target.com --save subdomains.txt

# 2. Probe for live hosts
python3 spyhunt.py -p subdomains.txt --save live_hosts.txt

# 3. Run comprehensive vulnerability scans
python3 spyhunt.py --xxe https://api.target.com/xml --save xxe_findings.json
python3 spyhunt.py --ssrf "https://api.target.com/fetch?url=test" --save ssrf_findings.json
python3 spyhunt.py --ssti "https://target.com/render?template=test" --save ssti_findings.json
python3 spyhunt.py --nosqli "https://api.target.com/users?id=test" --save nosql_findings.json
python3 spyhunt.py --crlf "https://target.com/redirect?url=test" --save crlf_findings.json

# 4. Traditional vulnerability scans
python3 spyhunt.py --xss "https://target.com/search?q=test"
python3 spyhunt.py --sqli "https://target.com/product?id=1"
python3 spyhunt.py -co live_hosts.txt
```

## Documentation

For detailed information:
- **NEW_FEATURES_README.md** - Quick start guide for v4.0 features
- **INTEGRATION_COMPLETE.md** - Complete integration details
- **SECURITY_ANALYSIS_REPORT.md** - Comprehensive security analysis
- **WHAT_CHANGED.md** - Summary of changes from v3.4 to v4.0

## Security Notes

### Default Security Settings (v4.0)
- ✅ SSL certificate verification is **enabled by default**
- ✅ All operations are logged to `spyhunt.log`
- ✅ Command injection protection is active
- ✅ Input validation prevents injection attacks

### Best Practices
1. Always use SSL verification in production (`--insecure` only for testing)
2. Review logs regularly for security events
3. Save scan results with `--save` for documentation
4. Use `--verbose` for detailed debugging
5. Test on authorized targets only

## Version History

### v4.0 (Security Hardened) - October 2025
- ➕ Added XXE Scanner
- ➕ Added SSRF Scanner
- ➕ Added SSTI Scanner
- ➕ Added NoSQL Injection Scanner
- ➕ Added CRLF Injection Scanner
- 🔒 Fixed command injection vulnerabilities
- 🔒 Added SSL verification control
- 📝 Added structured logging system
- ⚡ Added HTTP session management
- 🛡️ Added input validation framework

### v3.4 and earlier
- See git history for previous changes