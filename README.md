# DESCRIPTION

![Spyhunt](https://github.com/gotr00t0day/spyhunt/blob/main/spyhunt_logo_cropped.png)

Spyhunt is comprehensive network scanning and vulnerability assessment tool. This tool is designed for security professionals and penetration testers to perform comprehensive reconnaissance and vulnerability assessment on target networks and web applications. It combines multiple scanning techniques and integrates various external tools to provide a wide range of information about the target.

## Here's a high-level overview of its functionality

1. It imports various libraries for network operations, web scraping, and parallel processing.

2. The script defines a colorful banner and sets up command-line argument parsing for different scanning options.

3. It includes multiple scanning functions for different purposes:
   - Subdomain enumeration
   - Technology detection
   - DNS record scanning
   - Web crawling and URL extraction
   - Favicon hash calculation
   - Host header injection testing
   - Security header analysis
   - Network vulnerability analysis
   - Wayback machine URL retrieval
   - JavaScript file discovery
   - Broken link checking
   - HTTP request smuggling detection
   - IP address extraction
   - Domain information gathering
   - API endpoint fuzzing
   - Shodan integration for additional recon
   - 403 Forbidden bypass attempts
   - Directory and file brute-forcing
   - Local File Inclusion (LFI) scanning with Nuclei
   - Google dorking
   - Directory Traversal
   - SQL Injection
   - XSS
   - Subdomain Takeover
   - Web Server Detection
   - JavaScript file scanning for sensitive info
   - Auto Recon
   - Port Scanning
   - CIDR Notation Scanning
   - Custom Headers
   - API Fuzzing
   - AWS S3 Bucket Enumeration
   - JSON Web Token Scanning

   
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