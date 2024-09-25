
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
   - Web Server Detection
   - JavaScript file scanning for sensitive info

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

# DEMO

[![asciicast](https://asciinema.org/a/bCVk2NRnb5TJ7aVLV5ZIcnVa3.png)](https://asciinema.org/a/bCVk2NRnb5TJ7aVLV5ZIcnVa3)

# USAGE 

```

usage: spyhunt.py [-h] [-sv filename.txt | -wl filename.txt] [-th 25] [-s domain.com] [-t domain.com] [-d domains.txt] [-p domains.txt] [-r domains.txt]
                  [-b domains.txt] [-pspider domain.com] [-w https://domain.com] [-j domain.com] [-wc https://domain.com] [-fi https://domain.com]
                  [-fm https://domain.com] [-na https://domain.com] [-ri IP] [-rim IP] [-sc domain.com] [-ph domain.txt] [-co domains.txt] [-hh domain.com]
                  [-sh domain.com] [-ed domain.com] [-smu domain.com] [-ips domain list] [-dinfo domain list] [-isubs domain list] [-nft domains.txt]
                  [-n domain.com or IP] [-api domain.com] [-sho domain.com] [-fp domain.com] [-db domain.com] [-cidr IP/24] [-ps 80,443,8443] [-pai IP/24]
                  [-xss https://example.com/page?param=value] [-sqli https://example.com/page?param=value] [-shodan KEY] [-webserver domain.com]
                  [-javascript domain.com] [-dp 10] [-je file.txt] [-pm domain.com] [-ch domain.com] [-or domain.com] [-asn AS55555] [-v] [-c CONCURRENCY]
                  [-nl] [-gs] [-e EXTENSIONS] [-x EXCLUDE] [-u] [--shodan-api SHODAN_API]

options:
  -h, --help            show this help message and exit
  -sv filename.txt, --save filename.txt
                        save output to file
  -wl filename.txt, --wordlist filename.txt
                        wordlist to use
  -th 25, --threads 25  default 25
  -p domains.txt, --probe domains.txt
                        probe domains.
  -r domains.txt, --redirects domains.txt
                        links getting redirected
  -fi https://domain.com, --favicon https://domain.com
                        get favicon hashes
  -fm https://domain.com, --faviconmulti https://domain.com
                        get favicon hashes
  -ri IP, --reverseip IP
                        reverse ip lookup
  -rim IP, --reverseipmulti IP
                        reverse ip lookup for multiple ips
  -sc domain.com, --statuscode domain.com
                        statuscode
  -sh domain.com, --securityheaders domain.com
                        scan for security headers
  -ed domain.com, --enumeratedomain domain.com
                        enumerate domains
  -isubs domain list, --importantsubdomains domain list
                        extract interesting subdomains from a list like dev, admin, test and etc..
  -webserver domain.com, --webserver_scan domain.com
                        webserver scan
  -v, --verbose         Increase output verbosity
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Maximum number of concurrent requests
  --shodan-api SHODAN_API
                        Shodan API key for subdomain enumeration

Update:
  -u, --update          Update the script

Nuclei Scans:
  -nl, --nuclei_lfi     Find Local File Inclusion with nuclei

Vulnerability:
  -b domains.txt, --brokenlinks domains.txt
                        search for broken links
  -ph domain.txt, --pathhunt domain.txt
                        check for directory traversal
  -co domains.txt, --corsmisconfig domains.txt
                        cors misconfiguration
  -hh domain.com, --hostheaderinjection domain.com
                        host header injection
  -smu domain.com, --smuggler domain.com
                        enumerate domains
  -fp domain.com, --forbiddenpass domain.com
                        Bypass 403 forbidden
  -xss https://example.com/page?param=value, --xss_scan https://example.com/page?param=value
                        scan for XSS vulnerabilities
  -sqli https://example.com/page?param=value, --sqli_scan https://example.com/page?param=value
                        scan for SQLi vulnerabilities
  -or domain.com, --openredirect domain.com
                        open redirect

Crawlers:
  -pspider domain.com, --paramspider domain.com
                        extract parameters from a domain
  -w https://domain.com, --waybackurls https://domain.com
                        scan for waybackurls
  -j domain.com         find javascript files
  -wc https://domain.com, --webcrawler https://domain.com
                        scan for urls and js files
  -javascript domain.com, --javascript_scan domain.com
                        scan for sensitive info in javascript files
  -dp 10, --depth 10    depth of the crawl
  -je file.txt, --javascript_endpoints file.txt
                        extract javascript endpoints

Passive Recon:
  -s domain.com         scan for subdomains
  -t domain.com, --tech domain.com
                        find technologies
  -d domains.txt, --dns domains.txt
                        scan a list of domains for dns records
  -na https://domain.com, --networkanalyzer https://domain.com
                        net analyzer
  -ips domain list, --ipaddresses domain list
                        get the ips from a list of domains
  -dinfo domain list, --domaininfo domain list
                        get domain information like codes,server,content length
  -sho domain.com, --shodan domain.com
                        Recon with shodan
  -shodan KEY, --shodan_api KEY
                        shodan api key
  -gs, --google         Google Search

Fuzzing:
  -nft domains.txt, --not_found domains.txt
                        check for 404 status code
  -api domain.com, --api_fuzzer domain.com
                        Look for API endpoints
  -db domain.com, --directorybrute domain.com
                        Brute force filenames and directories
  -pm domain.com, --param_miner domain.com
                        param miner
  -ch domain.com, --custom_headers domain.com
                        custom headers
  -asn AS55555, --automoussystemnumber AS55555
                        asn
  -e EXTENSIONS, --extensions EXTENSIONS
                        Comma-separated list of file extensions to scan
  -x EXCLUDE, --exclude EXCLUDE
                        Comma-separated list of status codes to exclude

Port Scanning:
  -n domain.com or IP, --nmap domain.com or IP
                        Scan a target with nmap
  -cidr IP/24, --cidr_notation IP/24
                        Scan an ip range to find assets and services
  -ps 80,443,8443, --ports 80,443,8443
                        Port numbers to scan
  -pai IP/24, --print_all_ips IP/24
                        Print all ips
```


# EXAMPLE

Scan for subdomains and save the output to a file.
```
python3 spyhunt.py -s yahoo.com --save filename.txt
```
Scan for  subdomains but also extract subdomains from shodan
```
python3 spyhunt.py -s yahoo.com --shodan API_KEY --save filename.txt
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

