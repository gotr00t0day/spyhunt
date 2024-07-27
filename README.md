
# INSTALLATION

```bash

git clone https://github.com/gotr00t0day/spyhunt.git

cd spyhunt

pip3 install -r requirements.txt

sudo python3 install.py

```

# USAGE 

```
usage: spyhunt.py [-h] [-sv filename.txt] [-s domain.com] [-j domain.com] [-t domain.com] [-d domain.com]
                  [-p domains.txt] [-r domains.txt] [-b domains.txt] [-w https://domain.com]
                  [-wc https://domain.com] [-fi https://domain.com] [-fm https://domain.com]
                  [-na https://domain.com] [-ri IP] [-rim IP] [-sc domain.com] [-co domains.txt]
                  [-hh domain.com] [-sh domain.com] [-ed domain.com] [-smu domain.com] [-rd domain list]
                  [-ips domain list] [-dinfo domain list] [-isubs domain list] [-pspider domain.com]
                  [-nft domains.txt] [-ph domain.txt]

options:
  -h, --help            show this help message and exit
  -sv filename.txt, --save filename.txt
                        save output to file
  -s domain.com         scan for subdomains
  -j domain.com         find javascript files
  -t domain.com, --tech domain.com
                        find technologies
  -d domain.com, --dns domain.com
                        scan for dns records
  -p domains.txt, --probe domains.txt
                        probe domains.
  -r domains.txt, --redirects domains.txt
                        links getting redirected
  -b domains.txt, --brokenlinks domains.txt
                        search for broken links
  -w https://domain.com, --waybackurls https://domain.com
                        scan for waybackurls
  -wc https://domain.com, --webcrawler https://domain.com
                        scan for urls and js files
  -fi https://domain.com, --favicon https://domain.com
                        get favicon hashes
  -fm https://domain.com, --faviconmulti https://domain.com
                        get favicon hashes
  -na https://domain.com, --networkanalyzer https://domain.com
                        net analyzer
  -ri IP, --reverseip IP
                        reverse ip lookup
  -rim IP, --reverseipmulti IP
                        reverse ip lookup for multiple ips
  -sc domain.com, --statuscode domain.com
                        statuscode
  -co domains.txt, --corsmisconfig domains.txt
                        cors misconfiguration
  -hh domain.com, --hostheaderinjection domain.com
                        host header injection
  -sh domain.com, --securityheaders domain.com
                        scan for security headers
  -ed domain.com, --enumeratedomain domain.com
                        enumerate domains
  -smu domain.com, --smuggler domain.com
                        enumerate domains
  -rd domain list, --redirect domain list
                        get redirect links
  -ips domain list, --ipaddresses domain list
                        get the ips from a list of domains
  -dinfo domain list, --domaininfo domain list
                        get domain information like codes,server,content length
  -isubs domain list, --importantsubdomains domain list
                        extract interesting subdomains from a list like dev, admin, test and etc..
  -pspider domain.com, --paramspider domain.com
                        extract parameters from a domain
  -nft domains.txt, --not_found domains.txt
                        check for 404 status code
  -ph domain.txt, --pathhunt domain.txt
                        check for directory traversal      
  -n domain.com or IP, --nmap domain.com or IP
                        Scan a target with nmap
  -api domain.com, --api_fuzzer domain.com
                        Look for API endpoints
  -sho domain.com, --shodan domain.com
                        Recon with shodan
  -fp domain.com, --forbiddenpass domain.com
                        Bypass 403 forbidden        
```


# EXAMPLE

Scan for subdomains and save the output to a file.
```
python3 spyhunt.py -s yahoo.com --save filename.txt
```
Scan for javascript files 
```
python3 spyhunt.py -j yahoo.com
```
Scan for dns records
```
python3 spyhunt.py -d yahoo.com
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
