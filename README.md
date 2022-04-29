
# INSTALLATION

```bash

git clone https://github.com/gotr00t0day/spyhunt.git

cd spyhunt

pip3 install -r requirements.txt

sudo python3 install.py

```

# USAGE 

```
usage: spyhunt.py [-h] [-sv filename.txt] [-s domain.com] [-ri IP] [-rim IP] [-sc domain.com]
                  [-j domain.com] [-t domain.com] [-d domain.com] [-p domains.txt]
                  [-a domains.txt] [-r domains.txt] [-b domains.txt] [-w https://domain.com]
                  [-wc https://domain.com] [-fi https://domain.com] [-fm https://domain.com]

optional arguments:
  -h, --help            show this help message and exit
  -sv filename.txt, --save filename.txt
                        save output to file
  -s domain.com         scan for subdomains
  -ri IP, --reverseip IP
                        reverse ip lookup
  -rim IP, --reverseipmulti IP
                        reverse ip lookup for multiple ips
  -sc domain.com, --statuscode domain.com
                        statuscode
  -j domain.com         find javascript files
  -t domain.com, --tech domain.com
                        find technologies
  -d domain.com, --dns domain.com
                        scan for dns records
  -p domains.txt, --probe domains.txt
                        probe domains.
  -a domains.txt, --aquatone domains.txt
                        take screenshots of domains.
  -r domains.txt, --redirects domains.txt
                        links getting redirected
  -b domains.txt, --brokenlinks domains.txt
                        search for broken links
  -w https://domain.com, --waybackurls https://domain.com
                        scan for waybackurls
  -wc https://domain.com, --webcrawler https://domain.com
                        scan for urls and js files
  -fi https://domain.com, --favicon domain.com
                        get favicon hashes
  -fm https://domain.com, --faviconmulti domains.txt
                        get favicon hashes                                       
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

