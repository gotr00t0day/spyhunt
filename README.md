
# INSTALLATION

```bash

git clone https://github.com/gotr00t0day/spyhunt.git

cd spyhunt

sudo python3 install.py

```

# USAGE 

```
usage: spyhunt.py [-h] [-sv filename.txt] [-s domain.com] [-j domain.com] [-t domain.com] [-d domain.com] [-p domains.txt] [-a domains.txt] [-r domains.txt] [-b domains.txt]

optional arguments:
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
  -a domains.txt, --aquatone domains.txt
                        take screenshots of domains.
  -r domains.txt, --redirects domains.txt
                        links getting redirected
  -b domains.txt, --brokenlinks domains.txt
                        search for broken links                                          
```

# EXAMPLE

Scan for subdomains and save the output to a file.
```
sudo python3 spyhunt.py -s yahoo.com --save filename.txt
```
Scan for javascript files 
```
sudo python3 spyhunt -j yahoo.com
```
Scan for dns records
```
sudo python3 spyhunt -d yahoo.com
```

