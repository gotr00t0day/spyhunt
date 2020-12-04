from shutil import which
from colorama import Fore, Back, Style
from os import path
import os.path
import os
import subprocess

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

# colorama 

commands("sudo pip3 install colorama")

# golang

commands("sudo apt install golang")


if which("dnsx"):
    pass
else:
    home = os.environ['HOME']
    commands("GO111MODULE=on go get -u -v github.com/projectdiscovery/dnsx/cmd/dnsx | cd {}/go/bin | sudo mv {}/go/bin/dnsx /usr/local/bin".format(home, home))
    if which("dnsx"):
        print(Fore.GREEN + "dnsx installed successfully")

if which("subfinder"):
    pass
else:
    home = os.environ['HOME'] 
    commands("GO111MODULE=on go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder | cd {}/go/bin | sudo mv {}/go/bin/subfinder /usr/local/bin".format(home, home))
    if which("subfinder"):
        print(Fore.GREEN + "subfinder installed successfully")

if which("jq"):
    pass
else:
    commands("sudo apt install jq")
    if which("jq"):
        print(Fore.GREEN + "jq installed successfully")

if which("waybackurls"):
    pass
else:
    home = os.environ['HOME'] 
    commands("go get github.com/tomnomnom/waybackurls | cd {}/go/bin | sudo mv {}/go/bin/waybackurls /usr/local/bin".format(home, home))
    if which("waybackurls"):
        print(Fore.GREEN + "installed successfully")

if which("httprobe"):
    pass
else:
    home = os.environ['HOME']  
    commands("go get -u github.com/tomnomnom/httprobe | cd {}/go/bin | sudo mv {}/go/bin/httprobe /usr/local/bin".format(home, home))

if which("httpx"):
    pass
else:
    home = os.environ['HOME']  
    commands("GO111MODULE=auto go get -u -v github.com/projectdiscovery/httpx/cmd/httpx | cd {}/go/bin | sudo mv {}/go/bin/httpx /usr/local/bin".format(home, home))
    if which("httpx"):
        print(Fore.GREEN + "httpx installed successfully")

if which("anew"):
    pass
else:
    home = os.environ['HOME']  
    commands("go get -u github.com/tomnomnom/anew | cd {}/go/bin | sudo mv {}/go/bin/anew /usr/local/bin".format(home, home))
    if which("anew"):
        print(Fore.GREEN + "anew installed successfully")

if which("gau"):
    pass
else:
    home = os.environ['HOME']  
    commands("GO111MODULE=on go get -u -v github.com/lc/gau | cd {}/go/bin | sudo mv {}/go/bin/gau /usr/local/bin".format(home, home))
    if which("gau"):
        print(Fore.GREEN + "gau installed successfully")
