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

# nodejs

commands("sudo apt install nodejs")

# npm
commands("sudo apt install npm")

# brokenlinkchecker
if which("nodejs"):
    print(Fore.GREEN + "Found nodejs")
if which("npm"):
    print(Fore.GREEN + "Found npm")
    command("npm install broken-link-checker -g")

home = os.environ['HOME']

if which("dnsx"):
    pass
else:
    commands("go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest | cd {}/go/bin | sudo mv {}/go/bin/dnsx /usr/local/bin".format(home, home))
    if which("dnsx"):
        print(Fore.GREEN + "dnsx installed successfully")

if which("aquatone"):
    pass
else:
    filepath = os.path.abspath(os.getcwd())
    commands("wget -O aquatone.zip https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip | sudo mv {}/aquatone /usr/local/bin".format(filepath))
    if which("aquatone"):
        print(Fore.GREEN + "aquatone installed successfully")

if which("subfinder"):
    pass
else:
    commands("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest | cd {}/go/bin | sudo mv {}/go/bin/subfinder /usr/local/bin".format(home, home))
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
    commands("go install github.com/tomnomnom/waybackurls@latest | cd {}/go/bin | sudo mv {}/go/bin/waybackurls /usr/local/bin".format(home, home))
    if which("waybackurls"):
        print(Fore.GREEN + "installed successfully")

if which("httprobe"):
    pass
else: 
    commands("go install github.com/tomnomnom/httprobe@latest | cd {}/go/bin | sudo mv {}/go/bin/httprobe /usr/local/bin".format(home, home))

if which("httpx"):
    pass
else: 
    commands("go install github.com/projectdiscovery/httpx/cmd/httpx@latest | cd {}/go/bin | sudo mv {}/go/bin/httpx /usr/local/bin".format(home, home))
    if which("httpx"):
        print(Fore.GREEN + "httpx installed successfully")

if which("anew"):
    pass
else:
    commands("go install github.com/tomnomnom/anew@latest | cd {}/go/bin | sudo mv {}/go/bin/anew /usr/local/bin".format(home, home))
    if which("anew"):
        print(Fore.GREEN + "anew installed successfully")

if which("gau"):
    pass
else:
    commands("go install github.com/lc/gau@latest | cd {}/go/bin | sudo mv {}/go/bin/gau /usr/local/bin".format(home, home))
    if which("gau"):
        print(Fore.GREEN + "gau installed successfully")
        
if which("hakrawler"):
    pass
else:  
    commands("go install github.com/hakluke/hakrawler@latest | cd {}/go/bin | sudo mv {}/go/bin/hakrawler /usr/local/bin".format(home, home))
    if which("gau"):
        print(Fore.GREEN + "gau installed successfully")
