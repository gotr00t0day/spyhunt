#!/usr/bin/env python3
from shutil import which
from colorama import Fore, Style
from os import path
import os
import subprocess



def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except subprocess.CalledProcessError:
        pass



# run commands with sudo
def run_with_sudo(command):
    subprocess.run(["sudo", "bash", "-c", command], check=True)

# Dictionary of package managers 
package_managers = {
    "apt": {"install_cmd": "apt install", "packages": {"npm": "npm", "golang": "golang", "nodejs": "nodejs"}},
    "yum": {"install_cmd": "yum install", "packages": {"npm": "npm", "golang": "golang", "nodejs": "nodejs"}},
    "dnf": {"install_cmd": "dnf install", "packages": {"npm": "npm", "golang": "golang", "nodejs": "nodejs"}},
    "zypper": {"install_cmd": "zypper install", "packages": {"npm": "npm", "golang": "golang", "nodejs": "nodejs"}},
    "pacman": {"install_cmd": "pacman -S", "packages": {"npm": "npm", "golang": "go", "nodejs": "nodejs"}}
}

# Install packages
for manager, data in package_managers.items():
    if which(manager):
        print(f"Using {manager} package manager:")
        found = False
        for package, package_name in data["packages"].items():
            print(f"Installing {package}...")
            try:
                run_with_sudo(f"{data['install_cmd']} {package_name}")
                found = True
            except subprocess.CalledProcessError:
                print(Fore.YELLOW + f"Error occurred while installing {package} using {manager}")
        if found:
            print(Fore.GREEN + "Packages installed successfully")
        else:
            print(Fore.RED + "Failed to install any packages")
        break
else:
    print(Fore.RED + "No compatible package manager found")

# colorama 
commands("sudo pip3 install colorama")

# brokenlinkchecker
if which("blc"):
    pass
else:
    run_with_sudo("npm install broken-link-checker -g")
    if which("blc"):
        print(Fore.GREEN + "broken-link-checker installed successfully")

home = os.environ['HOME']

#dnsx
if which("dnsx"):
    pass
else:
    commands("go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest | cd {}/go/bin | sudo mv {}/go/bin/dnsx /usr/local/bin".format(home, home))
    if which("dnsx"):
        print(Fore.GREEN + "dnsx installed successfully")

#aquatone
if which("aquatone"):
    pass
else:
    filepath = os.path.abspath(os.getcwd())
    commands("wget -O aquatone.zip https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip | sudo mv {}/aquatone /usr/local/bin".format(filepath))
    if which("aquatone"):
        print(Fore.GREEN + "aquatone installed successfully")

#subfinder
if which("subfinder"):
    pass
else:
    commands("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest | cd {}/go/bin | sudo mv {}/go/bin/subfinder /usr/local/bin".format(home, home))
    if which("subfinder"):
        print(Fore.GREEN + "subfinder installed successfully")

#jq
if which("jq"):
    pass
else:
    commands("sudo apt install jq")
    if which("jq"):
        print(Fore.GREEN + "jq installed successfully")

#waybackurls
if which("waybackurls"):
    pass
else:
    commands("go install github.com/tomnomnom/waybackurls@latest | cd {}/go/bin | sudo mv {}/go/bin/waybackurls /usr/local/bin".format(home, home))
    if which("waybackurls"):
        print(Fore.GREEN + "installed successfully")

#httprobe
if which("httprobe"):
    pass
else: 
    commands("go install github.com/tomnomnom/httprobe@latest | cd {}/go/bin | sudo mv {}/go/bin/httprobe /usr/local/bin".format(home, home))

#httpx
if which("httpx"):
    pass
else: 
    commands("go install github.com/projectdiscovery/httpx/cmd/httpx@latest | cd {}/go/bin | sudo mv {}/go/bin/httpx /usr/local/bin".format(home, home))
    if which("httpx"):
        print(Fore.GREEN + "httpx installed successfully")

#anew
if which("anew"):
    pass
else:
    commands("go install github.com/tomnomnom/anew@latest | cd {}/go/bin | sudo mv {}/go/bin/anew /usr/local/bin".format(home, home))
    if which("anew"):
        print(Fore.GREEN + "anew installed successfully")

#gau
if which("gau"):
    pass
else:
    commands("go install github.com/lc/gau@latest | cd {}/go/bin | sudo mv {}/go/bin/gau /usr/local/bin".format(home, home))
    if which("gau"):
        print(Fore.GREEN + "gau installed successfully")

#gauplus
if which("gauplus"):
    pass
else:
    commands("go install github.com/bp0lr/gauplus@latest | cd {}/go/bin | sudo mv {}/go/bin/gauplus /usr/local/bin".format(home, home))
    if which("gauplus"):
        print(Fore.GREEN + "gauplus installed successfully")

#hakrawler
if which("hakrawler"):
    pass
else:  
    commands("go install github.com/hakluke/hakrawler@latest | cd {}/go/bin | sudo mv {}/go/bin/hakrawler /usr/local/bin".format(home, home))
    if which("gau"):
        print(Fore.GREEN + "gau installed successfully")

#shodan
if which("shodan"):
    pass
else:
    commands("easy_install shodan")
    if which("shodan"):
        print(Fore.GREEN + "shodan installed successfully")

#paramspider
if which("paramspider"):
    pass
else:
    commands("git clone https://github.com/devanshbatham/paramspider | cd paramspider | pip3 install .")
    if which("paramspider"):
        print(Fore.GREEN + " installed successfully")

#assetfinder
if which("assetfinder"):
    pass
else:
    commands("go install github.com/tomnomnom/assetfinder@latest | cd {}/go/bin | sudo mv {}/go/bin/assetfinder /usr/local/bin".format(home, home))
    if which("assetfinder"):
        print(Fore.GREEN + "assetfinder installed successfully")


