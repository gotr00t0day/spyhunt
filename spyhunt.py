from shutil import which
from shodan import Shodan
from colorama import Fore, Back, Style
from os import path
from builtwith import builtwith
from modules.favicon import *
import os.path
import socket
import subprocess
import sys
import socket
import os
import argparse
import time
import threading
import codecs
import requests
import mmh3
import urllib3
import random

requests.packages.urllib3.disable_warnings()

banner = """


███████╗██████╗ ██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
███████╗██████╔╝ ╚████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   
╚════██║██╔═══╝   ╚██╔╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   
███████║██║        ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚══════╝╚═╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
V 1.2
By c0deninja

"""

print(Fore.CYAN + banner)
print(Fore.WHITE)

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

group.add_argument('-sv', '--save', action='store',
                   help="save output to file",
                   metavar="filename.txt")

parser.add_argument('-s',
                    type=str, help='scan for subdomains',
                    metavar='domain.com')

parser.add_argument('-j',
                    type=str, help='find javascript files',
                    metavar='domain.com')

parser.add_argument('-t', '--tech',
                    type=str, help='find technologies',
                    metavar='domain.com')


parser.add_argument('-d', '--dns',
                    type=str, help='scan for dns records',
                    metavar='domain.com')

parser.add_argument('-p', '--probe',
                    type=str, help='probe domains.',
                    metavar='domains.txt')

parser.add_argument('-a', '--aquatone',
                    type=str, help='take screenshots of domains.',
                    metavar='domains.txt')

parser.add_argument('-r', '--redirects',
                    type=str, help='links getting redirected',
                    metavar='domains.txt')

parser.add_argument('-b', '--brokenlinks',
                    type=str, help='search for broken links',
                    metavar='domains.txt')

parser.add_argument('-w', '--waybackurls',
                    type=str, help='scan for waybackurls',
                    metavar='https://domain.com')

parser.add_argument('-wc', '--webcrawler',
                    type=str, help='scan for urls and js files',
                    metavar='https://domain.com')

parser.add_argument('-fi', '--favicon',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-fm', '--faviconmulti',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-na', '--networkanalyzer',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-ri', '--reverseip',
                    type=str, help='reverse ip lookup',
                    metavar='IP')

parser.add_argument('-rim', '--reverseipmulti',
                    type=str, help='reverse ip lookup for multiple ips',
                    metavar='IP')

parser.add_argument('-sc', '--statuscode',
                    type=str, help='statuscode',
                    metavar='domain.com')

parser.add_argument('-co', '--corsmisconfig',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

args = parser.parse_args()



if args.s:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        cmd = f"subfinder -d {args.s}"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        out = out.decode()  
        with open(f"{args.save}", "w") as subfinder:
            subfinder.writelines(out)
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
            sys.exit(1)
        cmd = f"./scripts/spotter.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        spotterout, err = p.communicate()
        spotterout = spotterout.decode()
        with open(f"{args.save}", "a") as spotter:
            spotter.writelines(spotterout)
        cmd = f"./scripts/certsh.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        certshout, err = p.communicate()
        certshout = certshout.decode()
    else:
        commands(f"subfinder -d {args.s}")
        commands(f"./scripts/spotter.sh {args.s} | uniq | sort")
        commands(f"./scripts/certsh.sh {args.s} | uniq | sort") 

if args.reverseip:
    domain = socket.gethostbyaddr(args.reverseip)
    print(f"{Fore.CYAN}Domain: {Fore.GREEN} {domain[0]}")

if args.reverseipmulti:
    try:
        with open(f"{args.reverseipmulti}") as f:
            ipadd = [x.strip() for x in f.readlines()]
            for ips in ipadd:
                print(f"{socket.gethostbyaddr(ips)}\n")
    except socket.herror:
        pass
    except FileNotFoundError:
        print(f"{Fore.RED} File not found!")


if args.webcrawler:
    if args.save:
        print(Fore.CYAN + f"Saving output to {args.save}")
        commands(f"echo {args.webcrawler} | hakrawler >> {args.save}")
    else:
        commands(f"echo {args.webcrawler} | hakrawler")


if args.statuscode:
    commands(f"echo '{args.statuscode}' | httpx -silent -status-code")

if args.favicon:
        response = requests.get(f'{args.favicon}/favicon.ico', verify=False)
        favicon = codecs.encode(response.content,"base64")
        hash = mmh3.hash(favicon)
        print(hash)

if args.faviconmulti:
    print(f"{Fore.MAGENTA}\t\t\t FavIcon Hashes\n")
    with open(f"{args.faviconmulti}") as f:
        domains = [x.strip() for x in f.readlines()]
        try:
            for domainlist in domains:
                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=60)
                if response.status_code == 200:
                    favicon = codecs.encode(response.content,"base64")
                    hash = mmh3.hash(favicon)
                    hashes = {}
                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=5)
                if response.status_code == 200:
                    favicon = codecs.encode(response.content,"base64")
                    hash = mmh3.hash(favicon)
                    if "https" in domainlist:
                        domainlist = domainlist.replace("https://", "")
                    if "http" in domainlist:
                        domainlist = domainlist.replace("http://", "")
                    ip = socket.gethostbyname(domainlist)
                    if hash == "0":
                        pass
                    for value, item in fingerprint.items():
                        if hash == value:
                            hashes[hash].append(item)
                            print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}[{hash}] {Fore.GREEN}[{ip}]{Fore.YELLOW} [{item}]")  
                    print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}[{hash}] {Fore.GREEN}[{ip}]{Fore.YELLOW}")
                    for v,i in hashes.items():
                        print(f"{Fore.MAGENTA}Servers Found")
                        print()
                        print(f"{v}:{i}")
                    else:
                        print(f"{Fore.WHITE}{domainlist} {Fore.MAGENTA}: {Fore.CYAN}{hash} {Fore.GREEN}{ip}")
                else:
                    pass
        except TimeoutError:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except urllib3.exceptions.ProtocolError:
            pass
        except requests.exceptions.ReadTimeout:
            pass

if args.corsmisconfig:
    print(f"\t\t\t{Fore.CYAN}CORS {Fore.MAGENTA}Misconfiguration {Fore.GREEN}Module\n\n")
    with open(f"{args.corsmisconfig}") as f:
        domains = [x.strip() for x in f.readlines()]
        try:
            for domainlist in domains:
                for pos, web in enumerate(domainlist):
                    if pos == 0:
                        original_payload = []
                        payload = []
                        remove_com = domainlist.replace(".com", "")
                        payload.append(f"{remove_com}evil.com")
                        payload.append("evil.com")
                        header = {'Origin': f"{payload}"}
                    else:
                        pass
                for i in payload:
                    if not i in original_payload:
                        original_payload.append(i)
                original_payload2 = ", ".join(original_payload)
                session = requests.Session()
                session.max_redirects = 10
                resp = session.get(f"{domainlist}", verify=False, headers=header)
                for value, key in resp.headers.items():
                    if value == "Access-Control-Allow-Origin":
                        AllowOrigin = key
                        if AllowOrigin == f"{payload}":
                            print(f"{Fore.YELLOW}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{original_payload2}")
                print(f"{Fore.YELLOW}NOT VULNERABLE: {Fore.GREEN} {domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{original_payload2}")
        except requests.exceptions.TooManyRedirects:
            pass
        except requests.exceptions.ConnectionError:
            pass



if args.networkanalyzer:
    print(f"{Fore.MAGENTA}\t\t Analyzing Network Vulnerabilities \n")
    print(f"{Fore.CYAN}IP Range: {Fore.GREEN}{args.networkanalyzer}\n")
    print(f"{Fore.WHITE}")
    commands(f"shodan stats --facets port net:{args.networkanalyzer}")
    commands(f"shodan stats --facets vuln net:{args.networkanalyzer}")


if args.waybackurls:
    if args.save:
        print(Fore.CYAN + f"Saving output to {args.save}")
        commands(f"waybackurls {args.waybackurls} | anew >> {args.save}")
        print(Fore.GREEN + "DONE!")
    else:
        commands(f"waybackurls {args.waybackurls}")

if args.j:
    if args.save:
        print(Fore.CYAN + "Saving output to {}".format(args.save))
        commands(f"echo {args.j} | waybackurls | grep '\\.js$' | uniq | sort >> {args.save}")
        commands(f"echo {args.j} | gau | grep -Eo 'https?://\\S+?\\.js' | anew >> {args.save}")
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f"echo {args.j} | waybackurls | grep '\\.js$' | anew")
        commands(f"echo {args.j} | gau | grep -Eo 'https?://\\S+?\\.js' | anew")

if args.dns:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        commands(f"cat {args.dns} | dnsx -silent -a -resp >> {args.save}")
        commands(f"cat {args.dns} | dnsx -silent -ns -resp >> {args.save}")
        commands(f"cat {args.dns} | dnsx -silent -cname -resp >> {args.save}")
    else:
        print(Fore.CYAN + "Printing A records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -a -resp\n")
        print(Fore.CYAN + "Printing NS Records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -ns -resp\n")
        print(Fore.CYAN + "Printing CNAME records...\n")
        time.sleep(2)
        commands(f"cat {args.dns} | dnsx -silent -cname -resp\n")            

if args.probe:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        commands(f'cat {args.probe} | httprobe | anew >> {args.save}')
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f'sudo cat {args.probe} | httprobe | anew')    


if args.redirects:
    if args.save:
        print(Fore.CYAN + "Saving output to {}}..".format(args.save))
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302 | anew >> redirects.txt")
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302")   


if args.aquatone:
    if path.exists("aquatone"):
        pass
    if not path.exists("aquatone"):
        commands("mkdir aquatone")
    commands(f"cat {args.aquatone} | aquatone")


if args.brokenlinks:
    if args.save:
        print(Fore.CYAN + "Saving output to {}".format(args.save))
        commands(f"blc -r --filter-level 2 {args.brokenlinks}")
        if path.exists(f"{args.save}"):
            print(Fore.CYAN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.CYAN + "ERROR!")
    else:
        commands(f"blc -r --filter-level 2 {args.brokenlinks}")

if args.tech:
    try:
        print("\n")
        print (Fore.CYAN + "Scanning..." + "\n")
        info = builtwith(f"{args.tech}")
        for framework, tech in info.items():
            print (Fore.GREEN + framework, ":", tech)
    except UnicodeDecodeError:
        pass
