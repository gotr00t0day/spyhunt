from colorama import Fore, init, Style
from os import path
from builtwith import builtwith
from modules.favicon import *
from bs4 import BeautifulSoup
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, quote_plus
from modules import useragent_list
from modules import sub_output
from googlesearch import search
from alive_progress import alive_bar
from queue import Queue
from shutil import which
from collections import defaultdict
from datetime import datetime
import threading
import os.path
import concurrent.futures
import multiprocessing
import os.path
import socket
import subprocess
import sys
import socket
import os
import argparse
import time
import codecs
import requests
import mmh3
import urllib3
import warnings
import re
import execjs
import nmap3
import json
import shodan
import ipaddress
import random
import string
import html



warnings.filterwarnings(action='ignore',module='bs4')

requests.packages.urllib3.disable_warnings()

banner = """


███████╗██████╗ ██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
███████╗██████╔╝ ╚████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   
╚════██║██╔═══╝   ╚██╔╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   
███████║██║        ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚══════╝╚═╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
V 2.0
By c0deninja

"""

print(Fore.CYAN + banner)
print(Fore.WHITE)

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

def scan(command: str) -> str:
    cmd = command
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, err = p.communicate()
    out = out.decode() 
    return out

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

update_group = parser.add_argument_group('Update')
nuclei_group = parser.add_argument_group('Nuclei Scans')
vuln_group = parser.add_argument_group('Vulnerability')
crawlers_group = parser.add_argument_group('Crawlers')
passiverecon_group = parser.add_argument_group('Passive Recon')
fuzzing_group = parser.add_argument_group('Fuzzing')
portscanning_group = parser.add_argument_group('Port Scanning')

group.add_argument('-sv', '--save', action='store',
                   help="save output to file",
                   metavar="filename.txt")

group.add_argument('-wl', '--wordlist', action='store',
                   help="wordlist to use",
                   metavar="filename.txt")

parser.add_argument('-th', '--threads',
                    type=str, help='default 25',
                    metavar='25')

passiverecon_group.add_argument('-s',
                    type=str, help='scan for subdomains',
                    metavar='domain.com')

passiverecon_group.add_argument('-t', '--tech',
                    type=str, help='find technologies',
                    metavar='domain.com')

passiverecon_group.add_argument('-d', '--dns',
                    type=str, help='scan a list of domains for dns records',
                    metavar='domains.txt')

parser.add_argument('-p', '--probe',
                    type=str, help='probe domains.',
                    metavar='domains.txt')

parser.add_argument('-r', '--redirects',
                    type=str, help='links getting redirected',
                    metavar='domains.txt')

vuln_group.add_argument('-b', '--brokenlinks',
                    type=str, help='search for broken links',
                    metavar='domains.txt')

crawlers_group.add_argument('-pspider', '--paramspider',
                    type=str, help='extract parameters from a domain',
                    metavar='domain.com')

crawlers_group.add_argument('-w', '--waybackurls',
                    type=str, help='scan for waybackurls',
                    metavar='https://domain.com')

crawlers_group.add_argument('-j',
                    type=str, help='find javascript files',
                    metavar='domain.com')

crawlers_group.add_argument('-wc', '--webcrawler',
                    type=str, help='scan for urls and js files',
                    metavar='https://domain.com')

parser.add_argument('-fi', '--favicon',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

parser.add_argument('-fm', '--faviconmulti',
                    type=str, help='get favicon hashes',
                    metavar='https://domain.com')

passiverecon_group.add_argument('-na', '--networkanalyzer',
                    type=str, help='net analyzer',
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

vuln_group.add_argument('-ph', '--pathhunt',
                    type=str, help='check for directory traversal',
                    metavar='domain.txt')

vuln_group.add_argument('-co', '--corsmisconfig',
                    type=str, help='cors misconfiguration',
                    metavar='domains.txt')

vuln_group.add_argument('-hh', '--hostheaderinjection',
                    type=str, help='host header injection',
                    metavar='domain.com')

parser.add_argument('-sh', '--securityheaders',
                    type=str, help='scan for security headers',
                    metavar='domain.com')

parser.add_argument('-ed', '--enumeratedomain',
                    type=str, help='enumerate domains',
                    metavar='domain.com')

vuln_group.add_argument('-smu', '--smuggler',
                    type=str, help='enumerate domains',
                    metavar='domain.com')

passiverecon_group.add_argument('-ips', '--ipaddresses',
                    type=str, help='get the ips from a list of domains',
                    metavar='domain list')

passiverecon_group.add_argument('-dinfo', '--domaininfo',
                    type=str, help='get domain information like codes,server,content length',
                    metavar='domain list')

parser.add_argument('-isubs', '--importantsubdomains',
                    type=str, help='extract interesting subdomains from a list like dev, admin, test and etc..',
                    metavar='domain list')

fuzzing_group.add_argument('-nft', '--not_found',
                    type=str, help='check for 404 status code',
                    metavar='domains.txt')

portscanning_group.add_argument('-n', '--nmap',
                    type=str, help='Scan a target with nmap',
                    metavar='domain.com or IP')

fuzzing_group.add_argument('-api', '--api_fuzzer',
                    type=str, help='Look for API endpoints',
                    metavar='domain.com')

passiverecon_group.add_argument('-sho', '--shodan',
                    type=str, help='Recon with shodan',
                    metavar='domain.com')

vuln_group.add_argument('-fp', '--forbiddenpass',
                    type=str, help='Bypass 403 forbidden',
                    metavar='domain.com')

fuzzing_group.add_argument('-db', '--directorybrute',
                    type=str, help='Brute force filenames and directories',
                    metavar='domain.com')

portscanning_group.add_argument('-cidr', '--cidr_notation',
                    type=str, help='Scan an ip range to find assets and services',
                    metavar='IP/24')

portscanning_group.add_argument('-ps', '--ports',
                    type=str, help='Port numbers to scan',
                    metavar='80,443,8443')

portscanning_group.add_argument('-pai', '--print_all_ips',
                    type=str, help='Print all ips',
                    metavar='IP/24')

vuln_group.add_argument('-xss', '--xss_scan',
                 type=str, help='scan for XSS vulnerabilities',
                 metavar='https://example.com/page?param=value')

vuln_group.add_argument('-sqli', '--sqli_scan',
                 type=str, help='scan for SQLi vulnerabilities',
                 metavar='https://example.com/page?param=value')

passiverecon_group.add_argument('-shodan', '--shodan_api',
                    type=str, help='shodan api key',
                    metavar='KEY')

parser.add_argument('-webserver', '--webserver_scan',
                    type=str, help='webserver scan',
                    metavar='domain.com')

nuclei_group.add_argument('-nl', '--nuclei_lfi', action='store_true', help="Find Local File Inclusion with nuclei")

passiverecon_group.add_argument('-gs', '--google', action='store_true', help='Google Search')

fuzzing_group.add_argument("-e", "--extensions", help="Comma-separated list of file extensions to scan", default="")

fuzzing_group.add_argument("-x", "--exclude", help="Comma-separated list of status codes to exclude", default="")

update_group.add_argument('-u', '--update', action='store_true', help='Update the script')


args = parser.parse_args()

user_agent = useragent_list.get_useragent()
header = {"User-Agent": user_agent}

if args.update:
    print(Fore.CYAN + "Updating the script...")
    commands("git pull")
    print(Fore.GREEN + "Script updated!")
    sys.exit(0)

if args.s:
    if args.save:
        print(Fore.CYAN + "Saving output to {}...".format(args.save))
        cmd = f"subfinder -d {args.s} -silent"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        out = out.decode() 
        with open(f"{args.save}", "a") as subfinder:
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
        with open(f"{args.save}", "a") as certsh:
            certsh.writelines(certshout)
    else:
        commands(f"subfinder -d {args.s}")
        commands(f"assetfinder -subs-only {args.s} | uniq | sort")
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

if args.enumeratedomain:
    try:
        server = []
        r = requests.get(f"{args.enumeratedomain}", verify=False, headers=header) 
        domain = args.enumeratedomain
        if "https://" in domain:
            domain = domain.replace("https://", "")
        if "http://" in domain:
            domain = domain.replace("http://", "")
        ip = socket.gethostbyname(domain)
        for value, key in r.headers.items():
            if value == "Server" or value == "server":
                server.append(key)
        if server:
            print(f"{Fore.WHITE}{args.enumeratedomain}{Fore.MAGENTA}: {Fore.CYAN}[{ip}] {Fore.WHITE}Server:{Fore.GREEN} {server}")
        else:
            print(f"{Fore.WHITE}{args.enumeratedomain}{Fore.MAGENTA}: {Fore.CYAN}[{ip}]")
    except requests.exceptions.MissingSchema as e:
        print(e)
    

if args.faviconmulti:
    print(f"{Fore.MAGENTA}\t\t\t FavIcon Hashes\n")
    with open(f"{args.faviconmulti}") as f:
        domains = [x.strip() for x in f.readlines()]
        try:
            for domainlist in domains:
                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=60, headers=header)
                if response.status_code == 200:
                    favicon = codecs.encode(response.content,"base64")
                    hash = mmh3.hash(favicon)
                    hashes = {}
                response = requests.get(f'{domainlist}/favicon.ico', verify=False, timeout=5, headers=header)
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
        except KeyError:
            pass

if args.corsmisconfig:
    print(f"\\t\\t\\t{Fore.CYAN}CORS {Fore.MAGENTA}Misconfiguration {Fore.GREEN}Module\\n\\n")

    with open(args.corsmisconfig, "r") as f:
        domains = [x.strip() for x in f.readlines()]

    def check_cors(domainlist):
        try:
            payload = []
            payload.append(domainlist)
            payload.append("evil.com")
            header = {'Origin': ', '.join(payload)}  # Constructing the header correctly here

            session = requests.Session()
            session.max_redirects = 10
            resp = session.get(domainlist, verify=False, headers=header, timeout=(5, 10))

            for value, key in resp.headers.items():
                if value == "Access-Control-Allow-Origin" and key == header['Origin']:
                    print(f"{Fore.YELLOW}VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{', '.join(payload)}")
                    return
            print(f"{Fore.CYAN}NOT VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{', '.join(payload)}")

        except requests.exceptions.RequestException as e:
            if isinstance(e, requests.exceptions.ConnectionError):
                print(f"{Fore.RED}Connection error occurred while processing {domainlist}")
            else:
                print(f"{Fore.LIGHTBLACK_EX}Error occurred while processing {domainlist}: {str(e)}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_cors, domain) for domain in domains]

    for future in futures:
        try:
            future.result()
        except Exception as e:
            print(f"An error occurred: {e}")


if args.hostheaderinjection:
    print(f"{Fore.MAGENTA}\\t\\t Host Header Injection \\n")
    redirect = {"301", "302", "303", "307", "308"}  # Use a set for faster lookup
    timeout = 5  # Timeout value in seconds
    with open(f"{args.hostheaderinjection}", "r") as f:
        domains = [x.strip() for x in f.readlines()]
    payload = b"google.com"
    print(f"{Fore.WHITE} Checking For {Fore.CYAN}X-Forwarded-Host {Fore.WHITE}and {Fore.CYAN}Host {Fore.WHITE}injections.....\\n")

    def check_host_header_injection(domainlist):
        vuln_domain = []
        session = requests.Session()
        header = {"X-Forwarded-Host": "google.com"}
        header2 = {"Host": "google.com"}
        try:
            start_time = time.time()
            resp = session.get(f"{domainlist}", verify=False, headers=header, timeout=timeout)
            resp2 = session.get(f"{domainlist}", verify=False, headers=header2, timeout=timeout)
            elapsed_time = time.time() - start_time
            resp_content = resp.content
            resp_status = resp.status_code
            resp2_content = resp2.content

            for value, key in resp.headers.items():
                if value == "Location" and key == payload and resp_status in redirect:
                    vuln_domain.append(domainlist)
                if payload in resp_content or key == payload:
                    vuln_domain.append(domainlist)

            for value2, key2 in resp2.headers.items():
                if payload in resp2_content or key == payload:
                    vuln_domain.append(domainlist)

            if vuln_domain:
                duplicates_none = list(set(vuln_domain))  # Remove duplicates
                duplicates_none = ", ".join(duplicates_none)
                print(f"{Fore.RED} POSSIBLE {Fore.YELLOW} Host Header Injection Detected {Fore.MAGENTA}- {Fore.GREEN} {duplicates_none}")

            print(f"{Fore.CYAN} No Detection {Fore.MAGENTA}- {Fore.GREEN} {(domainlist)}{Fore.BLUE} ({resp_status})")

            if elapsed_time > timeout:
                print(f"{Fore.LIGHTBLACK_EX} Timeout Exceeded for {domainlist}. Skipping...")

        except requests.exceptions.RequestException as e:
            print(f"{Fore.LIGHTBLACK_EX} Error occurred while accessing {domainlist}: {e}")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_host_header_injection, domain) for domain in domains]

    for future in futures:
        try:
            future.result()
        except Exception as e:
            print(f"An error occurred: {e}")


if args.securityheaders:
    print(f"{Fore.MAGENTA}\t\t Security Headers\n")
    security_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection"]
    session = requests.Session()
    no_sec = []
    found_hd = []
    no_dup = []
    no_dup_found = []
    lower = [x.lower() for x in security_headers]
    capital = [x.upper() for x in security_headers]
    resp = session.get(f"{args.securityheaders}", verify=False)
    print(f"{Fore.CYAN}Domain: {Fore.GREEN}{args.securityheaders}\n")
    for item, key in resp.headers.items():
        for sec_headers in security_headers:
            if sec_headers  == item or lower == item or capital == item:
                found_hd.append(sec_headers)
                [no_dup_found.append(x) for x in found_hd if x not in no_dup_found]
        print(f"{Fore.CYAN}{item}: {Fore.YELLOW}{key}")
    no_dup = ", ".join(no_dup)
    print(lower)
    print("\n")
    print(f"{Fore.GREEN} Found Security Headers: {Fore.YELLOW} {len(no_dup_found)}\n")
    no_dup_found = ", ".join(no_dup_found)
    print(f"{Fore.YELLOW} {no_dup_found}\n")
    no_headers = [item for item in security_headers if item not in no_dup_found]
    print(f"{Fore.RED} Found Missing headers: {Fore.YELLOW} {len(no_headers)}\n")
    no_headers = ", ".join(no_headers)
    print(f"{Fore.YELLOW} {no_headers}")


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
        commands(f'cat {args.probe} | httprobe -c 100 | anew >> {args.save}')
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f'sudo cat {args.probe} | httprobe | anew')    


if args.redirects:
    if args.save:
        print(Fore.CYAN + "Saving output to {}}..".format(args.save))
        if which("httpx"):
            print("Please uninstall httpx and install httpx-toolkit from https://github.com/projectdiscovery/httpx-toolkit")
            sys.exit()
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302 | anew >> redirects.txt")
        if path.exists(f"{args.save}"):
            print(Fore.GREEN + "DONE!")
        if not path.exists(f"{args.save}"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302")   


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

if args.smuggler:
    smug_path = os.path.abspath(os.getcwd())
    commands(f"python3 {smug_path}/tools/smuggler/smuggler.py -u {args.smuggler} -q")

if args.ipaddresses:
    ip_list = []

    with open(f"{args.ipaddresses}", "r") as f:
        domains = [x.strip() for x in f.readlines()]

    def scan(domain: str):
        try:
            ips = socket.gethostbyname(domain)
            ip_list.append(ips)
            print(f"{Fore.GREEN} {domain} {Fore.WHITE}- {Fore.CYAN}{ips}")
        except socket.gaierror:
            pass
        except UnicodeError:
            pass

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan, domain) for domain in domains]
        
        for future in futures:
            future.result()
    
    with open("ips.txt", "w") as file:
        ip_list = list(dict.fromkeys(ip_list))
        for iplist in ip_list:
            file.write(f"{iplist}\n")


if args.domaininfo:
    with open(f"{args.domaininfo}", "r") as f:
        domains = [x.strip() for x in f.readlines()]
    ip_list = []
    server = []
    new_server = set()
    for domain_list in domains:
        try:
            sessions = requests.Session()
            r = sessions.get(domain_list, verify=False, headers=header)
            if "https://" in domain_list:
                domain_list = domain_list.replace("https://", "")
            if "http://" in domain_list:
                domain_list = domain_list.replace("https://", "")
            for v, k in r.headers.items():
                if "Server" in v:
                    server.append(k)
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.find("title")
            ips = socket.gethostbyname(domain_list)
            ip_check = os.system(f"ping -c1 -W1 {ips} > /dev/null")
            if ip_check == 0:
                ip_list.append(ips)
            else:
                pass
            with open(f"ips.txt", "w") as f:
                for ipaddresses in ip_list:
                    f.writelines(f"{ipaddresses}\n")
            new_server.update(server)
            if r.status_code == 200:
                print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[{title.get_text()}]{Fore.GREEN}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
            if r.status_code == 403:
                print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[{title.get_text()}]{Fore.RED}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
            else:
                print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[{title.get_text()}]{Fore.CYAN}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
        except socket.gaierror:
            pass
        except requests.exceptions.MissingSchema:
            print(f"{Fore.RED} Please use http:// or https://")
        except requests.exceptions.SSLError:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except AttributeError:
            print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.YELLOW}[{ips}]{Fore.BLUE}[No title]{Fore.CYAN}[{r.status_code}]{Fore.LIGHTMAGENTA_EX}[{', '.join(map(str,new_server))}]")
        except UnicodeDecodeError:
            pass
        except requests.exceptions.InvalidURL:
            pass
        except KeyboardInterrupt:
            sys.exit()
        except:
            pass

if args.importantsubdomains:
    with open(f"{args.importantsubdomains}", "r") as f:
        important_subs = []
        subdomains = [x.strip() for x in f.readlines()]
        for subdomain_list in subdomains:
            if "admin" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "dev" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "test" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "api" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "staging" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "prod" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "beta" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "manage" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "jira" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
            if "github" in subdomain_list:
                important_subs.append(f"{subdomain_list}")
        for pos, value in enumerate(important_subs):
            print(f"{Fore.CYAN}{pos}: {Fore.GREEN}{value}")
        with open("juice_subs.txt", "w") as f:
            for goodsubs in important_subs:
                f.writelines(f"{goodsubs}\n")


if args.not_found:
    session = requests.Session()
    session.headers.update(header)

    def check_status(domain):
        try:
            r = session.get(domain, verify=False, headers=header, timeout=10)
            if r.status_code == 404:
                return domain
        except requests.exceptions.RequestException:
            pass

    def get_results(links, output_file):
        pool = ThreadPool(processes=multiprocessing.cpu_count())
        results = pool.imap_unordered(check_status, links)
        with open(output_file, "w") as f:
            for result in results:
                if result:
                    f.write(f"{result}\n")
                    print(result)
        pool.close()
        pool.join()

    with open(args.not_found, "r") as f:
        links = (f"{x.strip()}" for x in f.readlines())
        output_file = "results.txt"
        get_results(links, output_file)

if args.paramspider:
    commands(f"paramspider -d {args.paramspider}")

if args.pathhunt:
    def commands(cmd):
        try:
            subprocess.check_call(cmd, shell=True)
        except:
            pass
    pathhunt_path = os.path.abspath(os.getcwd())
    commands(f"python3 {pathhunt_path}/tools/pathhunt.py -t {args.pathhunt}")   
    
if args.nmap:
    print(f"{Fore.WHITE}Scanning {Fore.CYAN}{args.nmap}\n")
    nmap = nmap3.Nmap()
    results = nmap.nmap_version_detection(f"{args.nmap}")

    with open("nmap_results.json", "w") as f:
        json.dump(results, f, indent=4)

    with open('nmap_results.json', 'r') as file:
        data = json.load(file)

    for host, host_data in data.items():
        if host != "runtime" and host != "stats" and host != "task_results":
            ports = host_data.get("ports", [])
            for port in ports:
                portid = port.get("portid")
                service = port.get("service", {})
                product = service.get("product")
                print(f"{Fore.WHITE}Port: {Fore.CYAN}{portid}, {Fore.WHITE}Product: {Fore.CYAN}{product}")

if args.api_fuzzer:
    s = requests.Session()
    with open("payloads/api-endpoints.txt", "r") as file:
        api_endpoints = [x.strip() for x in file.readlines()]
    
    def check_endpoint(endpoint):
        url = f"{args.api_fuzzer}/{endpoint}"
        try:
            r = s.get(url, verify=False, headers=header, timeout=5)
            if r.status_code == 200:
                return f"{Fore.GREEN}{url}"
            else:
                return f"{Fore.RED}{url} [{r.status_code}]"
        except requests.RequestException:
            return f"{Fore.YELLOW}{url} [Error]"
    
    print(f"Scanning {len(api_endpoints)} endpoints for {args.api_fuzzer}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_endpoint, endpoint) for endpoint in api_endpoints]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.startswith(Fore.GREEN):
                print(result)

if args.shodan:
    key = input("Shodan Key: ")
    print("\n")
    api = shodan.Shodan(str(key))
    try:
        results = api.search(args.shodan)
        results_ = []
        results_5 = []
        for result in results['matches']:
            results_.append(result['ip_str'])
        results_5.append(results_[0:50])
        if results_5:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Shodan IPs: {Fore.GREEN}{', '.join(map(str,results_5))}")
        if not results_5:
            pass
    except shodan.APIError:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.YELLOW} Shodan Key: {Fore.GREEN} Invalid Key")
    except socket.herror:
        pass


if args.forbiddenpass:
    def word_list(wordlist: str) -> str:
        try:
            with open(wordlist, "r") as f:
                data = [x.strip() for x in f.readlines()] 
            return data
        except FileNotFoundError as e:
            print(f"File not found: {e}")

    wordlist = word_list("payloads/bypasses.txt")

    def header_bypass():
        headers = [
            {'User-Agent': user_agent},
            {'User-Agent': str(user_agent), 'X-Custom-IP-Authorization': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-For': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-For': '127.0.0.1:80'},
            {'User-Agent': str(user_agent), 'X-Originally-Forwarded-For': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Originating-': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Originating-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'True-Client-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-WAP-Profile': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Arbitrary': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-HTTP-DestinationURL': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Proto': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'Destination': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Remote-IP': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Client-IP': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Host': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Host': 'http://127.0.0.1'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '4443'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '80'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '8080'},
            {'User-Agent': str(user_agent), 'X-Forwarded-Port': '8443'},
            {'User-Agent': str(user_agent), 'X-ProxyUser-Ip': '127.0.0.1'},
            {'User-Agent': str(user_agent), 'Client-IP': '127.0.0.1'}

        ]
        return headers
    
    def do_request(url: str, stream=False):
        headers = header_bypass()
        try:
            for header in headers:
                if stream:
                    s = requests.Session()
                    r = s.get(url, stream=True, headers=header)
                else:
                    s = requests.Session()
                    r = s.get(url, headers=header)
                if r.status_code == 200:
                    print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.GREEN + " [{}]".format(r.status_code))
                else:
                    print(Fore.WHITE + url + ' ' + json.dumps(list(header.items())[-1]) + Fore.RED + " [{}]".format(r.status_code))
        except requests.exceptions.ConnectionError as ce_error:
            pass
        except requests.exceptions.Timeout as t_error:
            print("Connection Timeout Error: ", t_error)
            pass
        except requests.exceptions.RequestException as req_err:
            print("Some Ambiguous Exception:", req_err)
            pass

    def main(wordlist):
        for bypass in wordlist:
            links = f"{args.forbiddenpass}{bypass}"
            do_request(links)

    if __name__ == "__main__":
        main(wordlist)

if args.directorybrute:
    if args.wordlist:
        if args.threads:
            def filter_wordlist(wordlist, extensions):
                if not extensions:
                    return wordlist
                ext_list = [ext.strip() for ext in extensions.split(',')]
                return [word for word in wordlist if any(word.endswith(ext) for ext in ext_list)]

            def dorequests(wordlist: str, base_url: str, headers: dict, is_file_only: bool, excluded_codes: set, bar, print_lock):
                s = requests.Session()
                
                def check_and_print(url, type_str):
                    try:
                        r = s.get(url, verify=False, headers=headers, timeout=10)
                        if r.status_code not in excluded_codes:
                            color = Fore.GREEN if r.status_code == 200 else Fore.YELLOW
                            with print_lock:
                                print(f"\n{url} - {color}{type_str} Found (Status: {r.status_code}){Fore.RESET}\n")
                    except requests.RequestException:
                        pass
                    finally:
                        bar()

                if is_file_only:
                    url = f"{base_url}/{wordlist}"
                    check_and_print(url, "File")
                else:
                    dir_url = f"{base_url}/{wordlist}/"
                    check_and_print(dir_url, "Directory")
                    
            def main():
                with open(args.wordlist, "r") as f:
                    wordlist_ = [x.strip() for x in f.readlines()]
                
                is_file_only = bool(args.extensions)
                
                filtered_wordlist = filter_wordlist(wordlist_, args.extensions)
                
                excluded_codes = set(int(code.strip()) for code in args.exclude.split(',') if code.strip())
                
                print(f"Target: {Fore.CYAN}{args.directorybrute}{Fore.RESET}\n"
                    f"Wordlist: {Fore.CYAN}{args.wordlist}{Fore.RESET}\n"
                    f"Extensions: {Fore.CYAN}{args.extensions or 'All'}{Fore.RESET}\n"
                    f"Excluded Status Codes: {Fore.CYAN}{', '.join(map(str, excluded_codes)) or 'None'}{Fore.RESET}\n")

                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}

                print_lock = threading.Lock()

                with alive_bar(len(filtered_wordlist), title="Scanning", bar="classic", spinner="classic") as bar:
                    with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
                        futures = [executor.submit(dorequests, wordlist, args.directorybrute, headers, is_file_only, excluded_codes, bar, print_lock) 
                                for wordlist in filtered_wordlist]
                        
                        for future in as_completed(futures):
                            future.result()

            if __name__ == "__main__":
                main()

if args.nuclei_lfi:
    vulnerability = []
    FileOrTarget = str(input("Do you want to scan a file or a single target?? Ex: F or T:  "))
    if FileOrTarget == "F" or FileOrTarget == "f":
        File = str(input("Filename: "))
        print(f"Scanning File {File} ..... \n")
        results = scan(f"nuclei -l {File} -tags lfi -c 100")
        vulnerability.append(results)
        if vulnerability:
            for vulns in vulnerability:
                print(vulns)
    elif FileOrTarget == "T" or FileOrTarget == "t":
        Target = str(input("Target: "))
        print(f"Scanning Target {Target} ..... \n")
        results = scan(f"nuclei -u {Target} -tags lfi -c 100")
        vulnerability.append(results)
        if vulnerability:
            for vulns in vulnerability:
                print(vulns)
    else:
        print("Enter either T or F")


if args.google:
    def search_google(dorks: str, page) -> str:
        for url in search(dork, num_results=int(page)):
            return url
    try: 
        dork = input("Enter Dork: ")
        numpage = input("Enter number of links to display: ")
        print ("\n")
        search_google(dork, numpage)
        print("\n")
        print ("Found: {} links".format(numpage))
    except Exception as e:
        print(str(e))

    save = input("Save results to a file (y/n)?: ").lower()
    if save == "y":
        dorklist = input("Filename: ")
        with open(dorklist, "w") as f:
            for url in search(dork, num_results=int(numpage)):
                f.writelines(url)
                f.writelines("\n")
        if path.exists(dorklist):
            print ("File saved successfully")
        if not path.exists(dorklist):
            print ("File was not saved")
    elif save == "n":
        pass        
            
if args.cidr_notation:
    if args.ports:
        if args.threads:
            def scan_ip(ip, ports):
                open_ports = []
                for port in ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((str(ip), port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                return ip, open_ports

            def scan_subnet(subnet, ports, max_threads=100):
                network = ipaddress.ip_network(subnet, strict=False)
                
                with ThreadPoolExecutor(max_workers=int(args.threads)) as executor:
                    futures = [executor.submit(scan_ip, ip, ports) for ip in network.hosts()]
                    
                    for future in as_completed(futures):
                        ip, open_ports = future.result()
                        if open_ports:
                            print(f"IP: {Fore.GREEN}{ip}:{Fore.CYAN}{','.join(map(str, open_ports))}{Fore.RESET}")

            def parse_ports(ports):
                if isinstance(ports, list):
                    return [int(p) for p in ports]
                return [int(p.strip()) for p in ports.split(',')]
            
            def main():
                ports = parse_ports(args.ports)
                scan_subnet(args.cidr_notation, ports, args.threads)

            if __name__ == "__main__":
                main()
    
if args.print_all_ips:
    def extract_ip(ip):
        return str(ip)

    def extract_ips(subnet, max_workers=100):
        network = ipaddress.ip_network(subnet, strict=False)
        ips = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(extract_ip, ip) for ip in network.hosts()]
            for future in as_completed(futures):
                ips.append(future.result())
        return ips

    print(f"Extracting IPs from {args.print_all_ips}...")
    ips = extract_ips(args.print_all_ips)
    
    print(f"\nExtracted IPs from {args.print_all_ips}:")
    for ip in ips:
        print(f"{Fore.GREEN}{ip}{Fore.RESET}")
    
    print(f"\nTotal IPs: {len(ips)}")

    save = input("Do you want to save these IPs to a file? (y/n): ").lower()
    if save == 'y':
        filename = input("Enter filename to save IPs: ")
        with open(filename, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        print(f"IPs saved to {filename}")


if args.xss_scan: 
    def generate_random_string(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def encode_payload(payload):
        encodings = [
            lambda x: x,  # No encoding
            lambda x: quote_plus(x),  # URL encoding
            lambda x: html.escape(x),  # HTML entity encoding
            lambda x: ''.join(f'%{ord(c):02X}' for c in x),  # Full URL encoding
            lambda x: ''.join(f'&#x{ord(c):02X};' for c in x),  # Hex entity encoding
            lambda x: ''.join(f'\\u{ord(c):04X}' for c in x),  # Unicode escape
        ]
        return random.choice(encodings)(payload)

    def print_vulnerability(vuln):
        print(f"\n{Fore.RED}XSS vulnerability found:{Fore.RESET}")
        print(f"URL: {Fore.CYAN}{vuln['url']}{Fore.RESET}")
        print(f"Parameter: {Fore.YELLOW}{vuln['parameter']}{Fore.RESET}")
        print(f"Payload: {Fore.MAGENTA}{vuln['payload']}{Fore.RESET}")
        print(f"Test URL: {Fore.BLUE}{vuln['test_url']}{Fore.RESET}")
        print(f"Execution Likelihood: {Fore.RED if vuln['execution_likelihood'] == 'High' else Fore.YELLOW}{vuln['execution_likelihood']}{Fore.RESET}")

    def xss_scan_url(url):
        print(f"{Fore.CYAN}Scanning for XSS vulnerabilities: {url}{Fore.RESET}")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "';alert(String.fromCharCode(88,83,83))//",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "<input type=\"text\" value=\"\" autofocus onfocus=\"alert('XSS')\">",
        ]
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        vulnerabilities = []
        
        for param in params:
            for payload in payloads:
                random_string = generate_random_string()
                test_payload = payload.replace("XSS", random_string)
                encoded_payload = encode_payload(test_payload)
                
                test_params = params.copy()
                test_params[param] = [encoded_payload]
                test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                
                try:
                    response = requests.get(test_url, verify=False, headers=header, timeout=10)
                    response_text = response.text.lower()
                    
                    if random_string.lower() in response_text:
                        vulnerability = {
                            "url": url,
                            "parameter": param,
                            "payload": encoded_payload,
                            "test_url": test_url
                        }
                        if re.search(r'<script>.*?alert\([\'"]{}[\'"]\).*?</script>'.format(random_string), response_text, re.IGNORECASE | re.DOTALL) or \
                        re.search(r'on\w+\s*=.*?alert\([\'"]{}[\'"]\)'.format(random_string), response_text, re.IGNORECASE):
                            vulnerability["execution_likelihood"] = "High"
                        else:
                            vulnerability["execution_likelihood"] = "Low"
                        
                        vulnerabilities.append(vulnerability)
                        print_vulnerability(vulnerability)
                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}Error scanning {test_url}: {str(e)}{Fore.RESET}")
        
        return vulnerabilities

    def xss_scanner(target):
        if os.path.isfile(target):
            with open(target, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
            
            all_vulnerabilities = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_url = {executor.submit(xss_scan_url, url): url for url in urls}
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        vulnerabilities = future.result()
                        all_vulnerabilities.extend(vulnerabilities)
                    except Exception as exc:
                        print(f'{Fore.RED}Error scanning {url}: {exc}{Fore.RESET}')
            
            return all_vulnerabilities
        else:
            return xss_scan_url(target)


    if __name__ == "__main__":
        vulnerabilities = xss_scanner(args.xss_scan)
        if not vulnerabilities:
            print(f"\n{Fore.GREEN}No XSS vulnerabilities found.{Fore.RESET}")
        else:
            print(f"\n{Fore.RED}Total XSS vulnerabilities found: {len(vulnerabilities)}{Fore.RESET}")


if args.sqli_scan:
    init(autoreset=True)

    def generate_random_string(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def encode_payload(payload):
        encodings = [
            lambda x: x,  # No encoding
            lambda x: quote_plus(x),  # URL encoding
            lambda x: ''.join(f'%{ord(c):02X}' for c in x),  # Full URL encoding
        ]
        return random.choice(encodings)(payload)

    def print_vulnerability(vuln):
        print(f"\n{Fore.RED}SQL Injection vulnerability found:{Fore.RESET}")
        print(f"URL: {Fore.CYAN}{vuln['url']}{Fore.RESET}")
        print(f"Parameter: {Fore.YELLOW}{vuln['parameter']}{Fore.RESET}")
        print(f"Payload: {Fore.MAGENTA}{vuln['payload']}{Fore.RESET}")
        print(f"Test URL: {Fore.BLUE}{vuln['test_url']}{Fore.RESET}")
        print(f"Type: {Fore.GREEN}{vuln['type']}{Fore.RESET}")

    def sqli_scan_url(url, print_queue):
        print_queue.put(f"{Fore.CYAN}Scanning for SQL injection vulnerabilities: {url}{Fore.RESET}")
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        for param in params:
            # Error-based SQLi
            error_payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' UNION SELECT NULL, NULL, NULL --",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1 UNION SELECT NULL, NULL, NULL --",
            ]
            
            for payload in error_payloads:
                encoded_payload = encode_payload(payload)
                test_params = params.copy()
                test_params[param] = [encoded_payload]
                test_url = parsed_url._replace(query=urlencode(test_params, doseq=True)).geturl()
                
                try:
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
                    response = requests.get(test_url, verify=False, headers=headers, timeout=10)
                    
                    sql_errors = [
                        r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result",
                        r"MySqlClient\.", r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*",
                        r"valid PostgreSQL result", r"Npgsql\.", r"Driver.*SQL SERVER",
                        r"OLE DB.*SQL SERVER", r"SQL Server.*Driver", r"Warning.*mssql_.*",
                        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
                        r"ODBC SQL Server Driver", r"SQLServer JDBC Driver", r"Oracle error",
                        r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"
                    ]
                    
                    for error in sql_errors:
                        if re.search(error, response.text, re.IGNORECASE):
                            vulnerability = {
                                "url": url,
                                "parameter": param,
                                "payload": encoded_payload,
                                "test_url": test_url,
                                "type": "Error-based SQLi"
                            }
                            print_queue.put(vulnerability)
                            return  # Exit after finding a vulnerability
                    
                except requests.RequestException as e:
                    print_queue.put(f"{Fore.YELLOW}Error scanning {test_url}: {str(e)}{Fore.RESET}")
            
            # Boolean-based blind SQLi
            original_params = params.copy()
            original_params[param] = ["1 AND 1=1"]
            true_url = parsed_url._replace(query=urlencode(original_params, doseq=True)).geturl()
            
            original_params[param] = ["1 AND 1=2"]
            false_url = parsed_url._replace(query=urlencode(original_params, doseq=True)).geturl()
            
            try:
                true_response = requests.get(true_url, verify=False, headers=headers, timeout=10)
                false_response = requests.get(false_url, verify=False, headers=headers, timeout=10)
                
                if true_response.text != false_response.text:
                    vulnerability = {
                        "url": url,
                        "parameter": param,
                        "payload": "1 AND 1=1 / 1 AND 1=2",
                        "test_url": f"{true_url} / {false_url}",
                        "type": "Boolean-based blind SQLi"
                    }
                    print_queue.put(vulnerability)
                    return  # Exit after finding a vulnerability
            
            except requests.RequestException as e:
                print_queue.put(f"{Fore.YELLOW}Error during boolean-based test for {url}: {str(e)}{Fore.RESET}")
            
            # Time-based blind SQLi
            time_payload = "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND '1'='1"
            encoded_time_payload = encode_payload(time_payload)
            time_params = params.copy()
            time_params[param] = [encoded_time_payload]
            time_url = parsed_url._replace(query=urlencode(time_params, doseq=True)).geturl()
            
            try:
                start_time = time.time()
                response = requests.get(time_url, verify=False, headers=headers, timeout=10)
                end_time = time.time()
                
                if end_time - start_time >= 5:
                    vulnerability = {
                        "url": url,
                        "parameter": param,
                        "payload": time_payload,
                        "test_url": time_url,
                        "type": "Time-based blind SQLi"
                    }
                    print_queue.put(vulnerability)
                    return  # Exit after finding a vulnerability
            
            except requests.RequestException as e:
                print_queue.put(f"{Fore.YELLOW}Error during time-based test for {url}: {str(e)}{Fore.RESET}")

    def print_worker(print_queue):
        while True:
            item = print_queue.get()
            if item is None:
                break
            if isinstance(item, dict):
                print_vulnerability(item)
            else:
                print(item)
            print_queue.task_done()

    def sqli_scanner(target):
        print_queue = Queue()
        print_thread = threading.Thread(target=print_worker, args=(print_queue,))
        print_thread.start()

        if os.path.isfile(target):
            with open(target, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(sqli_scan_url, url, print_queue) for url in urls]
                for future in as_completed(futures):
                    future.result()
        else:
            sqli_scan_url(target, print_queue)

        print_queue.put(None)
        print_thread.join()

    if __name__ == "__main__":
        sqli_scanner(args.sqli_scan)

        print(f"\n{Fore.GREEN}Scan completed.{Fore.RESET}")


if args.webserver_scan:
    init(autoreset=True)

    def get_server_info(url, path=''):
        full_url = urljoin(url, path)
        try:
            response = requests.get(full_url, allow_redirects=False, timeout=10)
            return response.headers, response.status_code, response.text
        except requests.RequestException:
            return {}, None, ''

    def analyze_headers(headers):
        server_info = {}
        for header, value in headers.items():
            if header.lower() == 'server':
                server_info['Server'] = value
            elif header.lower() == 'x-powered-by':
                server_info['X-Powered-By'] = value
            elif header.lower() == 'x-aspnet-version':
                server_info['ASP.NET'] = value
            elif header.lower() == 'x-generator':
                server_info['Generator'] = value
        return server_info

    def check_specific_files(url):
        files_to_check = {
            '/favicon.ico': {'Apache': 'Apache', 'Nginx': 'Nginx'},
            '/server-status': {'Apache': 'Apache Status'},
            '/nginx_status': {'Nginx': 'Nginx Status'},
            '/web.config': {'IIS': 'IIS Config'},
            '/phpinfo.php': {'PHP': 'PHP Version'}
        }
        
        results = {}
        for file, signatures in files_to_check.items():
            headers, status, content = get_server_info(url, file)
            if status == 200:
                for server, signature in signatures.items():
                    if signature in content:
                        results[server] = f"Detected via {file}"
        return results

    def detect_web_server(url):
        if not url.startswith('http'):
            url = 'http://' + url

        print(f"Scanning {Fore.GREEN}{url}{Fore.WHITE}...{Style.RESET_ALL}")

        headers, status, content = get_server_info(url)
        
        if status is None:
            print(f"{Fore.RED}Error: Unable to connect to the server{Style.RESET_ALL}")
            return

        server_info = analyze_headers(headers)
        
        if 'Server' not in server_info:
            if 'Set-Cookie' in headers and 'ASPSESSIONID' in headers['Set-Cookie']:
                server_info['Likely'] = 'IIS'
            elif 'Set-Cookie' in headers and 'PHPSESSID' in headers['Set-Cookie']:
                server_info['Likely'] = 'PHP'
        
        file_results = check_specific_files(url)
        server_info.update(file_results)

        if server_info:
            for key, value in server_info.items():
                print(f"{Fore.GREEN}{key}:{Style.RESET_ALL} {Fore.YELLOW}{value}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Unable to determine web server{Style.RESET_ALL}")

        if 'CF-RAY' in headers:
            print(f"{Fore.GREEN}Cloudflare detected{Style.RESET_ALL}")
        
        if 'X-Varnish' in headers:
            print(f"{Fore.GREEN}Varnish Cache detected{Style.RESET_ALL}")

    def main():
        detect_web_server(args.webserver_scan)

    if __name__ == "__main__":
        main()