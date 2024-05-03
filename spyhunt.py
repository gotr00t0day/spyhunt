from colorama import Fore
from os import path
from builtwith import builtwith
from modules.favicon import *
from bs4 import BeautifulSoup
from multiprocessing.pool import ThreadPool
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urljoin
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

warnings.filterwarnings(action='ignore',module='bs4')

requests.packages.urllib3.disable_warnings()

banner = """


███████╗██████╗ ██╗   ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
███████╗██████╔╝ ╚████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   
╚════██║██╔═══╝   ╚██╔╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   
███████║██║        ██║   ██║  ██║╚██████╔╝██║ ╚████║   ██║   
╚══════╝╚═╝        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
V 1.8
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

parser.add_argument('-co', '--corsmisconfig',
                    type=str, help='cors misconfiguration',
                    metavar='domains.txt')

parser.add_argument('-hh', '--hostheaderinjection',
                    type=str, help='host header injection',
                    metavar='domain.com')

parser.add_argument('-sh', '--securityheaders',
                    type=str, help='scan for security headers',
                    metavar='domain.com')

parser.add_argument('-ed', '--enumeratedomain',
                    type=str, help='enumerate domains',
                    metavar='domain.com')

parser.add_argument('-smu', '--smuggler',
                    type=str, help='enumerate domains',
                    metavar='domain.com')

parser.add_argument('-rd', '--redirect',
                    type=str, help='get redirect links',
                    metavar='domain list')

parser.add_argument('-ips', '--ipaddresses',
                    type=str, help='get the ips from a list of domains',
                    metavar='domain list')

parser.add_argument('-dinfo', '--domaininfo',
                    type=str, help='get domain information like codes,server,content length',
                    metavar='domain list')

parser.add_argument('-isubs', '--importantsubdomains',
                    type=str, help='extract interesting subdomains from a list like dev, admin, test and etc..',
                    metavar='domain list')

parser.add_argument('-pspider', '--paramspider',
                    type=str, help='extract parameters from a domain',
                    metavar='domain.com')

parser.add_argument('-nft', '--not_found',
                    type=str, help='check for 404 status code',
                    metavar='domains.txt')

parser.add_argument('-ph', '--pathhunt',
                    type=str, help='check for directory traversal',
                    metavar='domain.txt')

args = parser.parse_args()



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
        commands(f"./tools/assetfinder -subs-only {args.s} | uniq | sort")
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
    server = []
    r = requests.get(f"{args.enumeratedomain}", verify=False) 
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
        except KeyError:
            pass

if args.corsmisconfig:
    print(f"\t\t\t{Fore.CYAN}CORS {Fore.MAGENTA}Misconfiguration {Fore.GREEN}Module\n\n")
    with open(args.corsmisconfig, "r") as f:
        domains = [x.strip() for x in f.readlines()]
        for domainlist in domains:
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
                        break
                else:
                    print(f"{Fore.CYAN}NOT VULNERABLE: {Fore.GREEN}{domainlist} {Fore.CYAN}PAYLOADS: {Fore.MAGENTA}{', '.join(payload)}")

            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.ConnectionError):
                    print(f"{Fore.RED}Connection error occurred while processing {domainlist}")
                else:
                    print(f"{Fore.LIGHTBLACK_EX}Error occurred while processing {domainlist}: {str(e)}")

if args.hostheaderinjection:
    print(f"{Fore.MAGENTA}\t\t Host Header Injection \n")
    redirect = {"301", "302", "303", "307", "308"}  # Use a set for faster lookup
    timeout = 5  # Timeout value in seconds
    with open(f"{args.hostheaderinjection}", "r") as f:
        domains = [x.strip() for x in f.readlines()]
        payload = b"google.com" 
        print(f"{Fore.WHITE} Checking For {Fore.CYAN}X-Forwarded-Host {Fore.WHITE}and {Fore.CYAN}Host {Fore.WHITE}injections.....\n")
        for domainlist in domains:
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

                vuln_domain = []
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
                    continue

            except requests.exceptions.RequestException as e:
                print(f"{Fore.LIGHTBLACK_EX} Error occurred while accessing {domainlist}: {e}")
                continue

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
        response = requests.get(args.j)
        html_content = response.text
        pattern = r'<script\s+(?:[^>]*?\s+)?src=(["\'])(.*?)\1'

        def extract_js(html_content):
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            js_urls = []
            for match in matches:
                relative_url = match[1]
                if relative_url.startswith(('http://', 'https://')):
                    full_url = relative_url
                elif relative_url.startswith('//'):
                    parsed_base_url = urlparse(args.j)
                    full_url = f"{parsed_base_url.scheme}:{relative_url}"
                else:
                    full_url = urljoin(args.j, relative_url)
                js_urls.append(full_url)
            return js_urls

        def extract_endpoints(js_url):
            response = requests.get(js_url)
            js_content = response.text

            context = execjs.get().compile(js_content)
            urls = [item for item in context.eval("Object.values(this)") if isinstance(item, str) and item.startswith(('http://', 'https://'))]

            return urls

        
        with ThreadPoolExecutor() as executor:
             js_urls = executor.submit(extract_js, html_content).result()
             
        try:
            all_endpoints = []
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(extract_endpoints, js_url) for js_url in js_urls]
                for future in concurrent.futures.as_completed(futures):
                    endpoints = future.result()
                    all_endpoints.extend(endpoints)
        except execjs._exceptions.ProcessExitedWithNonZeroStatus:
            pass

        for js_url in js_urls:
            print(js_url)

        print("\n\n")
        print("-------- ENDPOINTS -----------")
        print("\n\n")

        for endpoint in all_endpoints:
            print(f"{endpoint}\n")

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

if args.smuggler:
    smug_path = os.path.abspath(os.getcwd())
    commands(f"python3 {smug_path}/tools/smuggler/smuggler.py -u {args.smuggler} -q")

if args.redirect:
    user_agent = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36"
    header = {'User Agent': f'{user_agent}'}
    path = os.getcwd()
    with open(f"{path}/{args.redirect}") as f:
        domain_list = {x.strip() for x in f.readlines()}
    for domainlist in domain_list:
            r = requests.get(f"{domainlist}", verify=False, headers=header)
            if r.status_code == 301 or r.status_code == 302:
                print(f"{Fore.GREEN}{domainlist}")
            else:
                print(domainlist)

if args.ipaddresses:
    with open(f"{args.ipaddresses}", "r") as f:
        domains = [x.strip() for x in f.readlines()]
    for domain_list in domains:
        try:
            ips = socket.gethostbyname(domain_list)
            print(f"{Fore.GREEN} {domain_list} {Fore.WHITE}- {Fore.CYAN}{ips}")
        except socket.gaierror:
            pass

if args.domaininfo:
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    header = {"User-Agent": user_agent}
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
    user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    header = {"User-Agent": user_agent_}
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
    
