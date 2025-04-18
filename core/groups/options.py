import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, init, Style
from os import path
from modules.favicon import fingerprint
from shutil import which
from modules.heap_dump import HeapdumpAnalyzer
import sys
import socket
import os
import codecs
import mmh3
import urllib3
from core.features.webserver_scan import detect_web_server
from core.features.forbidden import word_list, load_domains, scan_domain
from core.utils import commands, header

def run(args):

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

    if args.statuscode:
        commands(f"echo '{args.statuscode}' | httpx -silent -status-code")

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

    if args.webserver_scan:
        init(autoreset=True)
        detect_web_server(args.webserver_scan)

    #N2
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

    #N3
    if args.forbidden_domains:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist = word_list(os.path.join(current_dir, "payloads", "bypasses.txt"))
        domains = load_domains(args.forbidden_domains)
        print(f"{Fore.CYAN}Starting scan of {len(domains)} domains...{Style.RESET_ALL}\n")
        for domain in domains:
            scan_domain(domain, wordlist)

    if args.heapdump:
        analyzer = HeapdumpAnalyzer()
        analyzer.analyze(args.heapdump, args.output_dir)
