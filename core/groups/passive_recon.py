from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(action='ignore',module='bs4')

import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore
from os import path
from googlesearch import search
import sys
import socket
import os
import time
import shodan
from concurrent.futures import ThreadPoolExecutor
from core.features.s import process_domain
from core.features.ipaddresses import scan_do
from core.features.google import search_google
from core.utils import commands, header

def run(args):

    # Modify the argument parser to accept either a single domain or a file
    if args.s:
        if os.path.isfile(args.s):
            # Reading domains from file
            print(Fore.CYAN + f"Reading domains from {args.s}")
            with open(args.s) as f:
                domains = [line.strip() for line in f if line.strip()]
            
            for domain in domains:
                print(Fore.YELLOW + f"\nProcessing {domain}...")
                process_domain(domain, args.save, args.shodan_api)
        else:
            # Single domain
            process_domain(args.s, args.save, args.shodan_api)

    if args.networkanalyzer:
        print(f"{Fore.MAGENTA}\t\t Analyzing Network Vulnerabilities \n")
        print(f"{Fore.CYAN}IP Range: {Fore.GREEN}{args.networkanalyzer}\n")
        print(f"{Fore.WHITE}")
        commands(f"shodan stats --facets port net:{args.networkanalyzer}")
        commands(f"shodan stats --facets vuln net:{args.networkanalyzer}")

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

    if args.ipaddresses:
        ip_list = []
        with open(f"{args.ipaddresses}", "r") as f:
            domains = [x.strip() for x in f.readlines()]
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_do, domain, ip_list) for domain in domains]
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

    if args.shodan_:
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

    if args.google:
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
