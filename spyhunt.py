from shutil import which
from colorama import Fore, Back, Style
from os import path
import os.path
import socket
import subprocess
import sys
import socket
import os
import argparse
import time


banner = """



  ██████  ██▓███ ▓██   ██▓ ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓
▒██    ▒ ▓██░  ██▒▒██  ██▒▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒
░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░
  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒  ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   
░ ░▒  ░ ░░▒ ░     ▓██ ░▒░  ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░    
░  ░  ░  ░░       ▒ ▒ ░░   ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░  v 1.0 
      ░           ░ ░      ░  ░  ░   ░              ░          
                  ░ ░          by c0deNinja



"""

print(Fore.RED + banner)
print(Fore.WHITE)

def commands(cmd):
    try:
        subprocess.check_call(cmd, shell=True)
    except:
        pass

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

group.add_argument('-sv', '--save', action='store_true',
                   help="save output to file")

parser.add_argument('-s',
                    type=str, help='scan for subdomains',
                    metavar='domain.com')

parser.add_argument('-j',
                    type=str, help='find javascript files',
                    metavar='domain.com')

parser.add_argument('-d', '--dns',
                    type=str, help='scan for dns records',
                    metavar='domain.com')

parser.add_argument('-p', '--probe',
                    type=str, help='probe domains.',
                    metavar='domains.txt')

parser.add_argument('-r', '--redirects',
                    type=str, help='links getting redirected',
                    metavar='domains.txt')



args = parser.parse_args()

if args.s:
    if args.save:
        print(Fore.CYAN + "Saving output to subdomains.txt...")
        cmd = f"subfinder -d {args.s}"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, err = p.communicate()
        out = out.decode()  
        with open("subdomains.txt", "w") as subfinder:
            subfinder.writelines(out)
        if path.exists("subdomains.txt"):
            print(Fore.GREEN + "DONE!")
        if not path.exists("subdomains.txt"):
            print(Fore.RED + "ERROR!")
            sys.exit(1)
        cmd = f"./scripts/spotter.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        spotterout, err = p.communicate()
        spotterout = spotterout.decode()
        with open("subdomains.txt", "a") as spotter:
            spotter.writelines(spotterout)
        cmd = f"./scripts/certsh.sh {args.s} | uniq | sort"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        certshout, err = p.communicate()
        certshout = certshout.decode()
    else:
        commands(f"subfinder -d {args.s}")
        commands(f"./scripts/spotter.sh {args.s} | uniq | sort")
        commands(f"./scripts/certsh.sh {args.s} | uniq | sort") 

if args.j:
    if args.save:
        print(Fore.CYAN + "Saving output to javascript.txt...")
        commands(f"echo {args.j} | waybackurls | grep '\\.js$' | uniq | sort >> javascript.txt")
        commands(f"echo {args.j} | gau | grep -Eo 'https?://\\S+?\\.js' | anew >> javascript.txt")
        if path.exists("javascript.txt"):
            print(Fore.GREEN + "DONE!")
        if not path.exists("javascript.txt"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f"echo {args.j} | waybackurls | grep '\\.js$' | uniq | sort")
        commands(f"echo {args.j} | gau | grep -Eo 'https?://\\S+?\\.js' | anew")  

if args.dns:
    if args.save:
        print(Fore.CYAN + "Saving output to dnsinfo.txt...")
        commands(f"cat {args.dns} | dnsx -silent -a -resp >> dnsinfo.txt")
        commands(f"cat {args.dns} | dnsx -silent -ns -resp >> dnsinfo.txt")
        commands(f"cat {args.dns} | dnsx -silent -cname -resp >> dnsinfo.txt")
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
        print(Fore.CYAN + "Saving output to livesubdomains.txt...")
        commands(f'cat {args.probe} | httprobe | anew >> livesubdomains.txt')
        if path.exists("livesubdomains.txt"):
            print(Fore.GREEN + "DONE!")
        if not path.exists("livesubdomains.txt"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f'sudo cat {args.probe} | httprobe | anew')    

if args.redirects:
    if args.save:
        print(Fore.CYAN + "Saving output to redirects.txt..")
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302 | anew >> redirects.txt")
        if path.exists("redirects.txt"):
            print(Fore.GREEN + "DONE!")
        if not path.exists("redirects.txt"):
            print(Fore.RED + "ERROR!")
    else:
        commands(f"cat {args.redirects} | httpx -silent -location -mc 301,302")   


 



