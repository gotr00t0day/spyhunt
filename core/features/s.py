from colorama import Fore
import shodan
import subprocess
import os

def process_domain(domain, save_file=None, shodan_api=None):
    """Process a single domain for subdomain enumeration"""
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    spotter_path = os.path.join(current_script_dir, 'scripts', 'spotter.sh')
    certsh_path = os.path.join(current_script_dir, 'scripts', 'certsh.sh')
    
    results = []
    
    # Subfinder
    cmd = f"subfinder -d {domain} -silent"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = p.communicate()
    results.extend(out.decode().splitlines())
    
    # Spotter
    cmd = f"{spotter_path} {domain} | uniq | sort"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    spotterout, _ = p.communicate()
    results.extend(spotterout.decode().splitlines())
    
    # Cert.sh
    cmd = f"{certsh_path} {domain} | uniq | sort"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    certshout, _ = p.communicate()
    results.extend(certshout.decode().splitlines())
    
    # Shodan
    if shodan_api:
        try:
            api = shodan.Shodan(shodan_api)
            results = api.search(f'hostname:*.{domain}')
            for result in results['matches']:
                hostnames = result.get('hostnames', [])
                for hostname in hostnames:
                    if hostname.endswith(domain) and hostname != domain:
                        results.append(hostname)
        except shodan.APIError as e:
            print(Fore.RED + f"Error querying Shodan for {domain}: {e}")
    
    # Remove duplicates and sort
    results = sorted(set(results))
    
    if save_file:
        with open(save_file, "a") as f:
            for subdomain in results:
                if "www" in subdomain:
                    pass
                else:
                    f.write(f"{subdomain}\n")
        print(Fore.GREEN + f"Found {len(results)} subdomains for {domain}")
    else:
        print(Fore.CYAN + f"\nSubdomains for {domain}:\n")
        for subdomain in results:
            print(Fore.GREEN + f"{subdomain}")

