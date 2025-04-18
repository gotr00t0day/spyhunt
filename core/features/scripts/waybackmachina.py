
from waybackpy import WaybackMachineSaveAPI
from fake_useragent import UserAgent
from urllib.parse import urljoin
import requests
import re


# Extract all the links
ua = UserAgent()
url = "https://www.github.com"
header = {'User-Agent':str(ua.chrome)} 
user_agent = "Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0"
save_api = WaybackMachineSaveAPI(url, user_agent) 
site = save_api.save()
resp = requests.get(site, verify=False, headers=header)
if resp.status_code == 200:
    content = resp.content
    links = re.findall('(?:href=")(.*?)"', content.decode('utf-8'))
    duplicatelinks = set(links)
    for link in links:
        link = urljoin(site, link)
        if link not in duplicatelinks:
            print(f"{link} \n")