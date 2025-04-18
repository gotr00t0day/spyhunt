import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore

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
                if r.status_code == 200 and "Welcome" in r.text:
                    color = Fore.GREEN
                elif r.status_code == 301 or r.status_code == 302:
                    color = Fore.YELLOW
                else:
                    color = Fore.BLUE
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
        
