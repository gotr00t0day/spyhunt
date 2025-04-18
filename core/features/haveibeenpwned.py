import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore
import hashlib

def check_password_pwned(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url)
        response.raise_for_status()

        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                print(f"The password {Fore.GREEN}'{password}'{Fore.RESET} has been seen {Fore.RED}{count} times.{Fore.RESET}")
                return

        print(f"The password {Fore.GREEN}'{password}'{Fore.RESET} has not been found in any breaches.")

    except requests.exceptions.HTTPError as err:
        print(f"Error checking password: {err}")
    except Exception as e:
        print(f"An error occurred: {e}")
