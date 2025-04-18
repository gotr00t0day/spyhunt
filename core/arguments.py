import argparse

parser = argparse.ArgumentParser()

group = parser.add_mutually_exclusive_group()
group.add_argument('-sv', '--save', action='store', help="save output to file", metavar="filename.txt")#N0.7
group.add_argument('-wl', '--wordlist', action='store', help="wordlist to use", metavar="filename.txt")#N3.4

#N0
parser.add_argument('-th', '--threads', type=str, help='default 25', metavar='25')
parser.add_argument("-c", "--concurrency", type=int, default=10, help="Maximum number of concurrent requests")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
parser.add_argument('--proxy', help='Use a proxy (e.g., http://proxy.com:8080)')
parser.add_argument('--proxy-file', help='Load proxies from file')
parser.add_argument('--output-dir', help='Output directory', default='.')

# N1
parser.add_argument('-fi', '--favicon', type=str, help='get favicon hashes', metavar='https://domain.com')
parser.add_argument('-fm', '--faviconmulti', type=str, help='get favicon hashes', metavar='https://domain.com')
parser.add_argument('-sc', '--statuscode', type=str, help='statuscode', metavar='domain.com')    
parser.add_argument('-ri', '--reverseip', type=str, help='reverse ip lookup', metavar='IP')
parser.add_argument('-rim', '--reverseipmulti', type=str, help='reverse ip lookup for multiple ips', metavar='IP')
parser.add_argument('-sh', '--securityheaders', type=str, help='scan for security headers', metavar='domain.com') 
parser.add_argument('-webserver', '--webserver_scan', type=str, help='webserver scan', metavar='domain.com') 

#N2
parser.add_argument('-p', '--probe', type=str, help='probe domains.', metavar='domains.txt')
parser.add_argument('-r', '--redirects', type=str, help='links getting redirected', metavar='domains.txt')    
parser.add_argument('-ed', '--enumeratedomain', type=str, help='enumerate domains', metavar='domain.com') 
parser.add_argument('-isubs', '--importantsubdomains', type=str, help='extract interesting subdomains from a list like dev, admin, test and etc..', metavar='domain list') 

#N3
parser.add_argument('--shodan-api', help='Shodan API key for subdomain enumeration')
parser.add_argument('--forbidden_domains', help='File containing list of domains to scan for forbidden bypass') #fpass
parser.add_argument('--heapdump', help='Analyze Java heapdump file')


update_group = parser.add_argument_group('Update')
update_group.add_argument('-u', '--update', action='store_true', help='Update the script')#N0.8

passiverecon_group = parser.add_argument_group('Passive Recon')
passiverecon_group.add_argument('-s', type=str, help='scan for subdomains', metavar='domain.com')
passiverecon_group.add_argument('-d', '--dns', type=str, help='scan a list of domains for dns records', metavar='domains.txt')
passiverecon_group.add_argument('-na', '--networkanalyzer', type=str, help='net analyzer', metavar='https://domain.com')
passiverecon_group.add_argument('-ips', '--ipaddresses', type=str, help='get the ips from a list of domains', metavar='domain list') 
passiverecon_group.add_argument('-dinfo', '--domaininfo', type=str, help='get domain information like codes,server,content length', metavar='domain list') 
passiverecon_group.add_argument('-sho', '--shodan_', type=str, help='Recon with shodan', metavar='domain.com') 
passiverecon_group.add_argument('-shodan', '--shodan_api', type=str, help='shodan api key', metavar='KEY') 
passiverecon_group.add_argument('-gs', '--google', action='store_true', help='Google Search')

vuln_group = parser.add_argument_group('Vulnerability')
vuln_group.add_argument('-b', '--brokenlinks', type=str, help='search for broken links', metavar='domains.txt')
vuln_group.add_argument('-ph', '--pathhunt', type=str, help='check for directory traversal', metavar='domain.txt')
vuln_group.add_argument('-co', '--corsmisconfig', type=str, help='cors misconfiguration', metavar='domains.txt')
vuln_group.add_argument('-hh', '--hostheaderinjection', type=str, help='host header injection', metavar='domain.com') 
vuln_group.add_argument('-smu', '--smuggler', type=str, help='enumerate domains', metavar='domain.com') 
vuln_group.add_argument('-fp', '--forbiddenpass', type=str, help='Bypass 403 forbidden', metavar='domain.com') 
vuln_group.add_argument('-xss', '--xss_scan', type=str, help='scan for XSS vulnerabilities', metavar='https://example.com/page?param=value') 
vuln_group.add_argument('-sqli', '--sqli_scan', type=str, help='scan for SQLi vulnerabilities', metavar='https://example.com/page?param=value') 
vuln_group.add_argument('-or', '--openredirect', type=str, help='open redirect', metavar='domain.com') 
vuln_group.add_argument('-st', '--subdomaintakeover', type=str, help='subdomain takeover', metavar='subdomains.txt') 
vuln_group.add_argument('-jwt', '--jwt_scan', type=str, help='analyze JWT token for vulnerabilities', metavar='token') 
vuln_group.add_argument('-jwt-modify', '--jwt_modify', type=str, help='modify JWT token', metavar='token') 
vuln_group.add_argument('-heapds', '--heapdump_file', type=str, help='file for heapdump scan', metavar='heapdump.txt') 
vuln_group.add_argument('-heapts', '--heapdump_target', type=str, help='target for heapdump scan', metavar='domain.com') 
vuln_group.add_argument('-zt', '--zone-transfer', type=str, help='Test for DNS zone transfer vulnerability', metavar='domain.com')

crawlers_group = parser.add_argument_group('Crawlers')
crawlers_group.add_argument('-pspider', '--paramspider', type=str, help='extract parameters from a domain', metavar='domain.com')
crawlers_group.add_argument('-w', '--waybackurls', type=str, help='scan for waybackurls', metavar='https://domain.com')
crawlers_group.add_argument('-j', type=str, help='find javascript files', metavar='domain.com')
crawlers_group.add_argument('-wc', '--webcrawler', type=str, help='scan for urls and js files', metavar='https://domain.com')
crawlers_group.add_argument('-javascript', '--javascript_scan', type=str, help='scan for sensitive info in javascript files', metavar='domain.com') 
crawlers_group.add_argument('-dp', '--depth', type=str, help='depth of the crawl', metavar='10') 
crawlers_group.add_argument('-je', '--javascript_endpoints', type=str, help='extract javascript endpoints', metavar='file.txt') 
crawlers_group.add_argument('-hibp', '--haveibeenpwned', type=str, help='check if the password has been pwned', metavar='password') 

fuzzing_group = parser.add_argument_group('Fuzzing')
fuzzing_group.add_argument('-nft', '--not_found', type=str, help='check for 404 status code', metavar='domains.txt') 
fuzzing_group.add_argument('-api', '--api_fuzzer', type=str, help='Look for API endpoints', metavar='domain.com') 
fuzzing_group.add_argument('-db', '--directorybrute', type=str, help='Brute force filenames and directories', metavar='domain.com') 
fuzzing_group.add_argument('-pm', '--param_miner', type=str, help='param miner', metavar='domain.com') 
fuzzing_group.add_argument('-ch', '--custom_headers', type=str, help='custom headers', metavar='domain.com') 
fuzzing_group.add_argument('-asn', '--automoussystemnumber', type=str, help='asn', metavar='AS55555') 
fuzzing_group.add_argument('-ar', '--autorecon', type=str, help='auto recon', metavar='domain.com') 
fuzzing_group.add_argument('-f_p', '--forbidden_pages', type=str, help='forbidden pages', metavar='domain.com')
fuzzing_group.add_argument("-e", "--extensions", help="Comma-separated list of file extensions to scan", default="")
fuzzing_group.add_argument("-x", "--exclude", help="Comma-separated list of status codes to exclude", default="")

portscanning_group = parser.add_argument_group('Port Scanning')
portscanning_group.add_argument('-n', '--nmap', type=str, help='Scan a target with nmap', metavar='domain.com or IP') 
portscanning_group.add_argument('-cidr', '--cidr_notation', type=str, help='Scan an ip range to find assets and services', metavar='IP/24') 
portscanning_group.add_argument('-ps', '--ports', type=str, help='Port numbers to scan', metavar='80,443,8443') 
portscanning_group.add_argument('-pai', '--print_all_ips', type=str, help='Print all ips', metavar='IP/24') 

nuclei_group = parser.add_argument_group('Nuclei Scans')
nuclei_group.add_argument('-nl', '--nuclei_lfi', action='store_true', help="Find Local File Inclusion with nuclei")
nuclei_group.add_argument("-nc", "--nuclei", type=str, help="scan nuclei on a target", metavar="domain.com")
nuclei_group.add_argument("-nct", "--nuclei_template", type=str, help="use a nuclei template", metavar="template.yaml")

cloud_group = parser.add_argument_group('Cloud Security')
cloud_group.add_argument('-aws', '--aws-scan', type=str, help='Scan for exposed AWS resources', metavar='domain.com')
cloud_group.add_argument('-az', '--azure-scan', type=str, help='Scan for exposed Azure resources', metavar='domain.com') 
cloud_group.add_argument('--s3-scan', help='Scan for exposed S3 buckets')
cloud_group.add_argument('-gcp', '--gcp-scan', type=str, help='Scan for exposed GCP Storage resources', metavar='domain.com')

bruteforcing_group = parser.add_argument_group('Bruteforcing')
bruteforcing_group.add_argument('--brute-user-pass', type=str, help='Bruteforcing username and password input fields', metavar='domain.com')
bruteforcing_group.add_argument('--username_wordlist', type=str, help='Bruteforcing username and password input fields', metavar='domain.com')
bruteforcing_group.add_argument('--password_wordlist', type=str, help='Bruteforcing username and password input fields', metavar='domain.com')

ip_group = parser.add_argument_group('IP Information')
ip_group.add_argument('--ipinfo', type=str, help='Get IP info for a company domain/IP', metavar='TARGET')
ip_group.add_argument('--token', type=str, help='IPinfo API token', metavar='TOKEN')
ip_group.add_argument('--save-ranges', type=str, help='Save IP ranges to file', metavar='FILENAME')
