import requests
requests.packages.urllib3.disable_warnings()

import sys

def get_ip_ranges(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if 'data' in data and 'prefixes' in data['data']:
            return asn, [prefix['prefix'] for prefix in data['data']['prefixes']]
        else:
            return asn, []
    except requests.RequestException as e:
        print(f"Error fetching data for {asn}: {e}", file=sys.stderr)
        return asn, []

def process_asn(asn):
    print(f"Fetching IP ranges for AS{asn}...")
    return get_ip_ranges(asn)

