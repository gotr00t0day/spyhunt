import json

def load_json(file_path):
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    return None

def extract_a_records(data):
    return data.get('a', [])

def extract_mx_records(data):
    return data.get('mx', [])

def extract_txt_records(data):
    return data.get('txt', [])

def extract_resolvers(data):
    return data.get('resolver', [])

def extract_soa_records(data):
    return data.get('soa', [])

def save_to_file(items, output_file, header=None):
    try:
        with open(output_file, 'w') as file:
            if header:
                file.write(f"{header}\n")
            for item in items:
                file.write(f"{item}\n")
        print(f"Data saved to {output_file}")
    except IOError as e:
        print(f"Error writing to file {output_file}: {e}")

def print_soa_records(soa_records):
    print("SOA Records:")
    for i, soa in enumerate(soa_records, start=1):
        print(f"  SOA Record {i}:")
        print(f"    Name: {soa.get('name', 'N/A')}")
        print(f"    NS: {soa.get('ns', 'N/A')}")
        print(f"    Mailbox: {soa.get('mailbox', 'N/A')}")
        print(f"    Serial: {soa.get('serial', 'N/A')}")
        print(f"    Refresh: {soa.get('refresh', 'N/A')}")
        print(f"    Retry: {soa.get('retry', 'N/A')}")
        print(f"    Expire: {soa.get('expire', 'N/A')}")
        print(f"    Min TTL: {soa.get('minttl', 'N/A')}\n")

def main():
    # Load JSON data
    json_data = load_json('dnsscan.json')
    if not json_data:
        return
    
    # Extract fields
    host = json_data.get('host', 'N/A')
    ttl = json_data.get('ttl', 'N/A')
    status_code = json_data.get('status_code', 'N/A')
    timestamp = json_data.get('timestamp', 'N/A')
    
    print(f"Host: {host}")
    print(f"TTL: {ttl}")
    print(f"Status Code: {status_code}")
    print(f"Timestamp: {timestamp}\n")
    
    # A Records
    a_records = extract_a_records(json_data)
    print(f"A Records ({len(a_records)}):")
    for ip in a_records:
        print(f"  - {ip}")
    print()
    save_to_file(a_records, 'a_records.txt', header="A Records")
    
    # MX Records
    mx_records = extract_mx_records(json_data)
    print(f"MX Records ({len(mx_records)}):")
    for mx in mx_records:
        print(f"  - {mx}")
    print()
    save_to_file(mx_records, 'mx_records.txt', header="MX Records")
    
    # TXT Records
    txt_records = extract_txt_records(json_data)
    print(f"TXT Records ({len(txt_records)}):")
    for txt in txt_records:
        print(f"  - {txt}")
    print()
    save_to_file(txt_records, 'txt_records.txt', header="TXT Records")
    
    # Resolver Information
    resolvers = extract_resolvers(json_data)
    print(f"Resolvers ({len(resolvers)}):")
    for resolver in resolvers:
        print(f"  - {resolver}")
    print()
    save_to_file(resolvers, 'resolvers.txt', header="Resolvers")
    
    # SOA Records
    soa_records = extract_soa_records(json_data)
    print_soa_records(soa_records)
    # Saving SOA records as JSON for better structure
    try:
        with open('soa_records.json', 'w') as file:
            json.dump(soa_records, file, indent=4)
        print("SOA records saved to soa_records.json\n")
    except IOError as e:
        print(f"Error writing to file soa_records.json: {e}\n")
    
    # NS Records
    ns_records = json_data.get('ns', [])
    print(f"NS Records ({len(ns_records)}):")
    for ns in ns_records:
        print(f"  - {ns}")
    print()
    save_to_file(ns_records, 'ns_records.txt', header="NS Records")
    
    # All Records
    all_records = json_data.get('all', [])
    print(f"All DNS Records ({len(all_records)}):")
    for record in all_records:
        print(f"  - {record}")
    print()
    save_to_file(all_records, 'all_dns_records.txt', header="All DNS Records")
    
    # AXFR Information
    axfr_info = json_data.get('axfr', {})
    print("AXFR Information:")
    for key, value in axfr_info.items():
        print(f"  {key}: {value}")
    print()
    # Saving AXFR info as JSON
    try:
        with open('axfr_info.json', 'w') as file:
            json.dump(axfr_info, file, indent=4)
        print("AXFR information saved to axfr_info.json\n")
    except IOError as e:
        print(f"Error writing to file axfr_info.json: {e}\n")

if __name__ == "__main__":
    main()