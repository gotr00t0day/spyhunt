from colorama import Fore
from modules import sub_output
import json

def nuclei_scan(template: str, url: str) -> str:
    print(f"Scanning {Fore.GREEN}{url} {Fore.WHITE}with {Fore.MAGENTA}{template}{Fore.WHITE}..\n")
    nuclei_output = sub_output.subpro_scan(f"nuclei -u {url} -t {template} -silent -c 20 -j -o vulnerable.json")
    return nuclei_output

def nuclei_parser(nuclei_output: str) -> str:
    try:
        with open("vulnerable.json", "r") as f:
            data = [x.strip() for x in f.readlines()]
        
        if not data:
            print(f"{Fore.YELLOW}No vulnerabilities found.{Fore.WHITE}")
            return
            
        results = []
        for data_item in data:
            try:
                json_result = json.loads(data_item)
                
                template_id = json_result.get("template-id", "N/A")
                matched_at = json_result.get("matched-at", "N/A")
                info = json_result.get("info", {})
                
                name = info.get("name", "Unknown Vulnerability")
                description = info.get("description", "No description available")
                severity = info.get("severity", "unknown")
                
                # Print findings
                print(f"{Fore.MAGENTA}Template ID: {Fore.GREEN}{template_id}")
                print(f"{Fore.MAGENTA}PoC: {Fore.GREEN}{matched_at}")
                print(f"{Fore.MAGENTA}Vulnerability: {Fore.GREEN}{name}")
                print(f"{Fore.MAGENTA}Description: {Fore.GREEN}{description}")
                print(f"{Fore.MAGENTA}Severity: {Fore.RED}{severity}")
                print("-" * 60)
                
                # Append to results
                results.append({
                    "template_id": template_id,
                    "matched_at": matched_at,
                    "name": name,
                    "description": description,
                    "severity": severity
                })
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}Error parsing JSON result: {e}{Fore.WHITE}")
                continue
            
        return results
    except FileNotFoundError:
        print(f"{Fore.RED}Error: vulnerable.json file not found. Nuclei scan may have failed.{Fore.WHITE}")
        return []
    except Exception as e:
        print(f"{Fore.RED}Error processing nuclei output: {str(e)}{Fore.WHITE}")
        return []
