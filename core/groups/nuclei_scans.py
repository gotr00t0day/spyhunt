from colorama import Fore
from core.features.nuclei import nuclei_scan, nuclei_parser
from core.utils import scan

def run(args):

    if args.nuclei_lfi:
        vulnerability = []
        FileOrTarget = str(input("Do you want to scan a file or a single target?? Ex: F or T:  "))
        if FileOrTarget == "F" or FileOrTarget == "f":
            File = str(input("Filename: "))
            print(f"Scanning File {File} ..... \n")
            results = scan(f"nuclei -l {File} -tags lfi -c 100")
            vulnerability.append(results)
            if vulnerability:
                for vulns in vulnerability:
                    print(vulns)
        elif FileOrTarget == "T" or FileOrTarget == "t":
            Target = str(input("Target: "))
            print(f"Scanning Target {Target} ..... \n")
            results = scan(f"nuclei -u {Target} -tags lfi -c 100")
            vulnerability.append(results)
            if vulnerability:
                for vulns in vulnerability:
                    print(vulns)
        else:
            print("Enter either T or F")

    if args.nuclei:    
        template = args.nuclei_template
        url = args.nuclei
        if not template or not url:
            print(f"{Fore.RED}Error: Both template and URL are required for nuclei scanning.{Fore.WHITE}")
            print(f"Usage: python spyhunt.py --nuclei [URL] --nuclei-template [TEMPLATE_PATH]")
        else:    
            results = nuclei_scan(template, url)
            nuclei_parser(results)

        