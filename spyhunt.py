from colorama import Fore
from core.groups import (
    passive_recon, cloud_security, vulnerability,
    crawlers, fuzzing, ip_information, nuclei_scans,
    port_scanning, update, bruteforcing, options
)
from core.arguments import parser

banner = f"""


  ██████  ██▓███ ▓██   ██▓ ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓
▒██    ▒ ▓██░  ██▒▒██  ██▒▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒
░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░
  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ 
▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒  ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   
░ ░▒  ░ ░░▒ ░     ▓██ ░▒░  ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░    
░  ░  ░  ░░       ▒ ▒ ░░   ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░      
      ░           ░ ░      ░  ░  ░   ░              ░         
{Fore.WHITE}V 3.2
{Fore.WHITE}By c0deninja
{Fore.RESET}
"""

print(Fore.MAGENTA + banner)
print(Fore.WHITE)

args = parser.parse_args()

# Dictionary mapping groups to their respective files and activation status (initially False)
group_files = {
    "Options": {"file": "options", "active": False},  # For arguments without a group
    "Update": {"file": "update", "active": False},
    "Passive Recon": {"file": "passive_recon", "active": False},
    "Vulnerability": {"file": "vulnerability", "active": False},
    "Crawlers": {"file": "crawlers", "active": False},
    "Fuzzing": {"file": "fuzzing", "active": False},
    "Port Scanning": {"file": "port_scanning", "active": False},
    "Nuclei Scans": {"file": "nuclei_scans", "active": False},
    "Cloud Security": {"file": "cloud_security", "active": False},
    "Bruteforcing": {"file": "bruteforcing", "active": False},
    "IP Information": {"file": "ip_information", "active": False},
}

# Convert args to a dictionary to access argument names and values
all_args = vars(args)

# Iterate over each argument in args
for arg_name, arg_value in all_args.items():
    found_group = None
    # Iterate through all groups in the parser
    for group in parser._action_groups:
        if group.title not in ['positional arguments', 'optional arguments']:
            # Check if the argument belongs to this group
            for action in group._group_actions:
                if action.dest == arg_name:
                    found_group = group.title
                    break
            if found_group:
                break
    # Use "Options" if no group is found, otherwise use the found group's name
    group_key = found_group if found_group else "Options"
    # Set the 'active' flag to True in the dictionary for the corresponding group
    if group_key in group_files:
        group_files[group_key]["active"] = True

# Execute run(args) for each active group using the file name to reference the imported module
for group, details in group_files.items():
    if details["active"]:  # Check if the group is active
        module_name = details["file"]
        # Access the module from globals() using the file name
        module = globals().get(module_name)
        if module:
            try:
                # Call the run(args) function from the module
                module.run(args)
            except Exception as e:
                print(f"Error executing run(args) for module {module_name}: {e}")
        else:
            print(f"Module {module_name} not found in imported modules.")