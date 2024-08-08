import platform
import subprocess
import os
from shutil import which
from colorama import Fore, init

init(autoreset=True)

def run_command(cmd):
    try:
        print(f"{Fore.CYAN}Running command: {cmd}{Fore.RESET}")
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"{Fore.GREEN}Command output: {output.strip()}{Fore.RESET}")
        return output
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Failed to run command: {cmd}")
        print(f"Error: {e.output}")
        return None

def detect_package_manager():
    package_managers = [
        ("apt", "apt"),
        ("dnf", "dnf"),
        ("yum", "yum"),
        ("pacman", "pacman"),
        ("zypper", "zypper"),
        ("apk", "apk")
    ]
    
    for pm, cmd in package_managers:
        if which(cmd):
            return pm
    
    return None

def install_package(package, manager):
    if manager == "apt":
        return run_command(f"sudo apt install -y {package}")
    elif manager == "dnf" or manager == "yum":
        return run_command(f"sudo {manager} install -y {package}")
    elif manager == "pacman":
        return run_command(f"sudo pacman -S --noconfirm {package}")
    elif manager == "zypper":
        return run_command(f"sudo zypper install -y {package}")
    elif manager == "apk":
        return run_command(f"sudo apk add {package}")
    elif manager == "brew":
        return run_command(f"brew install {package}")
    elif manager == "pip":
        return run_command(f"pip3 install {package}")
    elif manager == "npm":
        return run_command(f"sudo npm install -g {package}")
    elif manager == "go":
        return run_command(f"go install {package}")

def install_tool(name, install_cmd, check_cmd=None):
    if check_cmd is None:
        check_cmd = name
    if not which(check_cmd):
        print(f"{Fore.YELLOW}Installing {name}...{Fore.RESET}")
        result = install_cmd()
        if result is not None:
            print(f"{Fore.GREEN}{name} installed successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Failed to install {name}{Fore.RESET}")
    else:
        print(f"{Fore.GREEN}Found {name}{Fore.RESET}")

def install_go_tool(tool, package):
    print(f"{Fore.YELLOW}Installing {tool}...{Fore.RESET}")
    if run_command(f"go install {package}") is not None:
        go_path = run_command("go env GOPATH").strip()
        bin_path = os.path.join(go_path, "bin", tool)
        if os.path.exists(bin_path):
            run_command(f"sudo mv {bin_path} /usr/local/bin/")
            print(f"{Fore.GREEN}{tool} installed successfully{Fore.RESET}")
        else:
            print(f"{Fore.RED}Failed to find {tool} in GOPATH{Fore.RESET}")
    else:
        print(f"{Fore.RED}Failed to install {tool}{Fore.RESET}")

def main():
    system = platform.system()
    if system == "Linux":
        package_manager = detect_package_manager()
        if package_manager is None:
            print(f"{Fore.RED}Unable to detect package manager. Please install packages manually.{Fore.RESET}")
            return
        print(f"{Fore.GREEN}Detected package manager: {package_manager}{Fore.RESET}")
    elif system == "Darwin":  # macOS
        package_manager = "brew"
        if not which("brew"):
            print(f"{Fore.RED}Homebrew is required for macOS. Please install it first.{Fore.RESET}")
            return
    else:
        print(f"{Fore.RED}Unsupported operating system: {system}{Fore.RESET}")
        return

    home = os.path.expanduser("~")
    
    # Install colorama
    install_tool("colorama", lambda: install_package("colorama", "pip"))

    # Install golang
    install_tool("go", lambda: install_package("golang", package_manager))

    # Install nodejs and npm
    install_tool("node", lambda: install_package("nodejs", package_manager))
    install_tool("npm", lambda: install_package("npm", package_manager))

    # Install broken-link-checker
    install_tool("blc", lambda: install_package("broken-link-checker", "npm"))

    # Install nuclei
    install_go_tool("nuclei", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")

    # Clone nuclei-templates
    if not os.path.exists(os.path.join(home, "nuclei-templates")):
        run_command(f"git clone https://github.com/projectdiscovery/nuclei-templates.git {home}/nuclei-templates")

    # Install other tools
    tools = [
        ("dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
        ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
        ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
        ("httprobe", "github.com/tomnomnom/httprobe@latest"),
        ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
        ("anew", "github.com/tomnomnom/anew@latest"),
        ("gau", "github.com/lc/gau/v2/cmd/gau@latest"),
        ("gauplus", "github.com/bp0lr/gauplus@latest"),
        ("hakrawler", "github.com/hakluke/hakrawler@latest"),
        ("assetfinder", "github.com/tomnomnom/assetfinder@latest"),
    ]

    for tool, go_package in tools:
        install_go_tool(tool, go_package)

    # Install jq
    install_tool("jq", lambda: install_package("jq", package_manager))

    # Install shodan
    install_tool("shodan", lambda: install_package("shodan", "pip"))

    # Install paramspider
    install_tool("paramspider", lambda: run_command("git clone https://github.com/devanshbatham/paramspider && cd paramspider && python3 setup.py install"))

if __name__ == "__main__":
    main()

