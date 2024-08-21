import platform, subprocess, os, time
from shutil import which
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init

init(autoreset=True)

def run_command(cmd):
    try:
        print(f"{Fore.CYAN}Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}{Fore.RESET}")
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"{Fore.GREEN}{output.strip()}{Fore.RESET}")
        return output
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error: {e.output.strip()}{Fore.RESET}")
        return None

def detect_package_manager():
    if os.path.exists("/data/data/com.termux/files/usr"):
        return "pkg"
    for pm in ["apt", "dnf", "yum", "pacman", "zypper", "apk", "brew", "choco"]:
        if which(pm):
            return pm
    return None

def install_package(package, manager):
    commands = {
        "apt": ["sudo", "apt", "install", "-y", package],
        "dnf": ["sudo", "dnf", "install", "-y", package],
        "yum": ["sudo", "yum", "install", "-y", package],
        "pacman": ["sudo", "pacman", "-S", "--noconfirm", package],
        "zypper": ["sudo", "zypper", "install", "-y", package],
        "apk": ["sudo", "apk", "add", package],
        "pkg": ["pkg", "install", "-y", package],
        "brew": ["brew", "install", package],
        "choco": ["choco", "install", package, "-y"]
    }
    return run_command(commands.get(manager))

def install_tool(name, install_cmd, check_cmd=None):
    check_cmd = check_cmd or name
    if which(check_cmd) is None:
        print(f"{Fore.YELLOW}Installing {name}...{Fore.RESET}")
        install_cmd()
    else:
        print(f"{Fore.GREEN}{name} is already installed{Fore.RESET}")

def install_go_tool(tool, package, retries=3, delay=5):
    for _ in range(retries):
        if run_command(["go", "install", package]) is not None:
            go_path = run_command(["go", "env", "GOPATH"]).strip()
            bin_path = os.path.join(go_path, "bin", tool)
            if os.path.exists(bin_path):
                run_command(["mv", bin_path, "$PREFIX/bin/"])
                print(f"{Fore.GREEN}{tool} installed successfully{Fore.RESET}")
                return
        print(f"{Fore.YELLOW}Retrying in {delay} seconds...{Fore.RESET}")
        time.sleep(delay)
    print(f"{Fore.RED}Failed to install {tool} after {retries} attempts{Fore.RESET}")

def install_tools_parallel(tools):
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(tool[1]) for tool in tools]
        for future in futures:
            future.result()

def handle_input(prompt="Press Enter to continue..."):
    try:
        input(prompt)
    except EOFError:
        pass  # Handle case where input is not expected, e.g., script automation

def main():
    system = platform.system()
    package_manager = detect_package_manager()

    if package_manager is None:
        print(f"{Fore.RED}No package manager found. Install packages manually.{Fore.RESET}")
        return

    print(f"{Fore.GREEN}Detected package manager: {package_manager}{Fore.RESET}")

    # Install colorama
    install_tool("colorama", lambda: run_command(["pip3", "install", "colorama"]))

    # Handle platform-specific installations
    go_install = lambda: install_package("golang", package_manager)
    node_install = lambda: install_package("nodejs", package_manager)
    npm_install = lambda: install_package("npm", package_manager)
    if package_manager == "pkg":
        go_install = lambda: run_command(["pkg", "install", "-y", "golang"])
        node_install = lambda: run_command(["pkg", "install", "-y", "nodejs"])
        npm_install = lambda: run_command(["pkg", "install", "-y", "npm"])

    install_tool("go", go_install)
    install_tool("node", node_install)
    install_tool("npm", npm_install)

    install_tool("blc", lambda: run_command(["npm", "install", "-g", "broken-link-checker"]))

    tools = [
        ("nuclei", lambda: install_go_tool("nuclei", "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")),
        ("dnsx", lambda: install_go_tool("dnsx", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest")),
        ("subfinder", lambda: install_go_tool("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")),
        ("waybackurls", lambda: install_go_tool("waybackurls", "github.com/tomnomnom/waybackurls@latest")),
        ("httprobe", lambda: install_go_tool("httprobe", "github.com/tomnomnom/httprobe@latest")),
        ("httpx", lambda: install_go_tool("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest")),
        ("anew", lambda: install_go_tool("anew", "github.com/tomnomnom/anew@latest")),
        ("gau", lambda: install_go_tool("gau", "github.com/lc/gau/v2/cmd/gau@latest")),
        ("gauplus", lambda: install_go_tool("gauplus", "github.com/bp0lr/gauplus@latest")),
        ("hakrawler", lambda: install_go_tool("hakrawler", "github.com/hakluke/hakrawler@latest")),
        ("assetfinder", lambda: install_go_tool("assetfinder", "github.com/tomnomnom/assetfinder@latest")),
    ]

    install_tools_parallel(tools)

    install_tool("jq", lambda: install_package("jq", package_manager))
    install_tool("shodan", lambda: run_command(["pip3", "install", "shodan"]))
    install_tool("paramspider", lambda: run_command(["git", "clone", "https://github.com/devanshbatham/ParamSpider", "&&", "cd", "ParamSpider", "&&", "python3", "setup.py", "install"]))

    handle_input()

if __name__ == "__main__":
    main()
