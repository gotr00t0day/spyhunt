import platform, os, time
from shutil import which, move
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init
from pathlib import Path
import requests
import git

init(autoreset=True)

def run_command_alternative(cmd):
    """An alternative for subprocess that prints instructions instead of executing shell commands."""
    print(f"{Fore.YELLOW}To run the command: {' '.join(cmd)} manually on your system.{Fore.RESET}")
    return None

def detect_package_manager():
    if Path("/data/data/com.termux/files/usr").exists():
        return "pkg"
    for pm in ["apt", "dnf", "yum", "pacman", "zypper", "apk", "brew", "choco"]:
        if which(pm):
            return pm
    return None

def install_package(package, manager):
    # Alternative: We provide the command to the user as output
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
    run_command_alternative(commands.get(manager))

def install_tool(name, install_cmd, check_cmd=None):
    check_cmd = check_cmd or name
    if which(check_cmd) is None:
        print(f"{Fore.YELLOW}Installing {name}...{Fore.RESET}")
        install_cmd()
    else:
        print(f"{Fore.GREEN}{name} is already installed{Fore.RESET}")

def download_and_extract(url, extract_to='.', strip_components=0):
    local_filename = url.split('/')[-1]
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    if tarfile.is_tarfile(local_filename):
        with tarfile.open(local_filename, 'r:*') as tar:
            members = tar.getmembers()
            if strip_components > 0:
                for member in members:
                    member.path = Path(*Path(member.path).parts[strip_components:])
            tar.extractall(path=extract_to, members=members)
    elif zipfile.is_zipfile(local_filename):
        with zipfile.ZipFile(local_filename, 'r') as zip_ref:
            zip_ref.extractall(extract_to)

    os.remove(local_filename)

def install_go_tool(tool, repo_url, retries=3, delay=5):
    for _ in range(retries):
        # Instead of using "go install", download the binary directly if available
        try:
            download_and_extract(f"https://github.com/{repo_url}/releases/latest/download/{tool}.tar.gz")
            bin_path = Path(f"./{tool}")
            if bin_path.exists():
                move(str(bin_path), os.getenv("PREFIX") + "/bin/")
                print(f"{Fore.GREEN}{tool} installed successfully{Fore.RESET}")
                return
        except Exception as e:
            print(f"{Fore.RED}Failed to install {tool}: {e}{Fore.RESET}")
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

def clone_repo(repo_url, target_dir=None):
    """Clone a git repository using GitPython"""
    try:
        git.Repo.clone_from(repo_url, target_dir or repo_url.split('/')[-1])
        print(f"{Fore.GREEN}Cloned {repo_url} successfully{Fore.RESET}")
    except git.exc.GitError as e:
        print(f"{Fore.RED}Git cloning failed: {e}{Fore.RESET}")

def main():
    system = platform.system()
    package_manager = detect_package_manager()

    if package_manager is None:
        print(f"{Fore.RED}No package manager found. Install packages manually.{Fore.RESET}")
        return

    print(f"{Fore.GREEN}Detected package manager: {package_manager}{Fore.RESET}")

    # Install colorama
    install_tool("colorama", lambda: run_command_alternative(["pip3", "install", "colorama"]))

    # Handle platform-specific installations
    go_install = lambda: install_package("golang", package_manager)
    node_install = lambda: install_package("nodejs", package_manager)
    npm_install = lambda: install_package("npm", package_manager)
    if package_manager == "pkg":
        go_install = lambda: run_command_alternative(["pkg", "install", "-y", "golang"])
        node_install = lambda: run_command_alternative(["pkg", "install", "-y", "nodejs"])
        npm_install = lambda: run_command_alternative(["pkg", "install", "-y", "npm"])

    install_tool("go", go_install)
    install_tool("node", node_install)
    install_tool("npm", npm_install)

    install_tool("blc", lambda: run_command_alternative(["npm", "install", "-g", "broken-link-checker"]))

    tools = [
        ("nuclei", lambda: install_go_tool("nuclei", "projectdiscovery/nuclei/v2/cmd/nuclei@latest")),
        ("dnsx", lambda: install_go_tool("dnsx", "projectdiscovery/dnsx/cmd/dnsx@latest")),
        ("subfinder", lambda: install_go_tool("subfinder", "projectdiscovery/subfinder/v2/cmd/subfinder@latest")),
        ("waybackurls", lambda: install_go_tool("waybackurls", "tomnomnom/waybackurls@latest")),
        ("httprobe", lambda: install_go_tool("httprobe", "tomnomnom/httprobe@latest")),
        ("httpx", lambda: install_go_tool("httpx", "projectdiscovery/httpx/cmd/httpx@latest")),
        ("anew", lambda: install_go_tool("anew", "tomnomnom/anew@latest")),
        ("gau", lambda: install_go_tool("gau", "lc/gau/v2/cmd/gau@latest")),
        ("gauplus", lambda: install_go_tool("gauplus", "bp0lr/gauplus@latest")),
        ("hakrawler", lambda: install_go_tool("hakrawler", "hakluke/hakrawler@latest")),
        ("assetfinder", lambda: install_go_tool("assetfinder", "tomnomnom/assetfinder@latest")),
    ]

    install_tools_parallel(tools)

    install_tool("jq", lambda: install_package("jq", package_manager))
    install_tool("shodan", lambda: run_command_alternative(["pip3", "install", "shodan"]))
    install_tool("paramspider", lambda: clone_repo("https://github.com/devanshbatham/ParamSpider"))

    handle_input()

if __name__ == "__main__":
    main()
