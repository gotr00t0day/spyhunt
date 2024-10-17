import platform
import subprocess
import os
from shutil import which

def run_command(cmd):
    try:
        print(f"Running command: {cmd}")  # Removed colorama formatting
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"Command output: {output.strip()}")  # Removed colorama formatting
        return output
    except subprocess.CalledProcessError as e:
        print(f"Failed to run command: {cmd}")
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
        print(f"Installing {name}...")  # Removed colorama formatting
        result = install_cmd()
        if result is not None:
            print(f"{name} installed successfully")  # Removed colorama formatting
        else:
            print(f"Failed to install {name}")  # Removed colorama formatting
    else:
        print(f"Found {name}")  # Removed colorama formatting

def install_go_tool(tool, package):
    print(f"Installing {tool}...")  # Removed colorama formatting
    if run_command(f"go install {package}") is not None:
        go_path = run_command("go env GOPATH").strip()
        bin_path = os.path.join(go_path, "bin", tool)
        if os.path.exists(bin_path):
            run_command(f"sudo mv {bin_path} /usr/local/bin/")
            print(f"{tool} installed successfully")  # Removed colorama formatting
        else:
            print(f"Failed to find {tool} in GOPATH")  # Removed colorama formatting
    else:
        print(f"Failed to install {tool}")  # Removed colorama formatting

def check_wsl():
    if platform.system() == "Linux":
        with open('/proc/version', 'r') as f:
            return 'microsoft' in f.read().lower()
    return False

def update_upgrade_system(package_manager):
    print(f"Updating and upgrading the system...")  # Removed colorama formatting
    if package_manager == "apt":
        run_command("sudo apt update && sudo apt upgrade -y")
    elif package_manager in ["dnf", "yum"]:
        run_command(f"sudo {package_manager} update -y")
    elif package_manager == "pacman":
        run_command("sudo pacman -Syu --noconfirm")
    elif package_manager == "zypper":
        run_command("sudo zypper update -y")
    elif package_manager == "apk":
        run_command("sudo apk update && sudo apk upgrade")
    print(f"System updated and upgraded successfully")  # Removed colorama formatting

def ensure_pip_installed(package_manager):
    if not which("pip3") and not which("pip"):
        print(f"pip is not installed. Installing pip...")  # Removed colorama formatting
        if platform.system() == "Linux":
            if package_manager == "apt":
                run_command("sudo apt install -y python3-pip")
            elif package_manager in ["dnf", "yum"]:
                run_command(f"sudo {package_manager} install -y python3-pip")
            elif package_manager == "pacman":
                run_command("sudo pacman -S --noconfirm python-pip")
            elif package_manager == "zypper":
                run_command("sudo zypper install -y python3-pip")
            elif package_manager == "apk":
                run_command("sudo apk add py3-pip")
        elif platform.system() == "Darwin":
            run_command("brew install python")  # This will install pip as well
        print(f"pip installed successfully")  # Removed colorama formatting
    else:
        print(f"pip is already installed")  # Removed colorama formatting

def main():
    system = platform.system()
    is_wsl = check_wsl()

    if is_wsl:
        print(f"Detected Windows Subsystem for Linux (WSL)")  # Removed colorama formatting

    if system == "Linux":
        package_manager = detect_package_manager()
        if package_manager is None:
            print(f"Unable to detect package manager. Please install packages manually.")  # Removed colorama formatting
            return
        print(f"Detected package manager: {package_manager}")  # Removed colorama formatting
        
        if is_wsl:
            update_upgrade_system(package_manager)
    elif system == "Darwin":  # macOS
        package_manager = "brew"
        if not which("brew"):
            print(f"Homebrew is required for macOS. Please install it first.")  # Removed colorama formatting
            return
    else:
        print(f"Unsupported operating system: {system}")  # Removed colorama formatting
        return

    ensure_pip_installed(package_manager)

    home = os.path.expanduser("~")
    
    # Install colorama
    # install_tool("colorama", lambda: install_package("colorama", "pip"))  # Removed colorama installation

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
        ("asnmap", "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
        ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
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