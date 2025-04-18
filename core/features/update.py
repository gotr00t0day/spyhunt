from colorama import Fore, Style
from datetime import datetime
import subprocess
import os
import shutil

async def update_script():
    try:
        # Store current version
        current_version = "1.0.0"  # Replace with your version tracking system
        backup_dir = "backups"
        
        print(f"{Fore.CYAN}Checking for updates...{Style.RESET_ALL}")
        
        # Create backups directory if it doesn't exist
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        # Create backup of current version
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"spyhunt_backup_{timestamp}")
        
        print(f"{Fore.YELLOW}Creating backup...{Style.RESET_ALL}")
        try:
            shutil.copytree(".", backup_path, ignore=shutil.ignore_patterns(
                '.git*', '__pycache__', 'backups', '*.pyc'
            ))
            print(f"{Fore.GREEN}Backup created at: {backup_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Backup failed: {str(e)}{Style.RESET_ALL}")
            return False

        # Check remote repository for updates
        print(f"{Fore.CYAN}Checking remote repository...{Style.RESET_ALL}")
        try:
            # Fetch without merging
            subprocess.run(["git", "fetch"], check=True, capture_output=True)
            
            # Get current and remote commit hashes
            current = subprocess.run(["git", "rev-parse", "HEAD"], 
                                   check=True, capture_output=True, text=True).stdout.strip()
            remote = subprocess.run(["git", "rev-parse", "@{u}"], 
                                  check=True, capture_output=True, text=True).stdout.strip()
            
            if current == remote:
                print(f"{Fore.GREEN}SpyHunt is already up to date!{Style.RESET_ALL}")
                return True
                
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Failed to check for updates: {str(e)}{Style.RESET_ALL}")
            return False

        # Perform update
        print(f"{Fore.CYAN}Updating SpyHunt...{Style.RESET_ALL}")
        try:
            # Pull changes
            result = subprocess.run(["git", "pull"], check=True, capture_output=True, text=True)
            
            if "Already up to date" in result.stdout:
                print(f"{Fore.GREEN}SpyHunt is already up to date!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}Update successful!{Style.RESET_ALL}")
                
                # Check for dependency updates
                requirements_path = "requirements.txt"
                if os.path.exists(requirements_path):
                    print(f"{Fore.CYAN}Updating dependencies...{Style.RESET_ALL}")
                    subprocess.run(["pip", "install", "-r", requirements_path, "--upgrade"], 
                                 check=True)
                    print(f"{Fore.GREEN}Dependencies updated!{Style.RESET_ALL}")
                
                print(f"\n{Fore.GREEN}SpyHunt has been updated successfully!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Please restart SpyHunt to apply the updates.{Style.RESET_ALL}")
            
            return True

        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Update failed: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Restoring from backup...{Style.RESET_ALL}")
            
            # Restore from backup
            try:
                shutil.rmtree(".", ignore_errors=True)
                shutil.copytree(backup_path, ".", dirs_exist_ok=True)
                print(f"{Fore.GREEN}Restore successful!{Style.RESET_ALL}")
            except Exception as restore_error:
                print(f"{Fore.RED}Restore failed: {str(restore_error)}{Style.RESET_ALL}")
                print(f"{Fore.RED}Please restore manually from: {backup_path}{Style.RESET_ALL}")
            
            return False

    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {str(e)}{Style.RESET_ALL}")
        return False
