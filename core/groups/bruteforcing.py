from colorama import Fore, Style
from core.features.brute_user_pass import bruteforce_login

def run(args):

    # Update the argument handling
    if args.brute_user_pass:
        if not args.username_wordlist:
            print(f"{Fore.RED}[!] Error: Username wordlist is required. Use --username-wordlist to specify the file{Style.RESET_ALL}")
        elif not args.password_wordlist:
            print(f"{Fore.RED}[!] Error: Password wordlist is required. Use --password-wordlist to specify the file{Style.RESET_ALL}")
        else:
            bruteforce_login(args.brute_user_pass, args.username_wordlist, 
                            args.password_wordlist, proxy_file=args.proxy_file, verbose=args.verbose)
