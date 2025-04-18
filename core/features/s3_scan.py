from colorama import Fore, Style
from alive_progress import alive_bar
from modules.ss3sec import S3Scanner

async def handle_s3_scan(target):
    print(f"\n{Fore.MAGENTA}Starting S3 bucket scan for {Fore.CYAN}{target}{Style.RESET_ALL}")
    scanner = S3Scanner()
    with alive_bar(1, title='Scanning S3 buckets') as bar:
        results = await scanner.scan(target)
        scanner.save_results(target)
        bar()
    return results
