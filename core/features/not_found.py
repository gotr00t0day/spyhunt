import requests
requests.packages.urllib3.disable_warnings()

from multiprocessing.pool import ThreadPool
import multiprocessing
from core.utils import header

def check_status(domain, session):
    try:
        r = session.get(domain, verify=False, headers=header, timeout=10)
        if r.status_code == 404:
            return domain
    except requests.exceptions.RequestException:
        pass

def get_results(links, output_file, session):
    pool = ThreadPool(processes=multiprocessing.cpu_count())
    results = pool.imap_unordered(check_status, links, session)
    with open(output_file, "w") as f:
        for result in results:
            if result:
                f.write(f"{result}\n")
                print(result)
    pool.close()
    pool.join()
