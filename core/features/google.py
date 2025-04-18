from googlesearch import search

def search_google(dorks: str, page) -> str:
    for url in search(dorks, num_results=int(page)):
        return url
