def save_forbidden_pages(url):
    with open(f"forbidden_pages.txt", "a") as f:
        f.write(f"{url}\n")