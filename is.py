import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from itertools import cycle

BASE_URL = "https://www.isnic.is/en/whois/search?query={domain}"

INPUT_FILE = "domains_to_check.txt"
CHECKED_FILE = "checked_domains.txt"
AVAILABLE_FILE = "available_domains.txt"
PROXY_FILE = "proxies.txt"

THREADS = 10

def load_domains_to_check():
    if not os.path.exists(INPUT_FILE):
        print(f"[ERROR] Input file {INPUT_FILE} not found!")
        exit(1)
    with open(INPUT_FILE, "r") as file:
        return set(line.strip() for line in file if line.strip())

def load_checked_domains():
    if not os.path.exists(CHECKED_FILE):
        return set()
    with open(CHECKED_FILE, "r") as file:
        return set(line.strip() for line in file)

def save_checked_domain(domain):
    with open(CHECKED_FILE, "a") as file:
        file.write(domain + "\n")

def save_available_domain(domain):
    with open(AVAILABLE_FILE, "a") as file:
        file.write(domain.lower() + ".is\n")

def load_proxies():
    if not os.path.exists(PROXY_FILE):
        return []
    proxies = []
    with open(PROXY_FILE, "r") as file:
        for line in file:
            line = line.strip()
            if line:
                parts = line.split(":")
                if len(parts) == 4:
                    ip, port, username, password = parts
                    proxy = f"http://{username}:{password}@{ip}:{port}"
                    proxies.append(proxy)
                else:
                    print(f"[ERROR] Invalid proxy format: {line}")
    return proxies

def get_proxy(proxy_cycle):
    try:
        return next(proxy_cycle)
    except StopIteration:
        raise RuntimeError("No proxies left to use.")

def check_domain(domain, proxy=None):
    url = BASE_URL.format(domain=domain)
    try:
        proxy_dict = {"http": proxy, "https": proxy} if proxy else None
        response = requests.get(url, timeout=10, proxies=proxy_dict)
        if "Verify code" in response.text:
            print(f"[CAPTCHA DETECTED] Proxy: {proxy or 'None'} Switching to proxy...")
            raise ValueError("CAPTCHA Detected")
        if "available" in response.text:
            print(f"[AVAILABLE] {domain}")
            save_available_domain(domain)
        return domain
    except ValueError:
        raise
    except Exception as e:
        print(f"[ERROR] {domain} with proxy {proxy or 'None'}: {e}")
    return None

def main():
    all_domains = load_domains_to_check()
    checked_domains = load_checked_domains()
    domains_to_check = [d for d in all_domains if d not in checked_domains]

    if not domains_to_check:
        print("[INFO] No new domains to check.")
        return

    proxies = load_proxies()
    proxy_cycle = cycle(proxies) if proxies else None

    print(f"[INFO] Checking {len(domains_to_check)} domains...")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        use_proxies = False
        while domains_to_check:
            futures = {executor.submit(check_domain, domain, get_proxy(proxy_cycle) if use_proxies else None): domain for domain in domains_to_check}
            domains_to_check = []

            for future in as_completed(futures):
                domain = futures[future]
                try:
                    result = future.result()
                    if result:
                        save_checked_domain(result)
                except ValueError:
                    if proxy_cycle:
                        print(f"[INFO] Switching to proxy mode for domain {domain}...")
                        use_proxies = True
                        domains_to_check.append(domain)
                    else:
                        print("[ERROR] CAPTCHA detected, but no proxies available. Exiting...")
                        return
                except Exception as e:
                    print(f"[ERROR] Failed to process {domain}: {e}")

if __name__ == "__main__":
    main()
