import hashlib
import json
import requests
from urllib.request import urlopen, Request
from bs4 import BeautifulSoup
import nmap
import whois

# --------- Custom Colors for Terminal Output ---------
BLOOD_RED = "\033[91m"
BLOOD_GREEN = "\033[92m"
BLOOD_YELLOW = "\033[93m"
RESET = "\033[0m"

# --------- Simple Banner ---------
def banner():
    print(f"{BLOOD_GREEN}Welcome to S2 OSINT Toolkit v2{RESET}\n")

# --------- Function to Check Email Breach using Dehashed ---------
def check_email_breach(email):
    api_url = f"https://api.dehashed.com/search?query={email}"
    headers = {"Authorization": "YOUR_DEHASHED_API_KEY"}

    try:
        req = Request(api_url, headers=headers)
        with urlopen(req) as response:
            if response.status == 200:
                breaches = json.load(response)
                if breaches:
                    print(f"{BLOOD_RED}[!] This email has been found in breaches!{RESET}")
                    for breach in breaches:
                        print(f"- {BLOOD_RED}{breach['name']}{RESET}")
                else:
                    print(f"{BLOOD_GREEN}[✓] No breaches found for this email.{RESET}")
                return True
            else:
                print(f"{BLOOD_RED}[!] Error accessing Dehashed API: {response.status}{RESET}")
                return False
    except Exception as e:
        print(f"{BLOOD_RED}[!] Error with request: {e}{RESET}")
        return False

# --------- Function to Check Password Breach using Pwned Passwords ---------
def check_password_breach(password):
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    hash_prefix = sha1_hash[:5]
    hash_suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"

    try:
        with urlopen(url) as response:
            if response.status == 200:
                hashes = response.read().decode('utf-8').splitlines()
                for h in hashes:
                    suffix, count = h.split(':')
                    if suffix == hash_suffix:
                        print(f"{BLOOD_RED}[!] This password has been found {count} times in known breaches!{RESET}")
                        return True
                print(f"{BLOOD_GREEN}[✓] This password has not been found in known breaches.{RESET}")
                return False
            else:
                print(f"{BLOOD_RED}[!] Error accessing Pwned Passwords API.{RESET}")
                return False
    except Exception as e:
        print(f"{BLOOD_RED}[!] Error checking Pwned Passwords API: {e}{RESET}")
        return False

# --------- IP Geolocation ---------
def get_ip_geolocation(ip_address):
    url = f"https://ipinfo.io/{ip_address}/json"
    
    try:
        with urlopen(url) as response:
            if response.status == 200:
                data = json.load(response)
                print(f"{BLOOD_GREEN}[✓] Geolocation for IP {ip_address}:{RESET}")
                print(f"  Country: {data.get('country', 'N/A')}")
                print(f"  Region: {data.get('region', 'N/A')}")
                print(f"  City: {data.get('city', 'N/A')}")
                loc = data.get('loc', '0,0').split(',')
                print(f"  Latitude: {loc[0]}, Longitude: {loc[1]}")
                return data
            else:
                print(f"{BLOOD_RED}[!] Error fetching geolocation for {ip_address}{RESET}")
                return None
    except Exception as e:
        print(f"{BLOOD_RED}[!] Error with IP Geolocation request: {e}{RESET}")
        return None

# --------- Username Search ---------
def search_username(username):
    platforms = {
        "Twitter": f"https://twitter.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}/about.json",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Facebook": f"https://www.facebook.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}/",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "YouTube": f"https://www.youtube.com/{username}"
    }

    for platform, url in platforms.items():
        try:
            with urlopen(url) as response:
                if response.status == 200:
                    print(f"{BLOOD_GREEN}[✓] Found '{username}' on {platform}.{RESET}")
        except Exception:
            print(f"{BLOOD_RED}[✖] '{username}' not found on {platform}.{RESET}")

# --------- VirusTotal Domain Scan ---------
def scan_domain(domain):
    headers = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY"}
    
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            domain_info = data.get('data', {})
            if domain_info:
                stats = domain_info.get('attributes', {}).get('last_analysis_stats', {})
                print(f"{BLOOD_GREEN}[✓] Domain Scan Results for '{domain}':{RESET}")
                print(f"- Harmless: {stats.get('harmless', 0)}")
                print(f"- Malicious: {stats.get('malicious', 0)}")
                if stats.get('malicious', 0) > 0:
                    print(f"{BLOOD_RED}[!] Warning: Malicious activity detected!{RESET}")
                else:
                    print(f"{BLOOD_GREEN}[✓] Domain appears safe.{RESET}")
        else:
            print(f"{BLOOD_RED}[!] Error accessing VirusTotal API: {response.status_code}{RESET}")
    except Exception as e:
        print(f"{BLOOD_RED}[!] Error scanning domain: {e}{RESET}")

# --------- WHOIS Lookup ---------
def whois_lookup(domain):
    try:
        info = whois.whois(domain)
        print(f"{BLOOD_GREEN}[✓] WHOIS Info for '{domain}':{RESET}")
        print(info)
    except Exception as e:
        print(f"{BLOOD_RED}[!] WHOIS lookup error: {e}{RESET}")

# --------- Fake Account Check ---------
def check_fake_account(username, platform):
    urls = {
        "Instagram": f"https://www.instagram.com/{username}/?__a=1",
        "Twitter": f"https://twitter.com/{username}"
    }

    url = urls.get(platform)
    if not url:
        print(f"{BLOOD_RED}[!] Platform not supported.{RESET}")
        return

    try:
        response = requests.get(url)
        if response.status_code == 200:
            if platform == "Instagram":
                data = response.json()
                user_data = data['graphql']['user']
                if not user_data.get('biography'):
                    print(f"{BLOOD_RED}[!] Missing bio - possible fake account.{RESET}")
                if not user_data.get('profile_pic_url_hd'):
                    print(f"{BLOOD_RED}[!] Missing profile picture - possible fake account.{RESET}")
                if user_data['edge_followed_by']['count'] < 10:
                    print(f"{BLOOD_RED}[!] Very low followers - possible fake account.{RESET}")
            elif platform == "Twitter":
                soup = BeautifulSoup(response.text, 'html.parser')
                bio = soup.find('div', {'class': 'ProfileHeaderCard-bio'})
                if not bio:
                    print(f"{BLOOD_RED}[!] Missing bio on Twitter profile.{RESET}")
        else:
            print(f"{BLOOD_RED}[!] Error fetching {platform} profile: {response.status_code}{RESET}")
    except Exception as e:
        print(f"{BLOOD_RED}[!] Fake account check error: {e}{RESET}")

# --------- Server-level Scan (Port Scanning) ---------
def server_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')

    print(f"{BLOOD_GREEN}[✓] Open ports on {ip}:{RESET}")
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"  Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"    Port: {port} -> {nm[host][proto][port]['state']}")

# --------- Main Menu ---------
def main_menu():
    banner()
    while True:
        print(f"{BLOOD_GREEN}Main Menu{RESET}")
        print(f"{BLOOD_RED}1.{RESET} Check Email Breach")
        print(f"{BLOOD_RED}2.{RESET} Check Password Breach")
        print(f"{BLOOD_RED}3.{RESET} Get IP Geolocation")
        print(f"{BLOOD_RED}4.{RESET} Username Search")
        print(f"{BLOOD_RED}5.{RESET} Scan Domain (VirusTotal)")
        print(f"{BLOOD_RED}6.{RESET} WHOIS Lookup")
        print(f"{BLOOD_RED}7.{RESET} Fake Account Check")
        print(f"{BLOOD_RED}8.{RESET} Server Scan (Nmap)")
        print(f"{BLOOD_RED}9.{RESET} Exit")

        choice = input(f"{BLOOD_YELLOW}Enter your choice (1-9): {RESET}")
        
        if choice == "1":
            email = input("Enter Email: ")
            check_email_breach(email)
        elif choice == "2":
            password = input("Enter Password: ")
            check_password_breach(password)
        elif choice == "3":
            ip = input("Enter IP Address: ")
            get_ip_geolocation(ip)
        elif choice == "4":
            username = input("Enter Username: ")
            search_username(username)
        elif choice == "5":
            domain = input("Enter Domain: ")
            scan_domain(domain)
        elif choice == "6":
            domain = input("Enter Domain for WHOIS Lookup: ")
            whois_lookup(domain)
        elif choice == "7":
            platform = input("Enter Platform (Instagram/Twitter): ")
            username = input("Enter Username: ")
            check_fake_account(username, platform)
        elif choice == "8":
            ip = input("Enter IP Address for server scan: ")
            server_scan(ip)
        elif choice == "9":
            print(f"{BLOOD_GREEN}Goodbye!{RESET}")
            break
        else:
            print(f"{BLOOD_RED}[!] Invalid choice. Try again.{RESET}")

if __name__ == "__main__":
    main_menu()

