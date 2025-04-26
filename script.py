import hashlib
import json
import requests
from urllib.request import urlopen, Request
from bs4 import BeautifulSoup
import os
import subprocess
import socket
import nmap
import whois

# --------- Custom Colors for Terminal Output ---------
BLOOD_RED = "\033[91m"
BLOOD_GREEN = "\033[92m"
BLOOD_YELLOW = "\033[93m"
RESET = "\033[0m"  # Reset color to default

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

# --------- Function to Check Password Breach using Pwned Passwords API ---------
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
                print(f"{BLOOD_GREEN}[✓] Geolocation for IP {ip_address}: {RESET}")
                print(f"  Country: {data['country']}")
                print(f"  Region: {data['region']}")
                print(f"  City: {data['city']}")
                print(f"  Latitude: {data['loc'].split(',')[0]}, Longitude: {data['loc'].split(',')[1]}")
                return data
            else:
                print(f"{BLOOD_RED}[!] Error fetching geolocation for {ip_address}{RESET}")
                return None
    except Exception as e:
        print(f"{BLOOD_RED}[!] Error with IP Geolocation request: {e}{RESET}")
        return None

# --------- Username Search (Checking multiple platforms) ---------
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
                else:
                    print(f"{BLOOD_RED}[✖] '{username}' not found on {platform}.{RESET}")
        except Exception as e:
            print(f"{BLOOD_RED}[!] Error while checking {platform} for username {username}: {e}{RESET}")

# --------- Domain Scan using VirusTotal ---------
def scan_domain(domain):
    headers = {"x-apikey": "YOUR_VIRUSTOTAL_API_KEY"}
    
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            domain_info = data.get('data', {})
            if domain_info:
                domain_status = domain_info.get('attributes', {}).get('last_analysis_stats', {})
                print(f"{BLOOD_GREEN}[✓] Domain Scan Results for '{domain}':{RESET}")
                print(f"- Harmless: {domain_status.get('harmless', 0)}")
                print(f"- Malicious: {domain_status.get('malicious', 0)}")
                if domain_status.get('malicious', 0) > 0:
                    print(f"{BLOOD_RED}[!] Warning: This domain has malicious activity!{RESET}")
                else:
                    print(f"{BLOOD_GREEN}[✓] This domain is safe!{RESET}")
        else:
            print(f"{BLOOD_RED}[!] Error accessing VirusTotal API: {response.status_code}{RESET}")
    except Exception as e:
        print(f"{BLOOD_RED}[!] Error with the domain scan: {e}{RESET}")

# --------- Fake Account Check for Social Media ---------
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
                    print(f"{BLOOD_RED}[!] Missing bio. This may indicate a fake account.{RESET}")
                if not user_data.get('profile_pic_url_hd'):
                    print(f"{BLOOD_RED}[!] Missing profile image. This may indicate a fake account.{RESET}")
                if user_data['edge_followed_by']['count'] < 10:
                    print(f"{BLOOD_RED}[!] Low follower count. This may indicate a fake account.{RESET}")
            elif platform == "Twitter":
                soup = BeautifulSoup(response.text, 'html.parser')
                bio = soup.find('div', {'class': 'ProfileHeaderCard-bio'})
                if not bio:
                    print(f"{BLOOD_RED}[!] Missing bio. This may indicate a fake account.{RESET}")
                profile_image = soup.find('img', {'class': 'ProfileAvatar-image'})['src']
                if not profile_image:
                    print(f"{BLOOD_RED}[!] Missing profile image. This may indicate a fake account.{RESET}")
        else:
            print(f"{BLOOD_RED}[!] Error fetching data from {platform} for {username}: {response.status_code}{RESET}")
    except Exception as e:
        print(f"{BLOOD_RED}[!] Error checking fake account: {e}{RESET}")

# --------- Server-level Scanning (Port Scan, etc.) ---------
def server_scan(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')  # Scan ports 1-1024
    
    print(f"{BLOOD_GREEN}[✓] Scanning {ip} for open ports:{RESET}")
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"  Protocol: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"    Port: {port} -> State: {nm[host][proto][port]['state']}")

# --------- Main Menu ---------
def main_menu():
    while True:
        print(f"{BLOOD_GREEN}Welcome to the Ultimate OSINT Toolkit!{RESET}")
        print(f"{BLOOD_RED}1. Check Email Breach{RESET}")
        print(f"{BLOOD_RED}2. Check Password Breach{RESET}")
        print(f"{BLOOD_RED}3. Get IP Geolocation{RESET}")
        print(f"{BLOOD_RED}4. Username Search (Across Platforms){RESET}")
        print(f"{BLOOD_RED}5. Scan Domain using VirusTotal{RESET}")
        print(f"{BLOOD_RED}6. Fake Account Check{RESET}")
        print(f"{BLOOD_RED}7. Server-level Scan{RESET}")
        print(f"{BLOOD_RED}8. Exit{RESET}")
        
        choice = input(f"{BLOOD_YELLOW}Enter your choice (1-8): {RESET}")
        
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
            platform = input("Enter Platform (Instagram/Twitter): ")
            username = input("Enter Username: ")
            check_fake_account(username, platform)
        elif choice == "7":
            ip = input("Enter IP Address: ")
            server_scan(ip)
        elif choice == "8":
            break
        else:
            print(f"{BLOOD_RED}[!] Invalid choice. Please try again.{RESET}")

if __name__ == "__main__":
    main_menu()
