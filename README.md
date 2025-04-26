🕵️ Ultimate OSINT Toolkit
The Ultimate OSINT Toolkit is a powerful reconnaissance and information gathering tool designed for cybersecurity professionals, researchers, and ethical hackers.
It combines multiple OSINT (Open Source Intelligence) techniques into a single, easy-to-use Python tool.

✨ Features
Email Breach Check — Search for emails in known data breaches (via Dehashed API).

Password Breach Check — Verify if passwords have been exposed (using HaveIBeenPwned API).

IP Geolocation Lookup — Get geolocation info from IP addresses.

Username Search — Check for a username across major platforms (Twitter, Reddit, Instagram, GitHub, LinkedIn, etc.).

Domain Scan — Scan a domain for malicious activity (using VirusTotal API).

Fake Account Checker — Analyze Instagram and Twitter profiles for signs of being fake accounts.

Server-level Port Scanning — Perform basic port scans using Nmap.

Colorful, easy-to-read terminal output.

📦 Requirements
Python 3.8+

Install required Python packages:

bash
Copy
Edit
pip install requests beautifulsoup4 python-whois python-nmap
External Dependencies:

nmap must be installed on your system for port scanning:

Ubuntu/Debian: sudo apt install nmap

MacOS: brew install nmap

Windows: Download and install from https://nmap.org/

🔧 Setup
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/ultimate-osint-toolkit.git
cd ultimate-osint-toolkit
Set your API keys inside the script:

Dehashed API Key

VirusTotal API Key

Run the script:

bash
Copy
Edit
python3 main.py
⚠️ Important Notes
API Keys are required for Dehashed and VirusTotal functionality.

Use responsibly — this tool is intended for legal, ethical OSINT and cybersecurity testing.

Disclaimer:

This tool is provided "as is," without warranty of any kind.
The developers are not responsible for any misuse or illegal activities performed with this tool.

📜 License
This project is licensed under the MIT License.

