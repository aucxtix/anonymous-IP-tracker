## Anonymous OSINT Framework v5.0

A terminal-based OSINT and reconnaissance framework built with Python.  
This tool gathers public intelligence about an IP address using multiple threat intelligence sources while routing traffic through the Tor network for operational privacy.

> Educational and defensive security purposes only.

---
 
# Features

- Tor-based anonymous requests (SOCKS5)
- IP geolocation intelligence
- ISP and ASN lookup
- Proxy/VPN and hosting detection
- AbuseIPDB threat scoring
- Shodan reconnaissance integration 
- Rich terminal dashboard UI
- Open ports and CVE visibility
- Clean modular architecture

---

# Preview

```bash
TARGET INTEL DASHBOARD: 8.8.8.8

Network & Routing
-------------------------
ISP / Org       Google LLC
ASN             AS15169
Location        California, USA
Proxy/VPN       Clean
Datacenter      Yes

Threat Intelligence
-------------------------
Abuse Score     0%
Reports         0

Open Ports & Services
-------------------------
Operating System: Linux
Open Ports: 53, 443
```

---

# Requirements

Install Python dependencies:

```bash
pip install requests rich pysocks
```

---

# Tor Setup

This framework requires a running Tor SOCKS5 proxy.

# Linux Setup

Install Tor:

```bash
sudo apt install tor
sudo systemctl start tor
```

Verify SOCKS5 Proxy:

```bash
127.0.0.1:9050
```

---

# Windows Setup

## Step 1 — Download Tor Browser

Download from:

https://www.torproject.org/download/

Install and launch Tor Browser once.

---

## Step 2 — Keep Tor Browser Running

Your script uses:

```bash
127.0.0.1:9050
```

Tor Browser automatically opens this SOCKS5 proxy port.

Do NOT close Tor Browser while running the script.

---

## Step 3 — Install Python Dependencies

Open CMD or PowerShell:

```bash
pip install requests rich pysocks
```

---

## Step 4 — Run the Script

```bash
python main.py
```

---

# API Keys

Some advanced features require free API keys.

## AbuseIPDB

Get key from:
https://www.abuseipdb.com

## Shodan

Get key from:
https://account.shodan.io

Add keys inside the script:

```python
ABUSE_IPDB_KEY = "YOUR_KEY"
SHODAN_API_KEY = "YOUR_KEY"
```

---

# Usage

Run the script:

```bash
python main.py
```

Example:

```bash
Enter Target IP: 1.1.1.1
```

Exit:

```bash
exit
```

---

# Project Structure

```bash
.
├── main.py
├── README.md
└── requirements.txt
```

---

# Create requirements.txt

```txt
requests
rich
pysocks
```

---

# Security Notice

This tool is intended strictly for:

- Cybersecurity learning
- Defensive reconnaissance
- Threat intelligence research
- Authorized security testing

Do NOT use this framework against systems without permission

---

# Future Improvements

- Domain intelligence support
- WHOIS integration
- DNS enumeration
- CVE severity scoring
- Multi-threaded scanning
- Export reports as JSON/PDF
- Dark web breach lookup integration

---

# Author

Developed for cybersecurity learning and OSINT research. @aucxtix