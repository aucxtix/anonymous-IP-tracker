 
import os
import requests
import ipaddress
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout

# --- API KEYS (Optional but Highly Recommended for Deep Recon) ---
# Get free keys from https://www.abuseipdb.com/ and https://account.shodan.io/
ABUSE_IPDB_KEY = "" 
SHODAN_API_KEY = ""

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_tor_session():
    """Routes all traffic through the local Tor SOCKS5 proxy to hide identity."""
    session = requests.Session()
    session.proxies = {
        'http':  'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

def check_opsec(session):
    """Verifies that traffic is successfully routing through Tor."""
    try:
        # Check our IP as seen by the internet
        resp = session.get("https://api.ipify.org?format=json", timeout=10).json()
        tor_ip = resp.get('ip')
        
        # Check our actual local IP for comparison
        real_ip = requests.get("https://api.ipify.org?format=json", timeout=5).json().get('ip')
        
        if tor_ip == real_ip:
            console.print("[bold red][!] OPSEC FAILURE:[/bold red] Tor is not masking your IP. Exiting to protect identity.")
            exit()
        return tor_ip
    except requests.exceptions.RequestException:
        console.print("[bold red][!] Tor Proxy Error:[/bold red] Ensure the 'tor' service is running (sudo systemctl start tor).")
        exit()

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_core_intel(session, ip_address):
    """Fetches core OSINT data from IP-API."""
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query"
    try:
        return session.get(url, timeout=10).json()
    except Exception:
        return None

def get_threat_intel(session, ip_address):
    """Fetches threat scores from AbuseIPDB."""
    if not ABUSE_IPDB_KEY:
        return {"error": "API Key Missing"}
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSE_IPDB_KEY
    }
    params = {'ipAddress': ip_address, 'maxAgeInDays': 90}
    try:
        resp = session.get(url, headers=headers, params=params, timeout=10)
        return resp.json().get('data', {})
    except Exception:
        return {"error": "Connection Failed"}

def get_shodan_recon(session, ip_address):
    """Fetches open ports and vulnerabilities from Shodan."""
    if not SHODAN_API_KEY:
        return {"error": "API Key Missing"}
    
    url = f"https://api.shodan.io/shodan/host/{ip_address}?key={SHODAN_API_KEY}"
    try:
        resp = session.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return {"error": "No data found or rate limited"}
    except Exception:
        return {"error": "Connection Failed"}

def display_dashboard(target, core_data, threat_data, shodan_data):
    """Renders a clean, data-dense terminal dashboard."""
    if core_data.get('status') != 'success':
        console.print(f"[bold red]Core Intel Failed:[/bold red] {core_data.get('message')}")
        return

    console.print(f"\n[bold white on blue] TARGET INTEL DASHBOARD: {target} [/bold white on blue]\n")

    # Table 1: Core & Network
    net_table = Table(title="[bold cyan]Network & Routing[/bold cyan]", box=None)
    net_table.add_column("Attribute", style="cyan")
    net_table.add_column("Value", style="white")
    net_table.add_row("ISP / Org", str(core_data.get('isp')))
    net_table.add_row("ASN", str(core_data.get('as')))
    net_table.add_row("Location", f"{core_data.get('city')}, {core_data.get('regionName')}, {core_data.get('country')}")
    net_table.add_row("Proxy/VPN", "[bold red]Detected[/bold red]" if core_data.get('proxy') else "[green]Clean[/green]")
    net_table.add_row("Datacenter", "[bold yellow]Yes[/bold yellow]" if core_data.get('hosting') else "[green]No[/green]")

    # Table 2: Threat Intelligence
    threat_table = Table(title="[bold red]Threat Intelligence (AbuseIPDB)[/bold red]", box=None)
    threat_table.add_column("Metric", style="red")
    threat_table.add_column("Status", style="white")
    
    if "error" in threat_data:
        threat_table.add_row("Status", f"[dim]{threat_data['error']} (Add Key)[/dim]")
    else:
        score = threat_data.get('abuseConfidenceScore', 0)
        color = "green" if score == 0 else "yellow" if score < 50 else "red"
        threat_table.add_row("Abuse Score", f"[bold {color}]{score}%[/bold {color}]")
        threat_table.add_row("Total Reports", str(threat_data.get('totalReports', 0)))
        threat_table.add_row("Last Reported", str(threat_data.get('lastReportedAt', 'Never')))

    # Table 3: Shodan Recon
    shodan_table = Table(title="[bold magenta]Open Ports & Services (Shodan)[/bold magenta]", box=None)
    shodan_table.add_column("Data", style="magenta")
    
    if "error" in shodan_data:
        shodan_table.add_row(f"[dim]{shodan_data['error']} (Add Key)[/dim]")
    else:
        ports = shodan_data.get('ports', [])
        os_match = shodan_data.get('os', 'Unknown')
        vulns = shodan_data.get('vulns', [])
        
        shodan_table.add_row(f"[cyan]Operating System:[/cyan] {os_match}")
        shodan_table.add_row(f"[cyan]Open Ports:[/cyan] {', '.join(map(str, ports)) if ports else 'None detected'}")
        if vulns:
            shodan_table.add_row(f"[red]CVEs Detected:[/red] {', '.join(vulns[:5])}{'...' if len(vulns)>5 else ''}")

    # Render layout
    console.print(net_table)
    console.print("-" * 50)
    console.print(threat_table)
    console.print("-" * 50)
    console.print(shodan_table)
    console.print("=" * 50)

def main():
    clear_screen()
    console.print(Panel("[bold green]v5.0 CyberSec Edition[/bold green]\n[dim]Routing engine: Tor (SOCKS5)[/dim]", title="[bold yellow]Anonymous OSINT Framework[/bold yellow]"))
    
    console.print("[yellow]Establishing secure Tor circuit...[/yellow]")
    session = get_tor_session()
    tor_ip = check_opsec(session)
    console.print(f"[bold green][✓] OPSEC Secured.[/bold green] You are appearing as IP: [bold cyan]{tor_ip}[/bold cyan]\n")

    while True:
        try:
            target = console.input("[bold cyan]Enter Target IP: [/bold cyan]").strip()
            if target.lower() in ['exit', 'quit']:
                break
            if not is_valid_ip(target):
                console.print("[bold red]Invalid IP format.[/bold red]\n")
                continue

            console.print("[dim]Gathering Core Intel...[/dim]")
            core_data = get_core_intel(session, target)
            
            console.print("[dim]Querying Threat Databases...[/dim]")
            threat_data = get_threat_intel(session, target)
            
            console.print("[dim]Scanning Shodan Footprints...[/dim]")
            shodan_data = get_shodan_recon(session, target)
            
            if core_data:
                display_dashboard(target, core_data, threat_data, shodan_data)
                
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Exiting...[/bold yellow]")
            break

if __name__ == "__main__":
    main()