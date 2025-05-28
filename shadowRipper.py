import socket
import ssl
from ipwhois import IPWhois
from colorama import Fore, Style, init
import pyfiglet
import time
import re

init(autoreset=True)

SSL_PORTS = {443, 8443, 465, 993, 995, 636}


def show_banner():
    banner = pyfiglet.figlet_format("ShadowRipper")
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(Fore.YELLOW + Style.BRIGHT + "💀 Welcome to ShadowRipper Port Scanner 💀")
    print(Fore.BLUE + "-" * 60)
    time.sleep(1)


def clean_domain(domain):
    return re.sub(r'^https?://', '', domain.strip())


def domain_to_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"\n[✔] Domain       : {domain}")
        print(Fore.GREEN + f"[✔] IP Address   : {ip}")
        return ip
    except socket.gaierror:
        print(Fore.RED + f"[❌] Could not resolve domain: {domain}")
        return None


def ip_whois_lookup(ip):
    try:
        print(Fore.MAGENTA + "\n[~] Performing WHOIS Lookup...")
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        print(Fore.CYAN + "\n🌐 WHOIS Information:")
        print(Fore.WHITE + f"  🧾 Network Name : {results.get('network', {}).get('name', 'N/A')}")
        print(Fore.WHITE + f"  🏳 Country       : {results.get('network', {}).get('country', 'N/A')}")
        org_info = results.get('network', {}).get('org', {})
        print(Fore.WHITE + f"  🏢 Organization  : {org_info.get('name', 'N/A')}")
    except Exception as e:
        print(Fore.RED + f"[❌] WHOIS lookup failed: {e}")


def check_ssl_certificate(ip, port, domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])
                print(Fore.LIGHTCYAN_EX + f"     └─ 🔐 SSL Certificate:")
                print(Fore.LIGHTWHITE_EX + f"        CN      : {subject.get('commonName', 'N/A')}")
                print(Fore.LIGHTWHITE_EX + f"        Issuer  : {issuer.get('commonName', 'N/A')}")
                print(Fore.LIGHTWHITE_EX + f"        Expiry  : {cert.get('notAfter', 'N/A')}")
    except ssl.SSLError:
        print(Fore.YELLOW + "     └─ [!] SSL detected but handshake failed.")
    except Exception:
        print(Fore.YELLOW + "     └─ [!] SSL check skipped (timeout or error).")


def get_scan_range():
    print(Fore.CYAN + "\n📡 Select Port Scan Mode:")
    print("  1. All ports (20-65535)")
    print("  2. Custom (e.g. 22, 20-65535)")

    choice = input(Fore.YELLOW + "➤ Enter choice (1/2): ").strip()

    if choice == '1':
        return list(range(1, 65536))
    elif choice == '2':
        port_input = input("➤ Enter ports and/or ranges (comma-separated): ").strip()
        ports = set()

        parts = port_input.split(',')
        for part in parts:
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    if 1 <= start <= end <= 65535:
                        ports.update(range(start, end + 1))
                except:
                    print(Fore.RED + f"[❌] Invalid range: {part}")
            else:
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except:
                    print(Fore.RED + f"[❌] Invalid port: {part}")

        if ports:
            return sorted(ports)
        else:
            print(Fore.RED + "[❌] No valid ports entered. Exiting.")
            exit()
    else:
        print(Fore.RED + "[❌] Invalid choice. Exiting.")
        exit()


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"


def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "No banner"
    except:
        return "Banner grab failed"


def port_scan(ip, domain, ports):
    print(Fore.MAGENTA + "\n[~] Scanning ports...")
    open_ports = []

    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    service = get_service_name(port)
                    print(Fore.LIGHTGREEN_EX + f"[✔] Port {port:>5} ({service}) is OPEN")
                    open_ports.append((port, service))

                    if port in SSL_PORTS or service.lower() in ["https", "smtps", "imaps", "pop3s", "ldaps"]:
                        check_ssl_certificate(ip, port, domain)

                    banner = grab_banner(ip, port)
                    print(Fore.LIGHTBLUE_EX + f"     └─ 🧾 Banner: {banner}")
        except Exception:
            continue

    if not open_ports:
        print(Fore.YELLOW + "[!] No open ports found.")
    else:
        print(Fore.CYAN + f"\n[+] Total open ports found: {len(open_ports)}")


def main():
    show_banner()
    raw_input = input(Fore.YELLOW + "🌍 Enter a domain (e.g., example.com or https://example.com): ")
    domain = clean_domain(raw_input)
    ip = domain_to_ip(domain)
    if ip:
        ip_whois_lookup(ip)
        ports = get_scan_range()
        port_scan(ip, domain, ports)


if __name__ == "__main__":
    main()

