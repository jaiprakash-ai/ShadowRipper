import socket
import ssl
import time
import re
import json
import argparse
import sys
import threading
import urllib.request
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipwhois import IPWhois
from colorama import Fore, Style, init
import pyfiglet

init(autoreset=True)

SSL_PORTS = {443, 8443, 465, 993, 995, 636}
TOP_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 500, 514, 520, 587, 636, 873, 993, 995,
    1080, 1194, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 3000,
    3128, 3306, 3389, 4000, 5000, 5432, 5672, 5900, 5985, 6379, 7001, 8000, 8080,
    8081, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 27017, 50000
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
    "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
    "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
    "wiki", "web", "media", "email", "images", "img", "www1", "intranet", "portal",
    "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
    "search", "staging", "server", "my", "svn", "git", "login"
]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS - Enforces secure HTTPS connections"),
    ("X-Frame-Options", "Clickjacking Protection"),
    ("X-Content-Type-Options", "MIME-sniffing Protection"),
    ("Content-Security-Policy", "XSS & Data Injection Prevention"),
    ("X-XSS-Protection", "Cross-Site Scripting Filter"),
    ("Referrer-Policy", "Controls referrer data leakage"),
    ("Permissions-Policy", "Controls browser features/APIs access")
]

print_lock = threading.RLock()


def show_banner():
    banner = pyfiglet.figlet_format("ShadowRipper")
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(Fore.YELLOW + Style.BRIGHT + "💀 Welcome to ShadowRipper Port Scanner 💀")
    print(Fore.BLUE + "-" * 60)
    print(Fore.GREEN + Style.BRIGHT + "🔗 Developed by: Jai Prakash")
    print(Fore.BLUE + "-" * 60)
    time.sleep(0.5)


def clean_domain(domain):
    domain = domain.strip()
    if not domain:
        return ""
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    parsed = urlparse(domain)
    netloc = parsed.netloc or parsed.path
    netloc = netloc.split(':')[0]
    return netloc.strip('/')


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
        network_name = results.get('network', {}).get('name', 'N/A')
        country = results.get('network', {}).get('country', 'N/A')
        org_info = results.get('network', {}).get('org', {})
        org_name = org_info.get('name', 'N/A')

        print(Fore.CYAN + "\n🌐 WHOIS Information:")
        print(Fore.WHITE + f"  🧾 Network Name : {network_name}")
        print(Fore.WHITE + f"  🏳 Country       : {country}")
        print(Fore.WHITE + f"  🏢 Organization  : {org_name}")
        return {
            "network_name": network_name,
            "country": country,
            "organization": org_name
        }
    except Exception as e:
        print(Fore.RED + f"[❌] WHOIS lookup failed: {e}")
        return {
            "network_name": "N/A",
            "country": "N/A",
            "organization": "N/A"
        }


def find_subdomains(domain, max_threads=20):
    print(Fore.MAGENTA + f"\n[~] Enumerating {len(COMMON_SUBDOMAINS)} common subdomains...")
    discovered = []

    def check_sub(sub):
        sub_domain = f"{sub}.{domain}"
        try:
            sub_ip = socket.gethostbyname(sub_domain)
            return sub_domain, sub_ip
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_sub, sub) for sub in COMMON_SUBDOMAINS]
        for f in as_completed(futures):
            res = f.result()
            if res:
                sub_name, sub_ip = res
                with print_lock:
                    print(Fore.LIGHTGREEN_EX + f"  [✔] Subdomain Found: {sub_name:<30} -> {sub_ip}")
                discovered.append({"subdomain": sub_name, "ip": sub_ip})

    if not discovered:
        print(Fore.YELLOW + "  [!] No common subdomains discovered.")
    else:
        print(Fore.CYAN + f"  [+] Total subdomains discovered: {len(discovered)}")

    return discovered


def check_security_headers(domain):
    print(Fore.MAGENTA + "\n[~] Checking HTTP Security Headers...")
    target_urls = [f"https://{domain}", f"http://{domain}"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    headers = None
    active_url = None
    for url in target_urls:
        try:
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ShadowRipper/2.0'}
            )
            with urllib.request.urlopen(req, timeout=3.5, context=ctx) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                active_url = url
                break
        except Exception:
            continue

    if not headers:
        print(Fore.YELLOW + "  [!] Web service unreachable for security header inspection.")
        return {}

    print(Fore.CYAN + f"  🌐 Endpoint Tested: {active_url}")
    results = {}
    for header, desc in SECURITY_HEADERS:
        val = headers.get(header.lower())
        if val:
            print(Fore.LIGHTGREEN_EX + f"  [✔] {header:<28} : PRESENT")
            results[header] = {"status": "PRESENT", "value": val, "description": desc}
        else:
            print(Fore.LIGHTRED_EX + f"  [⚠️] {header:<28} : MISSING ({desc})")
            results[header] = {"status": "MISSING", "value": None, "description": desc}

    return results


def check_ssl_certificate(ip, port, domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=2.5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return {"error": "Certificate unavailable"}
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                cn = subject.get('commonName', 'N/A')
                issuer_name = issuer.get('commonName', 'N/A')
                expiry = cert.get('notAfter', 'N/A')

                return {
                    "common_name": cn,
                    "issuer": issuer_name,
                    "expiry": expiry
                }
    except ssl.SSLCertVerificationError as e:
        return {"error": f"Verification failed ({getattr(e, 'verify_message', 'Untrusted')})"}
    except ssl.SSLError as e:
        return {"error": f"Handshake failed ({getattr(e, 'reason', 'SSL error')})"}
    except Exception:
        return {"error": "Skipped or timed out"}


def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"


def grab_banner(ip, port, domain):
    try:
        # For SSL/TLS ports, use wrapped socket to avoid hanging on plaintext handshake
        if port in SSL_PORTS or port == 443:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((ip, port), timeout=2.0) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        http_req = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                        ssock.sendall(http_req.encode())
                        banner = ssock.recv(1024).decode(errors='ignore').strip()
                        if banner:
                            for line in banner.splitlines():
                                if line.lower().startswith("server:"):
                                    return line.strip()
                            first_line = banner.splitlines()[0].strip()
                            return first_line[:80] if first_line else "TLS service active"
            except Exception:
                return "TLS/SSL service"
            return "No banner"

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.5)
            sock.connect((ip, port))

            # Send HTTP probe for common web ports
            if port in {80, 8080, 8000, 8888, 3000, 5000}:
                http_req = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
                sock.sendall(http_req.encode())

            banner = sock.recv(1024).decode(errors='ignore').strip()
            if banner:
                for line in banner.splitlines():
                    if line.lower().startswith("server:"):
                        return line.strip()
                first_line = banner.splitlines()[0].strip()
                return first_line[:80] if first_line else "Banner received"
            return "No banner"
    except:
        return "No banner"


def parse_port_input(port_input):
    ports = set()
    parts = port_input.split(',')
    for part in parts:
        part = part.strip()
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
    return sorted(ports)


def get_scan_range():
    print(Fore.CYAN + "\n📡 Select Port Scan Mode:")
    print("  1. Common / Top Ports (~69 popular ports) [Recommended / Fastest]")
    print("  2. All ports (1-65535) [Full Scan]")
    print("  3. Custom (e.g. 22, 80, 443, 8000-8080)")

    choice = input(Fore.YELLOW + "➤ Enter choice (1/2/3): ").strip()

    if choice == '1':
        return TOP_PORTS
    elif choice == '2':
        return list(range(1, 65536))
    elif choice == '3':
        port_input = input("➤ Enter ports and/or ranges (comma-separated): ").strip()
        ports = parse_port_input(port_input)
        if ports:
            return ports
        else:
            print(Fore.RED + "[❌] No valid ports entered. Exiting.")
            sys.exit(1)
    else:
        print(Fore.RED + "[❌] Invalid choice. Defaulting to Common Ports.")
        return TOP_PORTS


def render_progress_bar(completed, total, open_count, width=28):
    pct = (completed / total) if total > 0 else 1.0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    percent_str = f"{int(pct * 100):>3}%"
    return f"\r{Fore.CYAN}[{bar}] {percent_str} | Scanned: {completed}/{total} | Open: {open_count}{Style.RESET_ALL}"


def scan_single_port(ip, domain, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = get_service_name(port)

                # Perform SSL check outside lock to prevent contention/deadlock
                ssl_info = None
                if port in SSL_PORTS or service.lower() in ["https", "smtps", "imaps", "pop3s", "ldaps"]:
                    ssl_info = check_ssl_certificate(ip, port, domain)

                # Perform banner grab outside lock
                banner = grab_banner(ip, port, domain)

                # Acquire lock exclusively for console output
                with print_lock:
                    sys.stdout.write("\r" + " " * 85 + "\r")
                    sys.stdout.flush()
                    print(Fore.LIGHTGREEN_EX + f"[✔] Port {port:>5} ({service}) is OPEN")

                    if ssl_info:
                        if "error" not in ssl_info:
                            print(Fore.LIGHTCYAN_EX + f"     └─ 🔐 SSL Certificate:")
                            print(Fore.LIGHTWHITE_EX + f"        CN      : {ssl_info.get('common_name', 'N/A')}")
                            print(Fore.LIGHTWHITE_EX + f"        Issuer  : {ssl_info.get('issuer', 'N/A')}")
                            print(Fore.LIGHTWHITE_EX + f"        Expiry  : {ssl_info.get('expiry', 'N/A')}")
                        else:
                            print(Fore.YELLOW + f"     └─ [!] SSL: {ssl_info['error']}")

                    print(Fore.LIGHTBLUE_EX + f"     └─ 🧾 Banner: {banner}")

                return {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "ssl": ssl_info
                }
    except Exception:
        pass
    return None


def port_scan(ip, domain, ports, max_threads=50):
    total = len(ports)
    print(Fore.MAGENTA + f"\n[~] Scanning {total} ports using {max_threads} parallel threads...")
    open_ports = []
    completed = 0
    start_time = time.time()

    # Initial progress bar display
    sys.stdout.write(render_progress_bar(0, total, 0))
    sys.stdout.flush()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_single_port, ip, domain, port): port for port in ports}
        try:
            for future in as_completed(futures):
                res = future.result()
                with print_lock:
                    completed += 1
                    if res:
                        open_ports.append(res)
                    sys.stdout.write(render_progress_bar(completed, total, len(open_ports)))
                    sys.stdout.flush()
        except KeyboardInterrupt:
            with print_lock:
                sys.stdout.write("\r" + " " * 85 + "\r")
                sys.stdout.flush()
                print(Fore.RED + "\n[!] Stopping scan gracefully...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    # Clear progress line when done
    with print_lock:
        sys.stdout.write("\r" + " " * 85 + "\r")
        sys.stdout.flush()

    open_ports.sort(key=lambda x: x['port'])
    duration = round(time.time() - start_time, 2)
    print(Fore.BLUE + "-" * 60)
    if not open_ports:
        print(Fore.YELLOW + f"[!] No open ports found. (Finished in {duration}s)")
    else:
        print(Fore.CYAN + f"\n[+] Total open ports found: {len(open_ports)} (Finished in {duration}s)")

    return open_ports


def save_report(domain, ip, whois_info, subdomains, sec_headers, open_ports, output_path=None):
    try:
        format_choice = None
        if not output_path:
            save_choice = input(Fore.YELLOW + "\n💾 Do you want to save the scan results to a file? (y/n): ").strip().lower()
            if save_choice != 'y':
                return
            format_choice = input(Fore.YELLOW + "➤ Choose format (1 for TXT / 2 for JSON): ").strip()
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            safe_domain = domain.replace(".", "_")
            if format_choice == '2':
                output_path = f"scan_{safe_domain}_{timestamp}.json"
            else:
                output_path = f"scan_{safe_domain}_{timestamp}.txt"

        if output_path.endswith('.json') or format_choice == '2':
            data = {
                "target_domain": domain,
                "ip_address": ip,
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "whois": whois_info,
                "subdomains": subdomains,
                "security_headers": sec_headers,
                "open_ports": open_ports
            }
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("=" * 65 + "\n")
                f.write(" " * 20 + "SHADOWRIPPER SCAN REPORT\n")
                f.write("=" * 65 + "\n")
                f.write(f"Target Domain  : {domain}\n")
                f.write(f"IP Address     : {ip}\n")
                f.write(f"Scan Timestamp : {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                f.write("-" * 65 + "\n")
                f.write("1. WHOIS INFORMATION:\n")
                f.write(f"   Network Name : {whois_info.get('network_name', 'N/A')}\n")
                f.write(f"   Country      : {whois_info.get('country', 'N/A')}\n")
                f.write(f"   Organization : {whois_info.get('organization', 'N/A')}\n\n")

                if subdomains:
                    f.write("-" * 65 + "\n")
                    f.write(f"2. DISCOVERED SUBDOMAINS ({len(subdomains)}):\n")
                    for s in subdomains:
                        f.write(f"   [✔] {s['subdomain']:<32} -> {s['ip']}\n")
                    f.write("\n")

                if sec_headers:
                    f.write("-" * 65 + "\n")
                    f.write("3. HTTP SECURITY HEADERS ANALYSIS:\n")
                    for h_name, h_info in sec_headers.items():
                        status = h_info.get('status')
                        desc = h_info.get('description', '')
                        f.write(f"   [{status}] {h_name:<28} : {desc}\n")
                    f.write("\n")

                f.write("-" * 65 + "\n")
                f.write(f"4. OPEN PORTS FOUND ({len(open_ports)}):\n")
                for p in open_ports:
                    f.write(f"   [+] Port {p['port']:>5} ({p['service']})\n")
                    f.write(f"       Banner : {p['banner']}\n")
                    if p.get('ssl'):
                        ssl_data = p['ssl']
                        if 'common_name' in ssl_data:
                            f.write(f"       SSL CN : {ssl_data['common_name']}\n")
                            f.write(f"       Issuer : {ssl_data['issuer']}\n")
                            f.write(f"       Expiry : {ssl_data['expiry']}\n")
                f.write("=" * 65 + "\n")

        print(Fore.GREEN + f"[✔] Scan report saved successfully to: {output_path}")
    except Exception as e:
        print(Fore.RED + f"[❌] Failed to save report: {e}")


def parse_cli_args():
    parser = argparse.ArgumentParser(
        description="ShadowRipper - Fast Multi-Threaded Port Scanner & Recon Tool",
        add_help=True
    )
    parser.add_argument("-d", "--domain", help="Target domain or IP (e.g. example.com)")
    parser.add_argument("-p", "--ports", help="Ports to scan: 'common', 'all', or custom list/ranges like '80,443,8000-8080'")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of concurrent threads (default: 50)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Run common subdomain enumeration")
    parser.add_argument("--skip-headers", action="store_true", help="Skip HTTP security headers analysis")
    parser.add_argument("-o", "--output", help="Output file path (e.g. results.txt or results.json)")
    return parser.parse_args()


def main():
    args = parse_cli_args()

    show_banner()

    # 1. Domain Resolution
    if args.domain:
        raw_input = args.domain
    else:
        raw_input = input(Fore.YELLOW + "🌍 Enter a domain (e.g., example.com or https://example.com): ")

    domain = clean_domain(raw_input)
    if not domain:
        print(Fore.RED + "[❌] No valid domain provided. Exiting.")
        return

    ip = domain_to_ip(domain)
    if not ip:
        return

    # 2. WHOIS Lookup
    whois_info = ip_whois_lookup(ip)

    # 3. Subdomain Reconnaissance
    subdomains = []
    run_sub_enum = args.subdomains
    if not args.domain and not run_sub_enum:
        sub_choice = input(Fore.YELLOW + "\n🔍 Do you want to run Subdomain Reconnaissance? (y/n): ").strip().lower()
        run_sub_enum = (sub_choice == 'y')

    if run_sub_enum:
        subdomains = find_subdomains(domain, max_threads=25)

    # 4. Ports Selection
    if args.ports:
        port_arg = args.ports.lower().strip()
        if port_arg == 'common':
            ports = TOP_PORTS
        elif port_arg == 'all':
            ports = list(range(1, 65536))
        else:
            ports = parse_port_input(args.ports)
            if not ports:
                print(Fore.RED + "[❌] No valid ports provided via CLI. Exiting.")
                return
    else:
        ports = get_scan_range()

    # 5. Multi-Threaded Port Scan with Live Progress Bar
    open_ports = port_scan(ip, domain, ports, max_threads=args.threads)

    # 6. HTTP Security Headers Analysis
    sec_headers = {}
    if not args.skip_headers:
        sec_headers = check_security_headers(domain)

    # 7. Report Generation
    save_report(domain, ip, whois_info, subdomains, sec_headers, open_ports, output_path=args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Process cancelled by user (Ctrl+C). Exiting gracefully.")
        sys.exit(0)
