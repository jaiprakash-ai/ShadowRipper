# ShadowRipper

**ShadowRipper** is an advanced, multi-threaded Python-based reconnaissance tool and port scanner featuring WHOIS lookup, subdomain enumeration, HTTP security headers analysis, SSL certificate inspection, banner grabbing, live progress bar, and comprehensive report exports.

---

## 💀 Features

- ⚡ **Multi-Threaded Port Scanner**: Blazing fast concurrent port scanning using `ThreadPoolExecutor`.
- 📊 **Live Progress Bar**: Visual scanning progress indicator displaying completion percentage, scanned count, and open ports in real-time.
- 🔍 **Subdomain Reconnaissance**: Multi-threaded discovery of common subdomains (e.g., `admin`, `api`, `mail`, `dev`, `portal`, `vpn`).
- 🛡️ **HTTP Security Headers Analysis**: Inspects critical security headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, etc.).
- 🌐 **Robust Domain Cleaning & IP Resolution**: Automatically parses URLs and strips paths, query params, and schemes to resolve target hostnames accurately.
- 🧾 **WHOIS & Banner Grabbing**: Network name, country, and organization lookup with service banner grabbing (including HTTP `Server` headers).
- 🔐 **SSL Certificate Inspection**: Extracts Common Name (CN), Issuer, and Expiry dates on SSL/TLS services.
- 💾 **Report Export**: Save complete scan & recon reports in **TXT** or **JSON** format.
- ⌨️ **CLI Flags & Interactive Mode**: Run through an interactive guided CLI or pass arguments for automation.
- 🛑 **Graceful Interrupt**: Clean exit on `Ctrl + C` without traceback errors.

---

## 🚀 Installation & Usage

#### 📥 1. Clone the Repository

```bash
git clone https://github.com/jaiprakash-ai/ShadowRipper.git
cd ShadowRipper
```

#### 📦 2. Install Dependencies

```bash
pip install -r requirements.txt
```

#### ▶️ 3. Run the Tool

**Interactive Mode:**
```bash
python shadowRipper.py
```

**CLI Argument Mode:**
```bash
# Scan common ports with subdomain recon
python shadowRipper.py -d example.com -p common -s

# Custom ports with 100 threads and save report to JSON
python shadowRipper.py -d example.com -p 80,443,8080 -t 100 -o report.json
```

---

## ⚙️ CLI Options

| Flag | Full Name | Description | Default |
|------|-----------|-------------|---------|
| `-d` | `--domain` | Target domain or IP address | Interactive prompt |
| `-p` | `--ports` | Ports to scan (`common`, `all`, or `80,443,8000-8080`) | Interactive prompt |
| `-t` | `--threads` | Number of concurrent threads | `50` |
| `-s` | `--subdomains` | Run common subdomain enumeration | Prompt in interactive mode |
| `--skip-headers` | `--skip-headers` | Skip HTTP security headers analysis | `False` |
| `-o` | `--output` | Output file path (`.txt` or `.json`) | Interactive prompt |
| `-h` | `--help` | Show help message and exit | - |

---

## 📁 Project Structure

```text
ShadowRipper/
├── shadowRipper.py       # Main reconnaissance script
├── requirements.txt      # Dependencies
└── README.md             # Project documentation
```

---

## 🙌 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License — feel free to use, modify, and distribute it.

## 👨‍💻 Developed by

**Jai Prakash**
