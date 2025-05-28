# ShadowRipper

**ShadowRipper** is an advanced and customizable Python-based port scanner with WHOIS lookup, SSL certificate inspection, and service banner grabbing. It's designed to be both powerful and user-friendly, offering deep insights into the target domain or IP.

---

## 💀 Features

- 🌐 Domain to IP resolution
- 🔍 WHOIS lookup for IPs
- 🔓 Port scanning (custom ranges supported)
- 🧾 Banner grabbing for open services
- 🔐 SSL certificate detection and inspection
- 🎨 Colorful CLI with `colorama` and `pyfiglet` for enhanced readability

---

## 🚀 Installation & Usage

#### 📥 1. Clone the Repository

```bash
git clone https://github.com/jaiprakash-ai/ShadowRipper.git
```
```bash
cd ShadowRipper
```
📦 2. Install Dependencies
```bash
pip install -r requirements.txt
```
▶️ 3. Run the Tool
```bash
python3 shadowripper.py
```


---
## 📊 Example Output

🌍 Enter a domain (e.g., example.com): example.com
           
      [✔] Domain       : example.com
      [✔] IP Address   : 93.184.216.34


🌐 WHOIS Information:
                
    🧾 Network Name : EXAMPLE-NET
    🏳 Country      : US
    🏢 Organization : Example Org
  

[~] Scanning ports...

[✔] Port    443 (https) is OPEN

     └─ 🔐 SSL Certificate:
        CN      : example.com
        Issuer  : Let's Encrypt Authority X3
        Expiry  : Mar 12 10:00:00 2025 GMT
     └─ 🧾 Banner: No banner
     

[+] Total open ports found: 1

---

## 📁 Project Structure

     ShadowRipper/
     ├── shadowripper.py       # Main script
     ├── requirements.txt      # Dependencies
     ├── README.md             # You're here!
## 🙌 Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

## 📄 License

This project is licensed under the MIT License — feel free to use, modify, and distribute it.

## 👨‍💻 Author
Jai prakash (@jaiprakash-ai)
