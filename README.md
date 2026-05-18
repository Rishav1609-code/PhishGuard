# PhishGuard — Phishing Attack Simulation & Detection System 
## Deployment link -- https://main.phishguard-5cy.pages.dev/

A Python-based defensive cybersecurity tool designed to analyze suspicious emails and websites for phishing indicators. It features both a **Command Line Interface (CLI)** and a modern **Web Dashboard**.

![PhishGuard Dashboard](https://img.shields.io/badge/Status-Active-brightgreen)
![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-black)

## 🛡️ Features

1. **Email Header Analysis:** Verifies SPF, DKIM, and DMARC authentication records via live DNS lookups. Detects domain spoofing, mismatched `Reply-To` addresses, and suspicious mailer agents.
2. **IOC Extraction:** Extracts URLs, IP addresses, email addresses, and obfuscated/hidden links from email bodies (both plain text and HTML).
3. **Website URL Analysis:** Scans target URLs for phishing indicators including SSL/TLS certificate validity (detects free CAs and expired certs), domain age (WHOIS), login forms served over HTTP, URL shorteners, and typosquatting.
4. **Professional Web Dashboard:** A sleek, dark-themed UI built with Flask to easily drag-and-drop `.eml` files and scan URLs.

## 📁 Project Structure

```
phishing_detection_system/
├── app.py                           # Flask Web Server entry point
├── main.py                          # CLI entry point
├── requirements.txt                 # Python dependencies
├── config/
│   └── settings.py                  # Tunable thresholds, keywords, and brand lists
├── phase2_detection/
│   ├── header_analyzer.py           # Core logic for email header verification
│   ├── ioc_extractor.py             # Core logic for extracting indicators from body
│   └── website_analyzer.py          # Core logic for analyzing domains & SSL
├── static/                          # CSS and JS for the web dashboard
├── templates/                       # HTML templates for the web dashboard
└── utils/
    └── dns_utils.py                 # DNS query helpers (SPF, DKIM, DMARC)
```

## 🚀 Setup & Installation

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/phishing_detection_system.git
cd phishing_detection_system
```

**2. Create a virtual environment**
```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Linux/Mac:
source .venv/bin/activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

## 💻 Usage: Web Dashboard

To launch the professional web interface:

```bash
python app.py
```
Then open your browser and navigate to: **http://127.0.0.1:5000**

## 📟 Usage: Command Line Interface

The tool can also be run entirely from the terminal.

**1. Analyze an Email Header (`.eml` file)**
```bash
python main.py header path/to/email.eml
```

**2. Analyze a Website URL**
```bash
python main.py website https://www.example.com
```

**3. Run the Full Pipeline** (Analyzes header, extracts IOCs, and scans all extracted URLs)
```bash
python main.py full path/to/email.eml
```

## ⚠️ Disclaimer
This tool is for **defensive and educational purposes only**. It performs live DNS and WHOIS lookups but does not execute any exploits or malicious requests.

## 📄 License
This project is licensed under the MIT License.
