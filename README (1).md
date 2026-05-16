# 🎣 Phishing URL Detector

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Topics](https://img.shields.io/badge/topics-cybersecurity%20%7C%20ethical--hacking%20%7C%20python%20%7C%20pentesting-red)](#)

A lightweight, zero-dependency Python tool that analyses URLs for phishing indicators using **heuristic checks** and a **blocklist**. Built for security researchers, students, and blue-team analysts.

---

## ⚠️ Disclaimer & Ethical Use

> **This tool is intended for educational and authorised security research purposes only.**
>
> - Only analyse URLs that you own or have **explicit written permission** to test.
> - Do **not** use this tool to facilitate illegal activity.
> - The authors accept no liability for misuse or damage caused by this software.
> - Automated scanning of third-party infrastructure without permission may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in your jurisdiction.

---

## ✨ Features

| Check | Description |
|---|---|
| 🚫 Blocklist | Matches against a curated list of known phishing domains |
| 🔢 IP address URLs | Flags URLs that use raw IPs instead of domain names |
| 🔓 HTTP (no TLS) | Warns when HTTPS is absent |
| ⚠️ Suspicious TLDs | Detects abused free TLDs (`.tk`, `.ml`, `.ga`, etc.) |
| 🔗 URL shorteners | Identifies services like bit.ly that hide destinations |
| 🎣 Phishing keywords | Scans for words like `login`, `verify`, `paypal`, `suspended` |
| 🌐 Excessive subdomains | Flags deep subdomain chains used to spoof legit sites |
| 📏 Long URLs | Detects obfuscation via URL padding |
| @ symbol trick | Catches the classic `real.com@evil.com` browser trick |
| 🔡 Punycode/Homograph | Detects `xn--` encoded look-alike domains |
| 🎲 High-entropy domains | Identifies algorithmically generated (DGA) domain names |
| 🔌 Non-standard ports | Flags unexpected port numbers |

Each check adds a risk **score**. The final risk level is:

| Score | Risk Level |
|---|---|
| 0 – 29 | 🟢 Low |
| 30 – 59 | 🟡 Medium |
| 60 – 89 | 🔴 High |
| 90+ | 🟣 Critical |

---

## 📁 Project Structure

```
phishing-url-detector/
├── detector.py            # Main tool
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── LICENSE                # MIT License
├── data/
│   ├── blocklist.txt      # Known phishing domains (one per line)
│   └── sample_urls.txt    # Example URLs for testing
└── tests/
    └── test_detector.py   # Pytest unit tests
```

---

## 🚀 Setup & Installation

### Prerequisites
- Python **3.8** or higher
- `pip` (comes with Python)

### 1 – Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector
```

### 2 – (Optional) Create a virtual environment

```bash
python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3 – Install dependencies

```bash
pip install -r requirements.txt
```

> The core `detector.py` uses **Python stdlib only** (no third-party packages required to run). The `requirements.txt` adds pytest for testing.

---

## 🖥️ Usage

### Analyse a single URL

```bash
python detector.py -u "http://paypa1-secure.tk/login/verify"
```

**Output:**
```
────────────────────────────────────────────────────────────
URL   : http://paypa1-secure.tk/login/verify
Score : 138
Risk  : Critical
Flags :
  • 🚫 Domain is on the blocklist
  • 🔓 No HTTPS – connection is unencrypted
  • ⚠️  Suspicious TLD: .tk
  • 🎣 Phishing keywords found: login, verify
────────────────────────────────────────────────────────────
```

---

### Analyse a list of URLs from a file

```bash
python detector.py -f data/sample_urls.txt
```

---

### Output as JSON

```bash
python detector.py -u "https://xn--pple-43d.com/id" --json
```

---

### Save JSON results to a file

```bash
python detector.py -f data/sample_urls.txt --output results.json
```

---

### Disable colour output (for piping / CI)

```bash
python detector.py -u "http://example.tk" --no-color
```

---

### Full help

```bash
python detector.py --help
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Expected output:
```
tests/test_detector.py::test_entropy_empty          PASSED
tests/test_detector.py::test_ip_address_flagged     PASSED
tests/test_detector.py::test_blocklist_hit          PASSED
...
15 passed in 0.12s
```

---

## 🔧 Extending the Blocklist

The blocklist lives at `data/blocklist.txt` — one domain per line, no protocol prefix.

```
# Add your own entries:
evil-phishing-site.com
fake-bank-login.ml
```

### Recommended free threat-intelligence feeds to integrate:
| Feed | URL |
|---|---|
| PhishTank | https://www.phishtank.com/developer_info.php |
| OpenPhish | https://openphish.com/ |
| URLhaus | https://urlhaus.abuse.ch/ |
| Abuse.ch | https://abuse.ch/ |

---

## 🗺️ Roadmap

- [ ] Live WHOIS domain age check (newly registered = higher risk)
- [ ] VirusTotal API integration
- [ ] Screenshot capture of suspicious pages
- [ ] Web dashboard (Flask/FastAPI)
- [ ] Browser extension wrapper
- [ ] Auto-update blocklist from threat feeds

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/whois-check`
3. Commit your changes: `git commit -m "Add WHOIS domain age check"`
4. Push and open a Pull Request

Please make sure `pytest tests/` passes before submitting.

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.

---

## 📌 GitHub Topics

`cybersecurity` `ethical-hacking` `python` `pentesting` `phishing` `url-analysis` `blue-team` `security-tools` `heuristics` `osint`

> Add these in **Settings → Topics** on your GitHub repository page.
