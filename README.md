# God's Sight by Arun Saru 🔍 
# i'll update readme later 
**Open Source Security Assessment Tool**

God's Sight is a modular, extensible security assessment tool designed to perform  
**network reconnaissance, service analysis, and security misconfiguration detection**  
using a **plugin-based architecture**.

It is built for:
- Security learners
- Ethical hackers
- Blue team engineers
- Open-source contributors

> ⚠️ This tool is intended **ONLY for authorized security testing**.  
> Unauthorized scanning of systems you do not own or have permission to test is illegal.

---

## ✨ Features

- ⚡ Fast multi-threaded port scanning  
- 🧩 Plugin-based vulnerability detection  
- 🔐 TLS certificate inspection  
- 🚫 Weak / legacy service detection (FTP, Telnet, etc.)  
- 📊 Structured findings with severity & confidence  
- 📁 JSON & SARIF export support  
- 🧼 Clean CLI output  
- 🧠 Designed for easy extension  

---

## 📂 Project Structure

godssight/
│
├── core/
│   ├── scanner.py        # Port scanning engine
│   ├── plugin_loader.py  # Dynamic plugin loader
│   ├── results.py        # ScanResult data model
│   ├── findings.py       # Finding data model
│   ├── utils.py          # Filtering & output helpers
│   ├── output_json.py    # JSON exporter
│   └── output_sarif.py   # SARIF exporter
│
├── plugins/
│   ├── base.py           # Plugin base class
│   ├── weak_services.py  # FTP / Telnet detection
│   ├── tls_cert.py       # TLS certificate inspection
│   └── __init__.py
│
├── main.py               # CLI entry point
├── LICENSE
└── README.md

---

## 🚀 Installation

### Requirements
- Python **3.9+**
- No external dependencies required (standard library only)

### Clone the repository
git clone https://github.com/yokai-crow/gods_sight.git  
cd gods-sight

---

## 🧪 Usage

### Basic scan

```bash
python main.py -H example.com
```

### Scan common ports only

```bash
python main.py -H example.com -C
```

### Increase threads

```bash
python main.py -H example.com --threads 50
```

### Enable verbose logging

```bash
python main.py -H example.com --verbose
```

### Strict mode (MEDIUM & HIGH findings only)

```bash
python main.py -H example.com --strict
```

---

## 📤 Exporting Results

### Export to JSON

```bash
python main.py -H example.com --json
```
### Export to SARIF (GitHub / CI compatible)

```bash
python main.py -H example.com --sarif
```

### Output files

>example.com_findings.json  
>example.com_findings.sarif

---

## 🔌 Plugins

God's Sight uses a plugin-based architecture.

Each plugin:
- Receives scan results  
- Analyzes services or configurations  
- Returns structured findings  

### Example Plugin

class WeakServicePlugin(Plugin):
    name = "Weak / Legacy Services"

    def run(self, results):
        ...

### Current Plugins

Plugin | Description  
------ | ------------
http_headers | http related checks
ssh_reachable | ssh related checks
sql_injection | simple test (ud)
WeakServicePlugin | Detects FTP & Telnet  
TLSCertPlugin | Checks TLS certificate expiration  

---

## 🧠 Findings Model

Each finding includes:
- id
- title
- severity (LOW / MEDIUM / HIGH)
- category
- confidence
- description
- evidence
- remediation

This makes the output SOC-ready and easy to integrate with other tools.

---

## 🛠️ Writing Your Own Plugin

1. Create a new file in `plugins/`
2. Extend the base `Plugin` class
3. Implement the `run()` method
4. Return a list of `Finding` objects

Example:

from plugins.base import Plugin

class MyPlugin(Plugin):
    name = "My Custom Check"

    def run(self, results):
        return []

Plugins are auto-loaded at runtime.

---

## 🔐 Legal Disclaimer

This project is provided for educational and authorized testing purposes only.

You are responsible for complying with:
- Local laws  
- Target authorization  
- Ethical hacking guidelines  

The author assumes no liability for misuse.

---

## 🤝 Contributing

Contributions are welcome!

You can:
- Add new plugins
- Improve detection logic
- Enhance output formats
- Improve documentation

Steps:
1. Fork the repository  
2. Create a feature branch  
3. Commit your changes  
4. Open a Pull Request  

---

## 📜 License

This project is licensed under the terms of the **MIT License**.  
See the `[LICENSE](LICENSE)` file for details.

---

## 👤 Author

**Arun Saru**  
Security Researcher | Ethical Hacker | Open Source Contributor

---

## ⭐ Support the Project

If you find this useful:
- Star the repo ⭐
- Share it
- Contribute improvements

“Security is not a product, but a process.”
