# 🔍 VulnSight - CLI & GUI Network Vulnerability Scanner

**VulnSight** is a powerful network vulnerability scanner that identifies open ports, running services, and their associated CVEs (Common Vulnerabilities and Exposures). It leverages **Nmap** for scanning and maps discovered services to known vulnerabilities using CVE databases. The project supports both a **Command Line Interface (CLI)** and a **Graphical User Interface (GUI)** for flexible usage.

---

## ✨ Features

- 🔌 **Network Scan**  
  Scan for open ports and services on any given IP or domain using Nmap.

- 🛡️ **CVE Detection**  
  Retrieve known vulnerabilities (CVEs) for discovered services, along with their **CVSS (Common Vulnerability Scoring System)** scores.

- 🖥️ **Modern GUI Interface**  
  Intuitive GUI with a clean interface and a scanning loader for better user experience.

- 🧾 **Detailed Reports**  
  Save comprehensive scan results in `nmap_report.txt` for offline analysis.

---

## 📦 Requirements

- Python 3.7+
- `python-nmap` – Interface for Nmap tool.
- `requests` – For CVE API communication.
- `ttkbootstrap` – For modern, themed GUI elements.

---

## 🚀 Installation

1. Clone the repository:
   ```bash 
   📂 git clone https://github.com/your-repo/vulnsight.git`  
   💻 `cd vulnsight`
   ```

3. Install dependencies:
   📦 Use `pip` to install required Python packages listed in `requirements.txt`.
   ```bash
    pip install -r requirements.txt
   ```

---

## ⚙️ Running the Application

### 🖥️ CLI Version
Run the CLI scanner with:  
📌 `python main.py`  
- Enter the target IP/domain when prompted.
- View scan results directly in the terminal, including open ports, services, and matched CVEs.

---

### 🪟 GUI Version
Run the GUI scanner with:  
```bash 
📌 `python gui_main.py`
```
  
- Enter the IP/domain in the input field.
- Click the **Scan** button to initiate scanning.
- Results appear in a scrollable view, with CVEs color-coded by severity:

  - 🔴 **High Severity** (CVSS ≥ 7)  
  - 🟠 **Medium Severity** (CVSS ≥ 4)  
  - 🟢 **Low Severity** (CVSS < 4)

---

## 🧠 CVE Lookup

VulnSight integrates with the **CVE Circl API** to gather vulnerability data for commonly used services like:

- Apache
- Nginx
- OpenSSL
- MySQL  
... and more.

---

## 📋 Example Output

```bash
Scan Report for 192.168.1.1
Scan Time: 2025-04-15 10:30:01

Protocol: TCP
  Port: 80   State: open   Service: Apache 2.4.41
    ➤ CVE-2020-11993 (CVSS: 8.2): Apache HTTP Server mod_proxy_uwsgi
    ➤ CVE-2020-35489 (CVSS: 5.3): Apache HTTP Server mod_proxy
  Port: 443   State: open   Service: OpenSSL 1.1.1
    ➤ CVE-2019-1551 (CVSS: 3.5): OpenSSL SSLv2 vulnerability

OS Detection:
  - Linux (Accuracy: 95%)
```

---

## 💾 Report Storage

All scan results are saved automatically in a `nmap_report.txt` file within the project directory for future review.

---

## 📝 License

This project is licensed under the **MIT License**.  
See the [LICENSE](./LICENSE) file for details.
