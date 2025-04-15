import tkinter as tk
from tkinter import scrolledtext, messagebox
from ttkbootstrap import Style
import nmap
import datetime
from cve_lookup import lookup_cves

import threading

def threaded_scan():
    scan_button.config(state=tk.DISABLED)
    status_label.config(text="🔄 Scanning... please wait.")

    target = target_entry.get().strip()
    if not target:
        messagebox.showwarning("Input Error", "Please enter a target IP or domain.")
        scan_button.config(state=tk.NORMAL)
        status_label.config(text="")
        return

    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, f"[+] Scanning {target}...\n")

    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-sV -O -Pn')
    except Exception as e:
        output_box.insert(tk.END, f"[!] Scan error: {e}\n")
        scan_button.config(state=tk.NORMAL)
        status_label.config(text="❌ Scan failed")
        return

    if target not in nm.all_hosts():
        output_box.insert(tk.END, "[-] Host is down or not responding.\n")
        scan_button.config(state=tk.NORMAL)
        status_label.config(text="✅ Scan complete")
        return

    result = f"🔎 Scan Report for {target}\n"
    result += f"🕒 Scan Time: {datetime.datetime.now()}\n\n"

    for proto in nm[target].all_protocols():
        ports = nm[target][proto].keys()
        result += f"\n📡 Protocol: {proto.upper()}\n"
        for port in sorted(ports):
            service = nm[target][proto][port]
            svc_name = service.get('product', '') or service.get('name', '')
            svc_ver = service.get('version', '')
            result += f"  🔹 Port: {port}\tState: {service['state']}\tService: {svc_name} {svc_ver}\n"

            # CVE Lookup
            if svc_name and svc_ver:
                cves = lookup_cves(svc_name, svc_ver)
                for cve in cves:
                    result += f"    ➤ {cve}\n"

    # OS Detection
    if 'osmatch' in nm[target]:
        result += "\n🧠 OS Detection:\n"
        for os in nm[target]['osmatch']:
            result += f"  - {os['name']} (Accuracy: {os['accuracy']}%)\n"

    with open("nmap_report.txt", "w", encoding="utf-8") as f:
        f.write(result)

    output_box.insert(tk.END, result + "\n[✓] Scan complete. Report saved to nmap_report.txt\n")
    scan_button.config(state=tk.NORMAL)
    status_label.config(text="✅ Scan complete")


def run_scan():
    threading.Thread(target=threaded_scan).start()
# GUI Setup
app = tk.Tk()
app.title("VulnSight - GUI Scanner")
app.geometry("750x500")

style = Style(theme="flatly")

frame = tk.Frame(app)
frame.pack(pady=10)

tk.Label(frame, text="Target IP / Domain:", font=("Segoe UI", 11)).pack(side=tk.LEFT, padx=5)
target_entry = tk.Entry(frame, width=40)
target_entry.pack(side=tk.LEFT, padx=5)

scan_button = tk.Button(frame, text="Scan", command=run_scan)
scan_button.pack(side=tk.LEFT, padx=5)

status_label = tk.Label(app, text="", font=("Segoe UI", 10), foreground="green")
status_label.pack()

output_box = scrolledtext.ScrolledText(app, font=("Consolas", 10), wrap=tk.WORD)
output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

app.mainloop()
