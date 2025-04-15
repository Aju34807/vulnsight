import nmap
import datetime
from cve_lookup import lookup_cves

def run_nmap_scan(target):
    print(f"[+] Starting scan on {target}")
    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=target, arguments='-sV -O -Pn')
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        return

    if target not in nm.all_hosts():
        print("[-] Host is down or not found.")
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
                cve_results = lookup_cves(svc_name, svc_ver)
                for cve in cve_results:
                    result += f"    ➤ {cve}\n"

    # OS Detection
    if 'osmatch' in nm[target]:
        result += "\n🧠 OS Detection:\n"
        for os in nm[target]['osmatch']:
            result += f"  - {os['name']} (Accuracy: {os['accuracy']}%)\n"

    # Save to file
    with open("nmap_report.txt", "w", encoding="utf-8") as f:
        f.write(result)

    print("\n[✓] Scan complete. Results saved to nmap_report.txt\n")
    print(result)

if __name__ == "__main__":
    print("=== VulnSight CLI Scanner ===")
    target_ip = input("Enter the IP or domain to scan: ")
    run_nmap_scan(target_ip)
