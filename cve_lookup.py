import requests

def lookup_cves(service, version):
    query = f"{service} {version}"
    print(f"🔍 Looking up CVEs for: {query}")

    try:
        response = requests.get(f"https://cve.circl.lu/api/search/{service}/{version}")
        if response.status_code != 200:
            return []

        data = response.json()
        cves = data.get("data", [])[:5]

        result = []
        for cve in cves:
            score = cve.get("cvss", 0)
            if score >= 7:
                emoji = "🔴"
            elif score >= 4:
                emoji = "🟠"
            else:
                emoji = "🟢"

            result.append(f"{emoji} {cve['id']} (CVSS: {score}): {cve['summary']}")
        return result

    except Exception as e:
        print(f"[!] Error fetching CVEs: {e}")
        return []
