#!/usr/bin/env python3
"""
OTAUD — CVE Lookup for OT/ICS Devices
Queries known CVE databases for vulnerabilities affecting ICS/OT equipment.
Uses the NIST NVD API and a built-in offline database of critical ICS CVEs.
Author: Ali AlEnezi (SiteQ8)
"""

import argparse
import json
import sys
from datetime import datetime

# Offline database of critical ICS/OT CVEs (curated)
ICS_CVE_DATABASE = [
    {"cve": "CVE-2024-3400", "vendor": "Palo Alto", "product": "PAN-OS (OT Firewall)", "severity": "CRITICAL", "cvss": 10.0,
     "description": "Command injection in GlobalProtect gateway — actively exploited in OT networks"},
    {"cve": "CVE-2023-3595", "vendor": "Rockwell", "product": "ControlLogix/GuardLogix", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Remote code execution via CIP protocol — can modify controller firmware"},
    {"cve": "CVE-2023-3596", "vendor": "Rockwell", "product": "1756-EN2/EN3 EtherNet/IP", "severity": "HIGH", "cvss": 7.5,
     "description": "Denial of service via crafted CIP packets"},
    {"cve": "CVE-2022-2003", "vendor": "AutomationDirect", "product": "DirectLOGIC PLCs", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Cleartext transmission of authentication credentials"},
    {"cve": "CVE-2023-46604", "vendor": "Apache", "product": "ActiveMQ (used in SCADA)", "severity": "CRITICAL", "cvss": 10.0,
     "description": "RCE via ClassInfo deserialization — impacts SCADA message buses"},
    {"cve": "CVE-2022-26134", "vendor": "Atlassian", "product": "Confluence (OT wiki)", "severity": "CRITICAL", "cvss": 9.8,
     "description": "OGNL injection RCE — found in OT documentation servers"},
    {"cve": "CVE-2023-27350", "vendor": "PaperCut", "product": "Print Mgmt (OT printers)", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Auth bypass + RCE in print management used in OT environments"},
    {"cve": "CVE-2020-14882", "vendor": "Oracle", "product": "WebLogic (SCADA backend)", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Unauthenticated RCE — used in SCADA web backends"},
    {"cve": "CVE-2021-22681", "vendor": "Rockwell", "product": "Logix Controllers", "severity": "CRITICAL", "cvss": 10.0,
     "description": "Authentication bypass via CIP — key extraction attack"},
    {"cve": "CVE-2020-25078", "vendor": "D-Link", "product": "DCS IP Camera", "severity": "HIGH", "cvss": 7.5,
     "description": "Admin credential disclosure — IoT camera"},
    {"cve": "CVE-2019-18935", "vendor": "Telerik", "product": "UI (used in HMI web)", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Deserialization RCE — found in HMI web applications"},
    {"cve": "CVE-2022-3602", "vendor": "OpenSSL", "product": "OpenSSL 3.x (OT devices)", "severity": "HIGH", "cvss": 7.5,
     "description": "Buffer overflow in X.509 certificate verification"},
    {"cve": "CVE-2019-13945", "vendor": "Siemens", "product": "S7-1500 CPU", "severity": "HIGH", "cvss": 6.8,
     "description": "Protection bypass allows read access to CPU data"},
    {"cve": "CVE-2019-6569", "vendor": "Siemens", "product": "SINEMA Remote Connect", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Auth bypass in remote access solution for OT"},
    {"cve": "CVE-2022-22965", "vendor": "VMware/Spring", "product": "Spring Framework (SCADA)", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Spring4Shell RCE — impacts Java-based SCADA systems"},
    {"cve": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j (OT/SCADA)", "severity": "CRITICAL", "cvss": 10.0,
     "description": "Log4Shell — widespread impact on SCADA/HMI applications"},
    {"cve": "CVE-2020-10644", "vendor": "Inductive", "product": "Ignition Gateway", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Deserialization RCE in Ignition SCADA gateway"},
    {"cve": "CVE-2020-12004", "vendor": "Iconics", "product": "Genesis64/Mitsubishi MC Works", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Uncontrolled deserialization in SCADA platform"},
    {"cve": "CVE-2023-28489", "vendor": "Siemens", "product": "CP-8031/CP-8050", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Command injection in Siemens SINEC NMS component"},
    {"cve": "CVE-2021-22779", "vendor": "Schneider", "product": "Modicon M340/M580", "severity": "CRITICAL", "cvss": 9.8,
     "description": "Authentication bypass on Modbus/UMAS protocol"},
    {"cve": "CVE-2018-7760", "vendor": "Schneider", "product": "Modicon Premium/Quantum", "severity": "CRITICAL", "cvss": 9.8,
     "description": "FTP/HTTP credential bypass on legacy PLCs"},
    {"cve": "CVE-2020-25198", "vendor": "Moxa", "product": "NPort IAW5000A Series", "severity": "CRITICAL", "cvss": 9.8,
     "description": "OS command injection in serial-to-IP gateway"},
    {"cve": "CVE-2022-30190", "vendor": "Microsoft", "product": "MSDT (OT workstations)", "severity": "HIGH", "cvss": 7.8,
     "description": "Follina RCE — impacts engineering workstations"},
    {"cve": "CVE-2023-21554", "vendor": "Microsoft", "product": "MSMQ (OT message queue)", "severity": "CRITICAL", "cvss": 9.8,
     "description": "QueueJumper RCE in Message Queuing — used in SCADA"},
    {"cve": "CVE-2017-0144", "vendor": "Microsoft", "product": "SMBv1 (OT workstations)", "severity": "CRITICAL", "cvss": 9.8,
     "description": "EternalBlue — still prevalent in legacy OT systems"},
]


def search_cves(query, severity_filter=None):
    """Search the offline CVE database."""
    query_lower = query.lower()
    results = []

    for cve in ICS_CVE_DATABASE:
        searchable = f"{cve['vendor']} {cve['product']} {cve['description']} {cve['cve']}".lower()
        if query_lower in searchable:
            if severity_filter and cve['severity'] != severity_filter.upper():
                continue
            results.append(cve)

    return sorted(results, key=lambda x: x['cvss'], reverse=True)


def try_nvd_api(query, api_key=None):
    """Attempt to query NIST NVD API (requires network access)."""
    try:
        import urllib.request
        import urllib.parse

        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = urllib.parse.urlencode({
            'keywordSearch': query,
            'resultsPerPage': 10
        })
        url = f"{base_url}?{params}"

        headers = {'User-Agent': 'OTAUD/1.0'}
        if api_key:
            headers['apiKey'] = api_key

        req = urllib.request.Request(url, headers=headers)
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())

        results = []
        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id', 'Unknown')
            descriptions = cve_data.get('descriptions', [])
            desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), 'No description')

            metrics = cve_data.get('metrics', {})
            cvss = 0.0
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get('cvssData', {}).get('baseScore', 0.0)
                    break

            severity = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM" if cvss >= 4.0 else "LOW"
            results.append({
                "cve": cve_id,
                "vendor": query,
                "product": "",
                "severity": severity,
                "cvss": cvss,
                "description": desc[:200]
            })
        return results
    except Exception as e:
        print(f"  [~] NVD API unavailable ({e}), using offline database")
        return None


def display_results(results, query):
    """Display CVE search results."""
    print("\n" + "=" * 70)
    print(f"  CVE SEARCH RESULTS — Query: '{query}'")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Results: {len(results)}")
    print("=" * 70)

    if not results:
        print("  No matching CVEs found in database.")
        print("  Try broader search terms or check NVD directly:")
        print("  https://nvd.nist.gov/vuln/search")
        return

    for cve in results:
        sev = cve['severity']
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
        print(f"\n  {icon} {cve['cve']} (CVSS: {cve['cvss']}) [{sev}]")
        print(f"     Vendor: {cve['vendor']} | Product: {cve['product']}")
        print(f"     {cve['description']}")

    print("\n" + "-" * 70)
    print("  REMEDIATION GUIDANCE:")
    print("  • Check vendor advisories for patches/mitigations")
    print("  • Apply compensating controls (network segmentation, monitoring)")
    print("  • Report to ICS-CERT if actively exploited")
    print("  • Reference: https://www.cisa.gov/known-exploited-vulnerabilities")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="OTAUD CVE Lookup for OT/ICS")
    parser.add_argument("--query", "-q", required=True, help="Search query (vendor, product, CVE ID)")
    parser.add_argument("--severity", "-s", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    parser.add_argument("--online", action="store_true", help="Also query NVD API")
    parser.add_argument("--api-key", help="NVD API key for higher rate limits")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    # Search offline database
    results = search_cves(args.query, args.severity)

    # Optionally query NVD
    if args.online:
        print("[*] Querying NIST NVD API...")
        nvd_results = try_nvd_api(args.query, args.api_key)
        if nvd_results:
            # Merge, avoiding duplicates
            existing_ids = {r['cve'] for r in results}
            for nr in nvd_results:
                if nr['cve'] not in existing_ids:
                    results.append(nr)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        display_results(results, args.query)


if __name__ == "__main__":
    main()
