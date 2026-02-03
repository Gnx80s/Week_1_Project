import nmap
import json
import requests

# ---  Step 1: Initialize  ---
scanner = nmap.PortScanner()
target = input("Enter target IP address or hostname: ")

print(f"\n[+] Scanning {target}...\n")
# ---  Step 2: Perform scan  ---
scanner.scan(target, '1-1024', '-sV')  # 1–1024 common ports, detect service versions

# ---  Step 3: Define known vulnerabilities  ---
vulnerable_ports = {
    21: "FTP may allow anonymous login",
    22: "SSH can be brute forced if weak credentials",
    23: "Telnet sends data insecurely",
    80: "HTTP is unencrypted",
    139: "NetBIOS may expose shared files",
    445: "SMB vulnerable to EternalBlue (CVE-2017-0144)",
    3389: "RDP may be vulnerable to BlueKeep (CVE-2019-0708)"
}
# results container
report = []
# ---  Step 4: Parse results  ---
for host in scanner.all_hosts():
    print(f"Host: {host} ({scanner[host].hostname()})")
    print(f"State: {scanner[host].state()}")
    
    for proto in scanner[host].all_protocols():
        ports = scanner[host][proto].keys()
        for port in sorted(ports):
            state = scanner[host][proto][port]['state']
            name = scanner[host][proto][port]['name']
            product = scanner[host][proto][port].get('product', '')
            version = scanner[host][proto][port].get('version', '')

            print(f" Port {port}/{proto}: {name} ({product} {version}) → [{state}]")

            issue = vulnerable_ports.get(port)
            if issue:
                print(f"  Potential vulnerability: {issue}")
            
            # Save to report
            report.append({
                "host": host,
                "port": port,
                "protocol": proto,
                "service": name,
                "product": product,
                "version": version,
                "state": state,
                "vulnerability": issue if issue else "None"
            })

# ---  Step 5: Save results to file  ---
with open("scan_report.json", "w") as f:
    json.dump(report, f, indent=2)

print("\n Report saved as scan_report.json\n")
print("Scan complete ")