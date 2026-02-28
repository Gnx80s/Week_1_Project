# Basic Vulnerability Scanner

A simple Python‑based network scanner that checks a target (IP or hostname) for open ports, running services, and a few known vulnerabilities.

---

## How It Works

1. Scans target ports (1‑1024) using **python‑nmap**
2. Detects running services and versions
3. Flags any port known to be **insecure or vulnerable**
4. Saves a report in **JSON format**

---

## Requirements

- Python 3
- Nmap installed on system
- Python libraries
  
---
## File Structure
<pre>
  
Week_1_Project/
│
├── scanner.py/
│            
├── requirement.txt/
│         
├── scan_report.json/
│      
└── README.md                       
 
</pre>
