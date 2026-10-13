# CertTools
My repository containing tools for certifications

## agent_scanner.sh
This tool requires you to perform a comprehensive nmap scan on all targets and output to a pre-set path (modifiable in the script as a variable)

Example (nmap scan + use):

$ nmap -sV --open -p 1-10000 192.168.50.21 192.168.50.22 192.168.50.23 192.168.50.24 -oN /tmp/general_nmap_scan.txt

$ /tmp/agent_scanner.sh /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

