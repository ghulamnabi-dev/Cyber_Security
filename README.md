# Cyber Security Internship – Allied Software Engineers

Name: Ghulam Nabi

This repository contains the Bash automation scripts I wrote for my Cyber Security
Internship lab assignments.

## Folders

### Lab02_Linux_Security_Monitoring
- `security_scan.sh` – Collects system details, disk usage, memory usage, running
  processes, IP address and open ports into an `AuditReport` folder, prints a
  completion message, and compresses the folder into a ZIP file.

### Lab03_Security_Audit_Incident_Response
- `security_audit.sh` – Runs a full Linux security audit (system info, users,
  passwords, permissions, network, services) and saves the result to a report file.
- `incident_triage.sh` – Collects incident evidence (logs, login history, running
  processes and active network connections) for investigating a security incident.

## How to run
```bash
chmod +x script_name.sh
./script_name.sh
```

Some checks read system files, so you may need to run with sudo:
```bash
sudo ./script_name.sh
```
