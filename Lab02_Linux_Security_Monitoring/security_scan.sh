#!/bin/bash
# ============================================================
# security_scan.sh
# Allied Software Engineers - Cyber Security Internship
# Lab Assignment 02 - Scenario 2
# Author: Ghulam Nabi
#
# This script collects basic system information and saves each
# report inside an "AuditReport" folder. At the end it shows a
# completion message and (bonus) compresses the folder to a ZIP.
# Usage:  bash security_scan.sh
# ============================================================

# 1. Make the report folder (with the date so old reports are not lost)
REPORT_DIR="AuditReport"
mkdir -p "$REPORT_DIR"

echo "Starting security scan..."
echo "Reports will be saved in the $REPORT_DIR folder."
echo

# 2. System details
echo "[+] Collecting system details..."
{
  echo "===== SYSTEM DETAILS ====="
  echo "Hostname : $(hostname)"
  echo "Date     : $(date)"
  echo "Uptime   : $(uptime -p)"
  echo
  echo "--- uname -a ---"
  uname -a
  echo
  echo "--- OS version ---"
  cat /etc/os-release | head -3
} > "$REPORT_DIR/system_details.txt"

# 3. Disk usage
echo "[+] Collecting disk usage..."
{
  echo "===== DISK USAGE ====="
  df -h
} > "$REPORT_DIR/disk_usage.txt"

# 4. Memory usage
echo "[+] Collecting memory usage..."
{
  echo "===== MEMORY USAGE ====="
  free -h
} > "$REPORT_DIR/memory_usage.txt"

# 5. Running processes
echo "[+] Collecting running processes..."
{
  echo "===== RUNNING PROCESSES (top 15 by CPU) ====="
  ps aux --sort=-%cpu | head -16
} > "$REPORT_DIR/processes.txt"

# 6. IP address
echo "[+] Collecting IP address..."
{
  echo "===== IP ADDRESS ====="
  ip addr show | grep -E "inet |link/ether"
  echo
  echo "--- Default route ---"
  ip route | grep default
} > "$REPORT_DIR/ip_address.txt"

# 7. Open network ports
echo "[+] Collecting open network ports..."
{
  echo "===== OPEN NETWORK PORTS ====="
  ss -tuln
} > "$REPORT_DIR/open_ports.txt"

echo
echo "============================================"
echo " Security scan completed successfully!"
echo " All reports are saved in: $REPORT_DIR/"
echo "============================================"

# 8. BONUS: compress the folder into a ZIP
ZIP_NAME="AuditReport_$(hostname)_$(date +%F).zip"
if command -v zip >/dev/null 2>&1; then
  zip -r "$ZIP_NAME" "$REPORT_DIR" >/dev/null
  echo "[+] Bonus: report folder compressed into $ZIP_NAME"
else
  echo "[!] 'zip' not installed, skipping compression."
fi
