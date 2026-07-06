#!/bin/bash
# ============================================================
# incident_triage.sh — Linux Incident Response Triage
# Allied Software Engineers | Cyber Security Internship Lab 03
# Usage: sudo bash incident_triage.sh [auth_log_path]
# Output: triage_<hostname>_<date>.txt
# ============================================================

LOG="${1:-/var/log/auth.log}"
OUT="triage_$(hostname)_$(date +%F_%H%M).txt"
exec > >(tee "$OUT") 2>&1

section() { echo; echo "==================== $1 ===================="; }

section "1. AUTHENTICATION LOG ANALYSIS ($LOG)"
if [ -f "$LOG" ]; then
  echo "-- Failed attempts per source IP --"
  grep "Failed password" "$LOG" | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head -10
  echo "-- Targeted usernames --"
  grep "Failed password" "$LOG" | grep -oE "for (invalid user )?[A-Za-z0-9_-]+" | sort | uniq -c | sort -rn | head -10
  echo "-- Successful logins --"
  grep "Accepted" "$LOG" | tail -10
  echo "-- Sudo command usage --"
  grep "sudo:" "$LOG" | grep COMMAND | tail -15
  echo "-- New user creation events --"
  grep -E "useradd|usermod|new user|new group" "$LOG" | tail -10
else
  echo "Log file $LOG not found."
fi

section "2. LOGIN HISTORY"
last -20 2>/dev/null
lastb -10 2>/dev/null
lastlog | grep -v "Never" | head -10

section "3. PROCESS INVESTIGATION"
echo "-- Top CPU --"; ps aux --sort=-%cpu | head -8
echo "-- Top MEM --"; ps aux --sort=-%mem | head -8
echo "-- Processes executing from /tmp or /dev/shm --"
ls -la /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm' || echo "None (clean)"
echo "-- Deleted-binary processes --"
ls -la /proc/*/exe 2>/dev/null | grep deleted || echo "None (clean)"

section "4. NETWORK CONNECTIONS"
ss -tunap state established 2>/dev/null
ss -tulnp

section "5. PERSISTENCE CHECKS"
echo "-- Recently modified /etc files (48h) --"
find /etc -type f -mtime -2 2>/dev/null | head -15
echo "-- Cron entries --"
ls -la /etc/cron.d/ /var/spool/cron/crontabs/ 2>/dev/null
echo "-- authorized_keys files --"
find /root /home -name authorized_keys -exec ls -la {} \; 2>/dev/null
echo "-- Hidden files in temp dirs --"
find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null || echo "None (clean)"
echo "-- Accounts created recently (check /etc/passwd mtime) --"
ls -l /etc/passwd /etc/shadow

section "TRIAGE COMPLETE — preserve $OUT as evidence"
