#!/bin/bash
# ============================================================
# security_audit.sh — Linux Security Audit Automation
# Allied Software Engineers | Cyber Security Internship Lab 03
# Usage: sudo bash security_audit.sh
# Output: audit_report_<hostname>_<date>.txt
# ============================================================

OUT="audit_report_$(hostname)_$(date +%F).txt"
exec > >(tee "$OUT") 2>&1

section() { echo; echo "==================== $1 ===================="; }

section "1. SYSTEM INFORMATION"
hostname; uname -a; cat /etc/os-release | head -5; uptime; df -h /; free -h

section "2. USER & GROUP AUDIT"
echo "-- Accounts with login shells --"
grep -E '(bash|sh|zsh)$' /etc/passwd
echo "-- UID 0 accounts (should only be root) --"
awk -F: '$3==0 {print $1}' /etc/passwd
echo "-- Members of sudo/adm groups --"
grep -E '^(sudo|adm|wheel|docker)' /etc/group

section "3. PASSWORD & ACCOUNT SECURITY"
echo "-- Empty-password accounts (CRITICAL if any listed) --"
awk -F: '($2==""){print $1}' /etc/shadow
echo "-- Password aging policy --"
grep -E '^PASS_(MAX|MIN|WARN)' /etc/login.defs
echo "-- Critical file permissions --"
ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow

section "4. FILE PERMISSION AUDIT"
echo "-- World-writable files (system dirs) --"
find /etc /usr/bin /usr/sbin -xdev -type f -perm -0002 2>/dev/null
echo "-- SUID binaries --"
find /usr -xdev -perm -4000 -type f 2>/dev/null
echo "-- Cron entries --"
ls -la /etc/cron.d/ 2>/dev/null; crontab -l 2>/dev/null

section "5. NETWORK AUDIT"
ip -brief addr; ip route
echo "-- Listening ports --"
ss -tulnp
echo "-- Firewall status --"
ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -20

section "6. SERVICES & PATCH STATUS"
systemctl list-units --type=service --state=running 2>/dev/null | head -20
echo "-- Pending security updates --"
apt list --upgradable 2>/dev/null | grep -c security
echo "-- SSH hardening check --"
grep -E '^(PermitRootLogin|PasswordAuthentication|MaxAuthTries)' /etc/ssh/sshd_config 2>/dev/null || echo "sshd not installed or defaults in use"

section "AUDIT COMPLETE"
echo "Report saved to: $OUT"
