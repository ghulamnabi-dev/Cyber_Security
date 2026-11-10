# Task 7 - Advanced Multi-Stage APT Investigation

Name: Ghulam Nabi
Allied Software Engineers - Cyber Security Internship
Case reference: IR-2026-07-APT

This repository has the detection rules, SIEM queries and IoCs I made for the
Task 7 APT investigation. Everything here is **defensive** - these files are used
to FIND the attack in the logs, they do not perform any attack.

## Folders

### sigma/
Five Sigma detection rules (YAML). Sigma is a generic rule format that can be
converted to Splunk, Sentinel, Elastic and other SIEMs.

| File | What it detects | MITRE |
|------|-----------------|-------|
| 01_office_macro_child_process.yml | Phishing macro starting PowerShell/cmd | T1566.001 |
| 02_lsass_credential_dumping.yml | Password dumping from LSASS memory | T1003.001 |
| 03_scheduled_task_persistence.yml | Persistence via scheduled task | T1053.005 |
| 04_shadow_copy_deletion.yml | Shadow copies deleted before ransomware | T1490 |
| 05_event_log_clearing.yml | Event logs cleared to hide evidence | T1070.001 |

Convert a rule to Splunk:
```
sigma convert -t splunk sigma/02_lsass_credential_dumping.yml
```

### yara/
One YARA file with two rules - one for the loader and one for the ransomware.
```
yara -r yara/apt_loader_and_ransomware.yar /path/to/scan
```

### queries/
- `kql_microsoft_sentinel.kql` - KQL for Microsoft Sentinel / Defender
- `splunk_spl.spl` - the same detections written in Splunk SPL

Both cover privilege escalation, lateral movement and data exfiltration.

### iocs/
`iocs.csv` - all the indicators found (IPs, domains, hashes, file paths,
persistence, rogue account) with the MITRE technique and how to detect each one.

## Note
This is a lab scenario from the internship, not a real incident. The IPs, domains and file
hashes in it are example values for the lab. They are not indicators taken from real
malware samples, so do not use them as threat intelligence. The ransomware binary is
listed by file name only, because no hash was recorded for it.
