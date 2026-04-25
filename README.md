# Wazuh Detection Rule Set

Production-quality Wazuh XML detection rules covering all major enterprise log
sources and MITRE ATT&CK tactics. Built for SOC training and operational deployment.

---

## Repository Structure

```
.
├── rules/
│   ├── office365/          # Microsoft 365 / Azure AD rules
│   ├── windows/            # Windows Security Event log rules
│   ├── defender/           # Microsoft Defender for Endpoint rules
│   ├── network/            # Firewall, VPN, DNS, EDR rules
│   ├── ai_threats/         # AI-augmented attack & AI infrastructure attack rules
│   └── correlation/        # Cross-source multi-stage attack correlation
├── lists/                  # Wazuh CDB lookup lists (IOCs, allowlists)
└── threat_intel/           # Automated threat-intel updater for CDB lists
```

---

## Rule Index

### Office 365

| File | Rule IDs | Coverage | MITRE |
|------|----------|----------|-------|
| `rules/office365/100000_o365_initial_access.xml` | 100000–100006 | Failed login, brute force, geo-anomaly, legacy auth, MFA disable, impossible travel | T1110, T1078.004, T1556.006 |
| `rules/office365/100020_o365_persistence.xml` | 100020–100025 | OAuth consent, inbox forwarding, external forwarding, admin role assign, mailbox delegation | T1550.001, T1114.003, T1098.002, T1098.003 |
| `rules/office365/100040_o365_exfiltration.xml` | 100040–100046 | Mass email access, bulk file download, external sharing, VIP mailbox access, eDiscovery export | T1114.002, T1048, T1048.002 |
| `rules/office365/100060_o365_defense_evasion.xml` | 100060–100064 | Audit log disabled, Conditional Access modified, MFA disabled org-wide, email purge, Security Defaults off | T1562.008, T1556, T1556.006 |

### Windows Security Events

| File | Rule IDs | Coverage | MITRE |
|------|----------|----------|-------|
| `rules/windows/100100_win_initial_access.xml` | 100100–100106 | Failed logon (4625), brute force, password spray, account lockout (4740), Pass-the-Hash, explicit credentials (4648) | T1110, T1110.001, T1110.003, T1550.002, T1078 |
| `rules/windows/100120_win_privilege_escalation.xml` | 100120–100125 | Special privileges (4672), dangerous privilege use (4673), token manipulation (4703), local/domain admin group add (4732) | T1078.002, T1134, T1134.001, T1098 |
| `rules/windows/100140_win_persistence.xml` | 100140–100146 | Scheduled task (4698), suspicious task path, new service (7045), suspicious service path, new user (4720), backdoor admin account, password change | T1053.005, T1543.003, T1136.001, T1098 |
| `rules/windows/100160_win_defense_evasion.xml` | 100160–100167 | Audit policy change (4719), security log cleared (1102), system log cleared (104), Defender disabled (5001), PS encoded command, PS download cradle, process injection, AMSI bypass | T1562.002, T1070.001, T1562.001, T1059.001, T1055 |
| `rules/windows/100180_win_discovery.xml` | 100180–100185 | Account enumeration, net user/group commands, network discovery, LDAP/AD recon tools, permission discovery, ipconfig/netstat | T1087, T1018, T1069, T1016 |

### Microsoft Defender

| File | Rule IDs | Coverage | MITRE |
|------|----------|----------|-------|
| `rules/defender/100200_defender_threats.xml` | 100200–100205 | Malware detected, high-severity threat, ransomware behavior, credential theft tool, exploit protection, failed remediation | T1204, T1203, T1486, T1003 |
| `rules/defender/100220_defender_evasion.xml` | 100220–100224 | Exclusion added, tamper protection disabled, RTP disabled, suspicious exclusion path, network protection disabled | T1562.001 |

### Network & Endpoint

| File | Rule IDs | Coverage | MITRE |
|------|----------|----------|-------|
| `rules/network/100300_firewall.xml` | 100300–100306 | Port scan, outbound/inbound to malicious IP, C2 beacon pattern, unusual high port, large data transfer | T1046, T1190, T1071, T1571, T1048 |
| `rules/network/100400_vpn.xml` | 100400–100406 | Failed auth, brute force, geo-anomaly, off-hours login, concurrent sessions, post-BF success, non-standard protocol | T1110.001, T1078, T1572 |
| `rules/network/100500_dns.xml` | 100500–100505 | IOC domain query, DNS tunneling (long label), NXDOMAIN flood/DGA, large TXT record, high-frequency beaconing, NRD pattern | T1568, T1568.002, T1071.004 |
| `rules/network/100600_edr.xml` | 100600–100607 | LOLBin abuse, LSASS access, Mimikatz by name, suspicious process chain, ransomware file extension, Run key persistence, remote thread injection, C2 from script host | T1218, T1003.001, T1055, T1486, T1547.001, T1071 |

### AI Threat Detection

| File | Rule IDs | Coverage | MITRE / ATLAS |
|------|----------|----------|---------------|
| `rules/ai_threats/100800_ai_attack_detection.xml` | 100800–100821 | AI-speed credential stuffing, AI-crafted phishing links, LLM tool execution on endpoint, AI-speed port scan, mass personalised spear-phishing, LLM API abuse (large tokens), prompt injection, ML model theft, dataset exfiltration, persistent prompt injection, deepfake media upload, multi-vector AI recon, polymorphic malware (AI-generated) | T1110, T1566, T1059, T1046, T1190, T1005, T1048, T1027 |

### Cross-Source Correlation

| File | Rule IDs | Coverage | MITRE |
|------|----------|----------|-------|
| `rules/correlation/100700_cross_source.xml` | 100700–100707 | O365 BF → success, Defender alert + log cleared, anomalous VPN + O365 bulk download, port scan + service install, Windows BF + Defender disabled, admin role + MFA disable, DNS DGA + C2 connection, ransomware + log cleared | T1110, T1048, T1070, T1046, T1562, T1098, T1568, T1486 |

---

## CDB Lists

| File | Purpose | Referenced by |
|------|---------|---------------|
| `lists/trusted_admins.txt` | Admin accounts excluded from some privilege alerts | Windows priv-esc rules |
| `lists/allowed_countries.txt` | Expected geo — logins from other countries alert | O365, VPN rules |
| `lists/sensitive_mailboxes.txt` | VIP/exec mailboxes with lower-threshold alerts | O365 exfiltration rules |
| `lists/known_bad_domains.txt` | IOC domains from threat feeds | DNS, O365 rules |
| `lists/known_bad_ips.txt` | IOC IPs from threat feeds | Firewall rules |

CDB format: one `entry:` per line (key-only lookup).

---

## Threat-Intel Auto-Updater

`threat_intel/update_rules.py` fetches fresh IOCs from public feeds and
regenerates the CDB list files automatically.

**Feeds included:**
- **abuse.ch URLhaus** — recent malicious domains
- **abuse.ch Feodo Tracker** — botnet C2 IPs
- **AlienVault OTX** — malware domains (requires API key)

**Setup:**
```bash
# Install cron job (run as root on the Wazuh manager)
sudo bash threat_intel/cron_setup.sh

# Test without writing (dry-run)
python3 threat_intel/update_rules.py --dry-run

# Run immediately
python3 threat_intel/update_rules.py --output-dir /var/ossec/etc/lists
```

After each update the script automatically reloads the Wazuh manager so
rules pick up the new IOC entries without a full restart.

**Schedule (installed by cron_setup.sh):**
- Daily at 02:00 UTC — full update (all feeds)
- Every 6 hours — Feodo C2 IP list only (changes frequently)

---

## Severity Scale

| Level | Label | Meaning |
|-------|-------|---------|
| 3 | Informational | Baseline telemetry; used as parent for correlation |
| 5 | Low | Single anomalous event; worth recording |
| 7–8 | Medium | Suspicious activity; investigate if repeated |
| 10 | High | Strong indicator; requires analyst review |
| 12 | High+ | High-confidence attack pattern |
| 13 | Critical | Confirmed attack technique; immediate review |
| 14 | Critical | Active attack in progress |
| 15 | Maximum | Confirmed incident — isolate and respond now |

---

## Wazuh Deployment Notes

1. **Copy rule files** to `/var/ossec/etc/rules/` (subdirectories supported)
2. **Copy CDB list files** to `/var/ossec/etc/lists/`
3. **Register lists** in `/var/ossec/etc/ossec.conf`:
   ```xml
   <ruleset>
     <list>etc/lists/trusted_admins</list>
     <list>etc/lists/allowed_countries</list>
     <list>etc/lists/sensitive_mailboxes</list>
     <list>etc/lists/known_bad_domains</list>
     <list>etc/lists/known_bad_ips</list>
   </ruleset>
   ```
4. **Include rule directories** in `ossec.conf`:
   ```xml
   <ruleset>
     <rule_dir>etc/rules/office365</rule_dir>
     <rule_dir>etc/rules/windows</rule_dir>
     <rule_dir>etc/rules/defender</rule_dir>
     <rule_dir>etc/rules/network</rule_dir>
     <rule_dir>etc/rules/ai_threats</rule_dir>
     <rule_dir>etc/rules/correlation</rule_dir>
   </ruleset>
   ```
5. **Validate XML** before deploying: `xmllint --noout rules/**/*.xml`
6. **Reload manager**: `/var/ossec/bin/ossec-control reload`

---

## False Positive Tuning

- Add legitimate service accounts to `lists/trusted_admins.txt`
- Add expected countries to `lists/allowed_countries.txt`
- For noisy process-creation rules, tune via Wazuh `<if_not_matched>` child rules
- Scheduled tasks and services created by software deployment tools (SCCM, Intune)
  will trigger rules 100140/100142 — allowlist known deployment account names

---

## MITRE ATT&CK Coverage Summary

| Tactic | Techniques Covered |
|--------|-------------------|
| Initial Access | T1078, T1078.004, T1110, T1110.001, T1110.003, T1190, T1566, T1566.001, T1566.002 |
| Execution | T1059, T1059.001, T1203, T1204, T1218 |
| Persistence | T1053.005, T1098, T1098.002, T1098.003, T1114.003, T1136.001, T1543.003, T1547.001, T1550.001 |
| Privilege Escalation | T1078.002, T1098, T1134, T1134.001 |
| Defense Evasion | T1027, T1027.005, T1055, T1070.001, T1562.001, T1562.002, T1562.008 |
| Credential Access | T1003, T1003.001, T1110, T1550.002, T1556, T1556.006 |
| Discovery | T1016, T1018, T1046, T1069, T1087, T1087.001 |
| Lateral Movement | T1550.002 |
| Collection | T1005, T1114.002 |
| Command & Control | T1071, T1071.004, T1568, T1568.002, T1571, T1572 |
| Exfiltration | T1048, T1048.002 |
| Impact | T1486 |
