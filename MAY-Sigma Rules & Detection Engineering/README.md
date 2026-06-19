# Sigma Rules Detection Engineering Portfolio

[![Sigma](https://img.shields.io/badge/format-sigma-blue)](https://github.com/SigmaHQ/sigma)  
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)  
[![License](https://img.shields.io/badge/license-MIT-green)](/tmp/.mount_JoplindbCERk/resources/app.asar/LICENSE "LICENSE")

A collection of behavioral Sigma detection rules built from hands-on offensive security research, bug bounty findings, and adversary tradecraft analysis. Each rule prioritizes **TTP-based detection** over IOC matching  rules target the underlying technique, not easily-rotated artifacts like file names or hashes.

**Author:** Psalms ([@byteoverride](https://hackerone.com/byteoverride))

* * *

## Why this repo exists

Most published Sigma rules detect known tools by name (`mimikatz.exe`, `procdump.exe`). That's brittle  attackers rename binaries in seconds. These rules try to detect the **behavior underneath**: LSASS access masks, registry hive saves, session-token reuse patterns.

The centerpiece is a **purple team rule** ([`session_persistence_post_reset.yml`](/tmp/.mount_JoplindbCERk/resources/app.asar/purple-team/session_persistence_post_reset.yml "purple-team/session_persistence_post_reset.yml")) derived from a real account takeover I found while bug bounty hunting  translating the attacker's technique into a defender's detection.

* * *

## Repository structure

```
sigma-rules/
├── README.md                              ← you are here
├── credential-access/
│   ├── mimikatz_behavioral.yml            T1003.001 — LSASS access masks
│   ├── procdump_lsass.yml                 T1003.001 — Procdump abuse
│   ├── comsvcs_minidump.yml               T1003.001 — Fileless LSASS dump
│   └── reg_save_sam.yml                   T1003.002 — Registry hive extraction
├── defense-evasion/
│   ├── certutil_download.yml              T1105 — LOLBin file download
│   ├── mshta_remote.yml                   T1218.005 — Remote HTA execution
│   └── bitsadmin_transfer.yml             T1197 — BITS job abuse
├── brute-force/
│   ├── ssh_brute_force.yml                T1110.001 — SSH password attack
│   └── windows_logon_brute.yml            T1110 — Windows brute + spray
├── persistence/
│   ├── linux_cron_persistence.yml         T1053.003 — Cron job persistence
│   └── ssh_authorized_keys.yml            T1098.004 — SSH key persistence
└── purple-team/
    └── session_persistence_post_reset.yml T1550.004 / T1078 — Session reuse
```

**Total rules:** 12 (some files contain correlation rules in addition to the base detection)

* * *

## MITRE ATT&CK coverage heatmap

| Tactic | Technique | Sub-technique | Rule |
| --- | --- | --- | --- |
| Credential Access | T1003 — OS Credential Dumping | .001 LSASS Memory | `mimikatz_behavioral.yml`, `procdump_lsass.yml`, `comsvcs_minidump.yml` |
| Credential Access | T1003 — OS Credential Dumping | .002 Security Account Manager | `reg_save_sam.yml` |
| Credential Access | T1003 — OS Credential Dumping | .004 LSA Secrets | `reg_save_sam.yml` |
| Credential Access | T1110 — Brute Force | .001 Password Guessing | `ssh_brute_force.yml`, `windows_logon_brute.yml` |
| Credential Access | T1110 — Brute Force | .003 Password Spraying | `windows_logon_brute.yml` |
| Defense Evasion | T1218 — System Binary Proxy Execution | .005 Mshta | `mshta_remote.yml` |
| Defense Evasion | T1197 — BITS Jobs | —   | `bitsadmin_transfer.yml` |
| Defense Evasion | T1550 — Use Alternate Authentication Material | .004 Web Session Cookie | `session_persistence_post_reset.yml` |
| Command and Control | T1105 — Ingress Tool Transfer | —   | `certutil_download.yml` |
| Persistence | T1053 — Scheduled Task/Job | .003 Cron | `linux_cron_persistence.yml` |
| Persistence | T1098 — Account Manipulation | .004 SSH Authorized Keys | `ssh_authorized_keys.yml` |
| Persistence / Initial Access | T1078 — Valid Accounts | —   | `session_persistence_post_reset.yml` |

* * *

## The purple team rule  from bug bounty finding to detection

The rule `purple-team/session_persistence_post_reset.yml` is the differentiator in this portfolio. It comes from real attacker research on session persistence — specifically, the pattern where session tokens issued before a password change continue to be accepted after the reset.

See [`BLOG.md`](/tmp/.mount_JoplindbCERk/resources/app.asar/BLOG.md "BLOG.md") for the full write-up of how this offensive finding was translated into a defensive detection.

* * *

## Auditd configuration

The Linux rules (`linux_cron_persistence.yml`, `ssh_authorized_keys.yml`) require auditd watches. Apply these rules to `/etc/audit/rules.d/`:

```bash
# Cron persistence watches
-w /etc/crontab -p wa -k cron_persistence
-w /etc/cron.d/ -p wa -k cron_persistence
-w /etc/cron.hourly/ -p wa -k cron_persistence
-w /etc/cron.daily/ -p wa -k cron_persistence
-w /etc/cron.weekly/ -p wa -k cron_persistence
-w /etc/cron.monthly/ -p wa -k cron_persistence
-w /var/spool/cron/ -p wa -k cron_persistence

# SSH key persistence watches (for each user home that matters)
-w /root/.ssh/authorized_keys -p wa -k ssh_keys
# Per-user watches dynamically added on user creation by a helper script
```

Reload with `augenrules --load`.

* * *

## Self-assessment  evasion gaps

Each rule was reviewed against the question: **"Could an attacker evade this by changing one thing?"**

| Rule | Known evasion | Mitigation |
| --- | --- | --- |
| `mimikatz_behavioral.yml` | Custom access masks not in selection list | Periodically review LSASS access masks from threat intel; rule will need updates |
| `procdump_lsass.yml` | Rename procdump binary | `OriginalFileName` selector catches renamed binary; can still bypass with recompiled procdump |
| `comsvcs_minidump.yml` | Use different export from comsvcs or different DLL entirely | Add complementary rules for `dbghelp.dll` and other minidump-capable DLLs |
| `reg_save_sam.yml` | Use PowerShell or WMI to access registry instead of reg.exe | Add Sysmon EventID 13 (registry value set) rules in parallel |
| `certutil_download.yml` | Use a different LOLBin (curl.exe on Win11+, bitsadmin, etc.) | Rule is one of a family — see `bitsadmin_transfer.yml` |
| `mshta_remote.yml` | Host HTA on internal compromised resource | Combine with new-domain / DNS reputation telemetry |
| `bitsadmin_transfer.yml` | Use PowerShell's `Start-BitsTransfer` cmdlet | Add `pwsh`\-side rule for BITS module use |
| `ssh_brute_force.yml` | Slow-and-low (1 attempt per hour, multiple IPs) | Lower threshold + add IP-rotation aware correlation by username |
| `windows_logon_brute.yml` | Same as above + Kerberoasting alternative | Pair with Kerberos pre-auth failure rules |
| `linux_cron_persistence.yml` | Use systemd timer instead of cron | Add companion rule for `/etc/systemd/system/*.timer` writes |
| `ssh_authorized_keys.yml` | Persist via `~/.ssh/config` ProxyCommand instead | Extend selection to ssh config files |
| `session_persistence_post_reset.yml` | Refresh the session immediately after password change (would generate new `iat`) | Requires session-store invalidation, not just token revocation, to fully close |

* * *

## Testing & validation

Rules were validated against the Sigma specification. To test:

```bash
pip install sigma-cli
sigma check sigma-rules/
sigma convert -t splunk sigma-rules/credential-access/mimikatz_behavioral.yml
```

For end-to-end testing, the [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) project provides parameterized adversary simulations that trigger most of the rules above.

* * *

## References

- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma-specification)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [GTFOBins (Linux equivalent)](https://gtfobins.github.io/)

* * *

## Contact

- **HackerOne:** [@byteoverride](https://hackerone.com/byteoverride)
- **GitHub:** [@byteoverride](https://github.com/byteoverride)
