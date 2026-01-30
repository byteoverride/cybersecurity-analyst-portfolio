# cybersecurity-analyst-portfolio
This is my cybersecurity analyst learning  Journey of 2026 from january to October 
### Month 1: Network Traffic Analysis (NTA)

- [ ] Week 1: Wireshark & Protocols.\*\*
    
    - [ ] *Study:* HTB Academy "Network Traffic Analysis" module.
    - [ ] *Lab:* Capture your own web browsing traffic. Identify the 3-way handshake and SSL Hello.
    - [ ] *Deliverable:* A diagram of a TCP Handshake mapped to specific packet numbers in your capture.
- [ ] Week 2: HTTP & DNS Inspection.\*\*
    
    - [ ] *Study:* HTB Academy "Protocols" module. Focus on HTTP methods (GET/POST) and DNS record types.
    - [ ] *Lab:* Malware Traffic Analysis (Exercise 1).
    - [ ] *Deliverable:* List all unique User-Agents found in the sample.
- [ ] Week 3: Identifying C2 & Beacons.\*\*
    
    - [ ] *Study:* Analyzing HTTPS traffic without decryption (JA3 fingerprints basics).
    - [ ] *Lab:* Malware Traffic Analysis (Exercise 2 & 3).
    - [ ] *Deliverable:* Isolate the specific IP address of the C2 server in the lab.
- [ ] Week 4: Month 1 Capstone.\*\*
    
    - [ ] *Challenge:* PacketDetective Lab**.
    - [ ] *Task:* Solve the lab.
    - [ ] *Deliverable:* A 1-page Incident Report detailing the attacker's IP, tools used, and timeline.

### Month 2: Windows Internals

- [ ] Week 5: Windows Event Logs Core.\*\*
    
    - [ ] *Study:* HTB "Windows Event Logs". Memorize IDs: 4624 (Logon), 4625 (Fail), 4688 (Process).
    - [ ] *Lab:* Generate a failed login on your PC. Find the log.
    - [ ] *Deliverable:* A filter query that shows only failed logins from external IPs (simulation).
- [ ] Week 6: Sysmon & Powershell.\*\*
    
    - [ ] *Study:* HTB "Sysmon". Event ID 1 (Process Create) vs 4688.
    - [ ] *Lab:* Install Sysmon on a VM. Run a harmless PowerShell script.
    - [ ] *Deliverable:* The Sysmon log entry showing the `ParentImage` (what launched PowerShell?).
- [ ] Week 7: Active Directory Basics.\*\*
    
    - [ ] *Study:* HTB "Introduction to Active Directory". Focus on Kerberos.
    - [ ] *Lab:* Analyze a PCAP of a Kerberoasting attack (sample online).
    - [ ] *Deliverable:* Explain "Service Principal Names" (SPN) in one paragraph.
- [ ] Week 8: Month 2 Capstone.\*\*
    
    - [ ] *Challenge:* **Atomic Red Team**.
    - [ ] *Task:* Run `T1003` (Credential Dumping) on a test VM.
    - [ ] *Deliverable:* Screenshots of the exact logs that caught this activity.

### Month 3: Linux Forensics

- [ ] Week 9: Linux Structure & Auth.\*\*
    
- [ ] *Study:* HTB "Linux Fundamentals". Focus on `/var/log/auth.log` and `/var/log/syslog`.
    
- [ ] *Lab:* Create a new user, `sudo` to root, then delete the user.
    
- [ ] *Deliverable:* The log trail that proves the deleted user existed.
    
- [ ] **Week 10: Persistence Mechanisms.**
    
- [ ] *Study:* Cron jobs, SSH keys (`authorized_keys`), `.bashrc`.
    
- [ ] *Lab:* Create a malicious Cron job that runs `ping` every minute.
    
- [ ] *Deliverable:* Find the Cron job using only the command line (`grep`).
    
- [ ] **Week 11: Linux Processes.**
    
- [ ] *Study:* `ps aux`, `/proc` filesystem.
    
- [ ] *Lab:* Hide a process (rename a binary). Find it using `ps`.
    
- [ ] *Deliverable:* A command sheet for investigating a slow Linux server.
    
- [ ] **Week 12: Month 3 Capstone.**
    
- [ ] *Challenge:* **HTB Sherlock "OpTinselTrace"**.
    
- [ ] *Task:* Solve the Sherlock.
    
- [ ] *Deliverable:* A write-up explaining how the attacker moved laterally.
    

* * *

## PHASE 2: DETECTION ENGINEERING (SIEM & SIGMA)

**Focus:** Turning manual hunting into automated rules.

### Month 4: The SIEM

- [ ] Week 13: ELK/Splunk Setup.\*\*
    
- [ ] *Study:* HTB "Introduction to SIEM".
    
- [ ] *Lab:* Set up a free Splunk or ELK instance.
    
- [ ] *Deliverable:* A screenshot of your instance receiving data.
    
- [ ] Week 14: Search Languages (SPL/KQL).\*\*
    
- [ ] *Study:* Filtering, stats, and visualization commands.
    
- [ ] *Lab:* Ingest Month 2 logs. Visualize "Logins per Hour".
    
- [ ] *Deliverable:* A saved query that alerts on >5 failed logins in 1 minute.
    
- [ ] Week 15: Log Parsing.\*\*
    
- [ ] *Study:* JSON parsing, extracting fields.
    
- [ ] *Lab:* Parse a custom application log.
    
- [ ] *Deliverable:* Turn a raw text log into a searchable field format.
    
- [ ] Week 16: Month 4 Capstone.\*\*
    
- [ ] *Challenge:* Build a "Brute Force Dashboard".
    
- [ ] *Task:* Visualize Source IP, Target User, and Count.
    
- [ ] *Deliverable:* A working dashboard screenshot.
    

### Month 5: Sigma Rules

- [ ] Week 17: Sigma Structure.\*\*
    
- [ ] *Study:* HTB "Sigma". YAML syntax.
    
- [ ] *Lab:* Translate a Splunk query into a Sigma rule.
    
- [ ] *Deliverable:* Your first valid `.yml` rule.
    
- [ ] Week 18: Mapping to MITRE.\*\*
    
- [ ] *Study:* MITRE ATT&CK Matrix.
    
- [ ] *Lab:* Map 3 past Sherlocks to MITRE T-Codes.
    
- [ ] *Deliverable:* A list of T-Codes you have successfully investigated.
    
- [ ] Week 19: Detection Logic.\*\*
    
- [ ] *Study:* "Pyramid of Pain". Writing robust rules (behavior vs hash).
    
- [ ] *Lab:* Write a rule for `Mimikatz` that doesn't use the word "Mimikatz".
    
- [ ] *Deliverable:* A rule based on command line flags or memory access.
    
- [ ] Week 20: Month 5 Capstone.\*\*
    
- [ ] *Challenge:* **Github Portfolio Init**.
    
- [ ] *Task:* Upload 5 original Sigma rules to Github.
    
- [ ] *Deliverable:* Link to your repository.
    

### Month 6: Threat Intel

- [ ] Week 21: Intel Sources.\*\*
    
- [ ] *Study:* HTB "Threat Intelligence".
    
- [ ] *Lab:* Subscribe to 3 CTI feeds (e.g., AlienVault OTX).
    
- [ ] *Deliverable:* A summary of the top threat actor of the week.
    
- [ ] Week 22: Yara Rules.\*\*
    
- [ ] *Study:* Writing Yara for file scanning.
    
- [ ] *Lab:* Write a Yara rule to detect a specific string in a binary.
    
- [ ] *Deliverable:* A working Yara rule.
    
- [ ] Week 23: Pivoting.\*\*
    
- [ ] *Study:* Using VirusTotal and Whois to find attacker infrastructure.
    
- [ ] *Lab:* Take a malicious IP, find the domain, find the registrant.
    
- [ ] *Deliverable:* An infrastructure map of a known campaign.
    
- [ ] Week 24: Month 6 Capstone.\*\*
    
- [ ] *Challenge:* **Threat Profile**.
    
- [ ] *Task:* Write a 3-page report on a specific APT group.
    
- [ ] *Deliverable:* The PDF report.
    

* * *

## PHASE 3: INCIDENT RESPONSE & CDSA (THE EXAM)

**Focus:** Full scope kill-chain analysis and professional reporting.

### Month 7: Forensics Deep Dive

- [ ] Week 25: Disk Forensics (KAPE).\*\*
    
- [ ] *Study:* HTB "Windows Forensics".
    
- [ ] *Lab:* Use KAPE to collect artifacts from a VM.
    
- [ ] Week 26: Registry & MFT.\*\*
    
- [ ] *Study:* UserAssist, ShimCache, AmCache.
    
- [ ] *Lab:* Determine what programs were executed on a machine.
    
- [ ] Week 27: Memory Forensics.\*\*
    
- [ ] *Study:* Volatility 3 usage.
    
- [ ] *Lab:* Find injected code in a memory dump.
    
- [ ] Week 28: Timeline Analysis.\*\*
    
- [ ] *Challenge:* **HTB Sherlock (Hard)**.
    
- [ ] *Deliverable:* A Master Timeline CSV (Time | Source | Action).
    

### Month 8: The CDSA Sprint

- [ ] Week 29: Review - Incident Handling.\*\*
    
- [ ] *Focus:* Review HTB "Incident Handling Process".
    
- [ ] Week 30: Review - Analysis Phase.\*\*
    
- [ ] *Focus:* Re-do any weak modules.
    
- [ ] Week 31: Report Writing Drill.\*\*
    
- [ ] *Task:* Write a report for a Sherlock you already solved. Make it better.
    
- [ ] Week 32: Mock Exam.\*\*
    
- [ ] *Task:* Set aside a weekend. Do a difficult investigation in 24h. Write the report.
    

### Month 9: Certification

- [ ] Week 33: Final Polish.\*\*
- [ ] Week 34: EXAM ATTEMPT.\*\*
- [ ] Week 35: Rest & Recovery.\*\*
- [ ] Week 36: Portfolio Update (Add redacted exam report structure).\*\*

* * *
