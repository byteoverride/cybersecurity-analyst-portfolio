# THE 9-MONTH LOCKIN PLAN
## Restructured: Months 1-9 (Free Resources Edition)
**byteoverride |  2026**
**Hardware: 32GB RAM / Ryzen 7 8845H / 1TB SSD — Full local lab capability**

---

## FREE RESOURCE STACK

| Resource | What You Get Free | URL |
|----------|------------------|-----|
| **TryHackMe** | 390+ free rooms (Splunk, Sigma, YARA, Sysmon, MITRE, IR) | github.com/winterrdog/tryhackme-free-rooms |
| **LetsDefend** | SOC simulator, free courses (SIEM 101, CTI, YARA, MITRE), limited SOC alerts | letsdefend.io |
| **CyberDefenders** | Free blue team CTF challenges (WebStrike, DanaBot, RE101, etc.) browser-based | cyberdefenders.org |
| **Blue Team Labs Online** | Free tier gamified defensive challenges | blueteamlabs.online |
| **Splunk Free** | 500MB/day indexing, no expiry, full search capability | splunk.com |
| **Splunk Academic Alliance** | Full training catalog + cert discounts with .edu email — **apply with ISBAT email** | splunk.com/academic-alliance |
| **Elastic/ELK** | Fully open-source, run locally via Docker | elastic.co/training/free |
| **SigmaHQ** | Open-source Sigma rules repo + pySigma CLI | github.com/SigmaHQ/sigma |
| **AlienVault OTX** | Free threat intel feeds, IOC sharing | otx.alienvault.com |
| **VirusTotal** | Free tier with API access, VT Graph for infrastructure mapping | virustotal.com |
| **AbuseIPDB** | Free IP reputation lookups | abuseipdb.com |
| **MalwareBazaar** | Free malware sample database (abuse.ch) | bazaar.abuse.ch |
| **KAPE** | Free triage collection tool | kroll.com |
| **EZTools** | Eric Zimmerman's free Windows forensics tools | ericzimmerman.github.io |
| **Volatility 3** | Free memory forensics framework | github.com/volatilityfoundation/volatility3 |
| **MemLabs** | Free memory forensics practice dumps | github.com/stuxnet999/MemLabs |
| **Atomic Red Team** | Free adversary emulation library | github.com/redcanaryco/atomic-red-team |
| **13Cubed** | Free forensics video walkthroughs (YouTube) | youtube.com/@13Cubed |
| **AWS Free Tier** | 12 months free (EC2, S3, CloudTrail, IAM) | aws.amazon.com/free |
| **Malware Traffic Analysis** | Free PCAP exercises with answers | malware-traffic-analysis.net |

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
    

---

# PHASE 2: DETECTION ENGINEERING (SIEM & SIGMA)
**Focus:** Turn manual hunting into automated detection. Build a local SOC lab that mirrors real-world environments.

---

## Month 4: The SIEM (Local Lab Build)
*Build your own SOC — Splunk Free + ELK on your Ryzen 7*

### Week 13: Splunk Setup & Fundamentals

**Study:**
- Splunk Fundamentals 1 (free on splunk.com/training/free-courses)
- TryHackMe "Splunk: Basics" room (free)
- LetsDefend "SIEM 101" course (free tier)

**Labs:**
1. Install Splunk Free on your machine (Docker or native Linux install). Configure it to receive data on port 9997.
2. Forward your local Linux logs to Splunk: `/var/log/auth.log`, `/var/log/syslog`, `/var/log/apache2/access.log` (install Apache if needed).
3. TryHackMe "Splunk: Basics" — complete all tasks in the free room. Learn the Splunk Bar, Search & Reporting app, and data ingestion workflow.
4. Run `hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://localhost` against your own machine (or a test VM). Watch the failed login events appear in Splunk in real time.
5. Write your first SPL query: `index=main sourcetype=syslog "Failed password" | stats count by src_ip | sort -count` — identify which IPs are brute-forcing.
6. LetsDefend "SOC Fundamentals" course — complete all modules in the free tier. Understand SOC structure, alert triage workflow, and the SOAR concept.

**Deliverables:**
- [ ] Screenshot of Splunk receiving live data from your system
- [ ] Completed TryHackMe "Splunk: Basics" room
- [ ] Completed LetsDefend "SOC Fundamentals"
- [ ] Your first working SPL query saved in Splunk

---

### Week 14: SPL Deep Dive & Visualization

**Study:**
- Splunk Fundamentals 2 (free on splunk.com)
- TryHackMe "Splunk: Exploring SPL" (free room)
- Splunk docs: Search Reference (docs.splunk.com)

**Labs:**
1. Ingest your Month 2/3 Windows Event Logs into Splunk (export from Event Viewer as .evtx, use Splunk's Windows Event Log input or convert with `evtx_dump`).
2. Write SPL queries for each of these and save them:
   - Failed logins: `index=main EventCode=4625 | stats count by Account_Name, Source_Network_Address`
   - Successful logins from unusual IPs: `index=main EventCode=4624 Logon_Type=10 | stats count by Source_Network_Address`
   - Process creation: `index=main EventCode=4688 | table _time, Creator_Process_Name, New_Process_Name, Account_Name`
   - PowerShell execution: `index=main EventCode=1 Image="*powershell.exe" | table _time, CommandLine, ParentImage`
3. Build a dashboard with 4 panels: "Failed Logins Over Time" (timechart), "Top Attacking IPs" (bar chart), "Logon Types Distribution" (pie chart), "Recent Process Creations" (table).
4. TryHackMe "Splunk: Exploring SPL" — practice field extraction, eval, transaction, and subsearch commands.
5. Set up a Splunk alert: trigger when >5 failed logins occur within 60 seconds from the same source IP. Test it by running Hydra again.
6. Export your dashboard as a PDF and save the XML config.

**Deliverables:**
- [ ] 4+ saved SPL queries covering different Event IDs
- [ ] Working 4-panel dashboard with real data
- [ ] Alert rule that fires on brute force detection
- [ ] Completed TryHackMe "Splunk: Exploring SPL"

---

### Week 15: ELK Stack Setup & Log Parsing

**Study:**
- Elastic free training (elastic.co/training/free) — "Getting Started with Elasticsearch"
- TryHackMe "ELK" room (free)
- TryHackMe "Investigating with ELK 101" (free)

**Labs:**
1. Deploy ELK stack via Docker on your machine using `docker-elk` by deviantony (GitHub). Verify Kibana is accessible at `localhost:5601`.
2. Create a Logstash pipeline that ingests auth.log and parses it into structured fields (timestamp, hostname, process, message, source_ip). Use grok patterns.
3. Ingest the same logs you put into Splunk. Write the KQL equivalent of your SPL queries:
   - Failed logins: `event.action: "failed_login" | top 10 source.ip`
   - Process creation: filter by `event.code: 4688`
4. Build a Kibana dashboard mirroring your Splunk dashboard. Compare the experience — know both platforms because job postings will ask for one or the other.
5. TryHackMe "ELK" — complete the room. Practice Kibana discover, lens visualizations, and saved searches.
6. TryHackMe "Investigating with ELK 101" — investigate security events using Kibana.
7. Install Filebeat on your local machine and configure it to ship logs to your ELK stack automatically. This is how production SOCs work.
8. Parse a custom JSON application log (create a fake one with timestamps, user IDs, actions, and status codes) through Logstash and visualize it in Kibana.

**Deliverables:**
- [ ] ELK stack running locally with parsed fields
- [ ] Same "failed logins" query written in both SPL and KQL (side-by-side comparison doc for portfolio)
- [ ] Kibana dashboard with 4+ panels
- [ ] Completed both TryHackMe ELK rooms
- [ ] Filebeat shipping logs automatically

---

### Week 16: Month 4 Capstone — Brute Force Dashboard + SOC Alert Triage

**Study:**
- LetsDefend SOC alerts (free tier) — understand the alert triage workflow
- TryHackMe "Incident Handling with Splunk" (free room)

**Labs:**
1. **Brute Force Simulation Lab**: Set up a vulnerable SSH server on a VM. Use Hydra and Medusa to simulate brute force attacks from multiple IPs. Forward all logs to Splunk.
2. Build the definitive "Brute Force Detection Dashboard" in Splunk:
   - Panel 1: Source IP heatmap (geolocation if possible using `iplocation` command)
   - Panel 2: Target User accounts (bar chart)
   - Panel 3: Attempt count over time (timechart)
   - Panel 4: Success vs. Failure ratio (pie chart)
   - Panel 5: Raw events table (sortable)
3. Create the same dashboard in Kibana/ELK to prove you can work in both.
4. TryHackMe "Incident Handling with Splunk" — work through the full incident using SPL queries.
5. LetsDefend SOC Alert Triage — triage **5 alerts** in the SOC simulator. For each alert: classify as true/false positive, document your reasoning, identify the MITRE technique, and write a 1-paragraph summary.
6. **BONUS lab**: Install Wazuh (open-source, free) on your machine alongside ELK. Wazuh adds endpoint detection (like a free EDR). Forward Wazuh alerts to your ELK stack. This is a resume-worthy setup.
7. Write a 1-page "SOC Lab Architecture" document describing your setup: what tools you run, how data flows, what you can detect. Push to GitHub.

**Deliverables:**
- [ ] Brute Force Dashboard in Splunk (screenshot + exported XML config)
- [ ] Brute Force Dashboard in Kibana (screenshot)
- [ ] Completed TryHackMe "Incident Handling with Splunk"
- [ ] 5 LetsDefend alert triage write-ups
- [ ] SOC Lab Architecture doc on GitHub
- [ ] (Bonus) Wazuh integrated with ELK

---

## Month 5: Sigma Rules & Detection Engineering
*Write detection rules that work across any SIEM*

### Week 17: Sigma Rule Structure & Syntax

**Study:**
- SigmaHQ GitHub wiki — read the full specification (github.com/SigmaHQ/sigma/wiki)
- TryHackMe "Sigma" room (free)
- Uncoder.io (free online Sigma converter)

**Labs:**
1. Install pySigma CLI: `pip install sigma-cli`. Clone the SigmaHQ repo: `git clone https://github.com/SigmaHQ/sigma.git`
2. Read 10 existing Sigma rules from the SigmaHQ repo (pick from `rules/windows/`). For each one, identify: title, logsource, detection logic, level, MITRE tags. Write notes on what patterns you see.
3. TryHackMe "Sigma" room — complete all tasks. Learn rule anatomy, sigmac conversion, and Uncoder.io.
4. Write your first Sigma rule from scratch: detect SSH brute force (>5 failed logins from same IP in 60 seconds on Linux auth.log). Convert it to SPL using pySigma, then paste it into Splunk and verify it fires against your Month 4 brute force data.
5. Write a second Sigma rule: detect PowerShell downloading a file (`Invoke-WebRequest`, `wget`, `curl` in PowerShell command line). Convert to both SPL and KQL.
6. Write a third Sigma rule: detect a new user being created on Linux (`useradd` or `adduser` in auth.log). Convert and test.
7. Use Uncoder.io to convert one SigmaHQ community rule to ElastAlert format. Deploy it in your ELK stack.

**Deliverables:**
- [ ] 3 original Sigma rules written and tested
- [ ] Proof of conversion to SPL and KQL (screenshots of queries running in Splunk and Kibana)
- [ ] Completed TryHackMe "Sigma" room
- [ ] Notes on 10 SigmaHQ community rules (what they detect, how they work)

---

### Week 18: MITRE ATT&CK Mapping

**Study:**
- MITRE ATT&CK website (attack.mitre.org) — explore the Enterprise matrix
- TryHackMe "MITRE" room (free)
- LetsDefend "MITRE ATT&CK" course (free tier)
- TryHackMe "ATT&CK Framework" room (free)

**Labs:**
1. TryHackMe "MITRE" room — complete all tasks. Learn to navigate the matrix, understand tactics vs. techniques, and use ATT&CK Navigator.
2. LetsDefend "MITRE ATT&CK" course — complete the free tier modules.
3. Go back to your Month 1–3 labs. Map **5 exercises** to MITRE T-Codes:
   - Month 1 C2 beacon identification → T1071 (Application Layer Protocol)
   - Month 2 credential dumping (Atomic Red Team T1003) → T1003 (OS Credential Dumping)
   - Month 3 cron job persistence → T1053.003 (Scheduled Task/Job: Cron)
   - Month 3 SSH authorized_keys persistence → T1098.004 (Account Manipulation: SSH Authorized Keys)
   - Month 3 renamed binary detection → T1036.003 (Masquerading: Rename System Utilities)
4. For each of the 5 mappings, write a Sigma rule that detects the technique. Test at least 2 of them in your Splunk/ELK lab.
5. Install ATT&CK Navigator (GitHub, free) and create a heatmap of techniques you can now detect. Export it as a PNG for your portfolio.
6. CyberDefenders "WebStrike" challenge (free) — investigate a web attack, then map every step of the attacker's kill chain to MITRE T-Codes.

**Deliverables:**
- [ ] Mapping table: Exercise | Technique | T-Code | Sigma Rule Filename | Detection Logic
- [ ] 5 Sigma rules (one per mapping), tested in your SIEM
- [ ] ATT&CK Navigator heatmap PNG
- [ ] Completed TryHackMe "MITRE" room
- [ ] Completed LetsDefend "MITRE ATT&CK" course
- [ ] CyberDefenders "WebStrike" write-up with kill chain mapping

---

### Week 19: Detection Logic — Pyramid of Pain & Behavior-Based Rules

**Study:**
- David Bianco's "Pyramid of Pain" blog (detect-respond.blogspot.com, free)
- TryHackMe "Tactical Detection" room (free)
- TryHackMe "Pyramid of Pain" room (free)
- Read: "The Importance of Detection Engineering" by Florian Roth (creator of Sigma)

**Labs:**
1. TryHackMe "Pyramid of Pain" room — understand why behavioral detection beats hash/IP-based detection.
2. TryHackMe "Tactical Detection" room — practice converting public IOCs into Sigma rules and deploying them.
3. **Mimikatz Behavioral Detection Lab**: Write a Sigma rule for Mimikatz that does NOT use the word "Mimikatz". Detect based on:
   - Command-line flags: `sekurlsa::logonpasswords`, `lsadump::sam`, `kerberos::golden`
   - LSASS access: Sysmon Event ID 10 with TargetImage `*lsass.exe` and CallTrace containing `UNKNOWN`
   - Process creation: Sysmon Event ID 1 with suspicious parent-child relationships
4. **Credential Dumping Variants Lab**: Write Sigma rules for 3 different credential dumping methods that aren't Mimikatz:
   - `procdump.exe -ma lsass.exe` (Sysinternals abuse)
   - `comsvcs.dll` MiniDump via `rundll32` (LOLBin technique)
   - `reg save HKLM\SAM` / `reg save HKLM\SYSTEM` (registry-based)
5. **Living off the Land (LOLBin) Lab**: Write Sigma rules for 3 common LOLBin abuse patterns:
   - `certutil.exe -urlcache -split -f` (file download)
   - `mshta.exe` executing remote HTA (script execution)
   - `bitsadmin /transfer` (file download via BITS)
6. Run Atomic Red Team tests for T1003.001 (LSASS Memory), T1105 (Ingress Tool Transfer), and T1218.005 (Mshta) on a Windows test VM. Verify your Sigma rules detect them in your Splunk/ELK instance.
7. Study the SigmaHQ `rules/windows/process_creation/` directory. Pick 5 rules and analyze their detection logic — what makes them robust vs. fragile?

**Deliverables:**
- [ ] Behavior-based Mimikatz Sigma rule (no tool name, no hash)
- [ ] 3 credential dumping variant Sigma rules
- [ ] 3 LOLBin detection Sigma rules
- [ ] Atomic Red Team test results showing rules firing
- [ ] Completed both TryHackMe rooms
- [ ] Analysis notes on 5 SigmaHQ community rules

---

### Week 20: Month 5 Capstone — GitHub Portfolio Push + Purple Team Bridge

**Study:**
- Review your own  account takeover finding from bug bounty research
- Think: what would the detection look like from the defender's side?
- Read about session fixation/persistence detection patterns

**Labs:**
1. **Portfolio Push**: Organize all your Sigma rules into a clean GitHub structure:
   ```
   sigma-rules/
   ├── README.md (overview, MITRE heatmap, rule descriptions)
   ├── credential-access/
   │   ├── mimikatz_behavioral.yml
   │   ├── procdump_lsass.yml
   │   ├── comsvcs_minidump.yml
   │   └── reg_save_sam.yml
   ├── defense-evasion/
   │   ├── certutil_download.yml
   │   ├── mshta_remote.yml
   │   └── bitsadmin_transfer.yml
   ├── brute-force/
   │   ├── ssh_brute_force.yml
   │   └── windows_logon_brute.yml
   ├── persistence/
   │   ├── linux_cron_persistence.yml
   │   └── ssh_authorized_keys.yml
   └── purple-team/
       └── session_persistence_post_reset.yml
   ```
2. **Purple Team Rule (Your Differentiator)**: Write a Sigma rule that detects the session persistence pattern you found in the Hover ATO — detecting cookie reuse after password reset, concurrent sessions from different IPs post-credential change, or session tokens that survive password resets. Map it to T1550.004 (Web Session Cookie) or T1078 (Valid Accounts).
3. Write a companion blog-style markdown document explaining the purple team rule: "I found this vulnerability as an attacker. Here's how I'd detect it as a defender." This goes in your portfolio.
4. LetsDefend — triage **3 more SOC alerts**. Include MITRE mapping in your triage notes.
5. CyberDefenders "DanaBot" challenge (free) — investigate C2 traffic and write a Sigma rule for the network indicators you find.
6. **Self-Assessment**: Review all Sigma rules you've written. For each one, ask: "Could an attacker evade this by changing one thing?" If yes, improve the rule.

**Deliverables:**
- [ ] GitHub repo with 10+ organized Sigma rules
- [ ] Purple team Sigma rule (session persistence detection) — **this is your portfolio centerpiece**
- [ ] Blog-style write-up: "From Bug Bounty Finding to Detection Rule"
- [ ] CyberDefenders "DanaBot" write-up + Sigma rule
- [ ] 3 LetsDefend alert triage write-ups
- [ ] All rules self-assessed for evasion gaps

---

## Month 6: Threat Intelligence + Cloud Security
*The gap in the original plan — filled*

### Week 21: Intel Sources & CTI Feeds

**Study:**
- LetsDefend "Cyber Threat Intelligence" course (free tier)
- TryHackMe "Threat Intelligence Tools" room (free)
- TryHackMe "OpenCTI" room (free)
- TryHackMe "MISP" room (free)

**Labs:**
1. Create accounts on all three: AlienVault OTX, AbuseIPDB, VirusTotal.
2. TryHackMe "Threat Intelligence Tools" — complete the room. Practice using VirusTotal, URLScan, AbuseIPDB, and Hybrid Analysis.
3. TryHackMe "OpenCTI" room — understand how CTI platforms aggregate and correlate threat data.
4. TryHackMe "MISP" room — learn how Malware Information Sharing Platform works for IOC sharing.
5. Subscribe to 3 CTI feeds on AlienVault OTX. Monitor them for 1 week. Pick the most active threat campaign and analyze it:
   - What IOCs are associated (hashes, IPs, domains)?
   - What MITRE techniques does it use?
   - What sectors/regions are targeted?
   - What malware families are involved?
6. Use AbuseIPDB to look up 10 suspicious IPs from your OTX feed. Cross-reference with VirusTotal.
7. Write a 1-page threat summary: Campaign name, actor attribution (if known), IOCs, MITRE techniques, and recommended detections (Sigma/YARA).
8. **Integration Lab**: Take 3 IOCs from your research and create Splunk searches to detect them in your SIEM. Add them as saved searches.

**Deliverables:**
- [ ] Completed TryHackMe rooms: "Threat Intelligence Tools", "OpenCTI", "MISP"
- [ ] Completed LetsDefend "Cyber Threat Intelligence"
- [ ] 1-page threat campaign summary
- [ ] IOC-based Splunk searches saved in your lab
- [ ] Cross-reference report (OTX → AbuseIPDB → VirusTotal) for 10 IPs

---

### Week 22: YARA Rules for File Detection

**Study:**
- LetsDefend "Mastering YARA for Malware Detection" course (free tier)
- TryHackMe "YARA" room (free)
- TryHackMe "Yara" (the original room, free)
- YARA documentation (virustotal.github.io/yara)
- yarGen documentation (GitHub)

**Labs:**
1. Install YARA on your Linux machine: `sudo apt install yara`. Install yarGen: `pip install yargen`.
2. TryHackMe "YARA" room — complete all tasks. Write basic rules matching strings, hex patterns, and conditions.
3. LetsDefend "Mastering YARA for Malware Detection" — complete the free tier modules.
4. Download 5 malware samples from MalwareBazaar (bazaar.abuse.ch). **Do this in an isolated VM or container.**
5. **Rule 1 — String Detection**: Write a YARA rule that detects a specific C2 domain or user-agent string found in one of your malware samples. Use `strings` command to extract strings first.
6. **Rule 2 — PE Header Detection**: Write a YARA rule that detects a PE file with suspicious imports (e.g., `VirtualAlloc`, `CreateRemoteThread`, `WriteProcessMemory` together — classic injection indicators).
7. **Rule 3 — Byte Pattern Detection**: Use a hex editor to identify a unique byte sequence in a malware sample. Write a YARA rule using hex strings `{ 4D 5A ... }`.
8. **Rule 4 — File Size + Entropy**: Write a YARA rule that flags PE files under 100KB with high entropy sections (common in packed malware). Use YARA's `math.entropy` module.
9. **Rule 5 — yarGen Auto-Generation**: Use yarGen to automatically generate a YARA rule for one of your samples, then manually review and improve it.
10. Test all 5 rules against your malware sample set AND against a clean file directory to verify zero false positives.
11. Scan a directory of 100+ benign files (e.g., `/usr/bin/`) with your rules to validate they don't false positive on legitimate software.

**Deliverables:**
- [ ] 5 working YARA rules pushed to GitHub (organized in `yara-rules/` folder)
- [ ] Test results: true positive matches + false positive rate
- [ ] Completed TryHackMe "YARA" room
- [ ] Completed LetsDefend "Mastering YARA for Malware Detection"
- [ ] yarGen output reviewed and improved

---

### Week 23: Cloud Security Fundamentals (NEW — was missing from original plan)

**Study:**
- TryHackMe "Intro to Cloud Security" (free)
- TryHackMe "AWS S3" room (free)
- AWS CloudTrail documentation (free)
- OWASP Cloud Security Top 10

**Labs:**
1. Create an AWS Free Tier account. Enable CloudTrail logging in your default region.
2. TryHackMe "Intro to Cloud Security" — understand shared responsibility model, cloud attack surfaces.
3. **S3 Misconfiguration Lab**: Create an S3 bucket. Intentionally set it to public read. Upload a test file. Then:
   - Find the public access evidence in CloudTrail logs
   - Find the S3 bucket policy that allows public access
   - Fix it (set to private) and verify the CloudTrail log shows the remediation
4. **IAM Privilege Escalation Lab**: Create an IAM user with overly permissive policies (e.g., `iam:*`). Then:
   - Use that user to create admin credentials
   - Find the evidence in CloudTrail (`CreateAccessKey`, `AttachUserPolicy` events)
   - Write a detection query for this pattern
5. **CloudTrail Log Analysis Lab**: Download CloudTrail logs as JSON. Ingest them into your local Splunk or ELK instance. Write queries to detect:
   - `ConsoleLogin` from unusual geographic locations
   - `StopLogging` events (attacker disabling CloudTrail — T1562.008)
   - Root account usage
   - Access key creation for IAM users
6. Write a Sigma rule for CloudTrail `StopLogging` detection. This is a real-world detection that SOC teams deploy.
7. **Bug Bounty Context**: Write a 1-page document on the top 5 cloud misconfigurations you'd test for in a bug bounty scope that includes cloud assets (S3 buckets, open Elasticsearch instances, exposed .env files, misconfigured IAM, public snapshots).

**Deliverables:**
- [ ] CloudTrail logs ingested into your SIEM
- [ ] 4+ CloudTrail detection queries (SPL or KQL)
- [ ] Sigma rule for CloudTrail `StopLogging`
- [ ] Completed TryHackMe cloud rooms
- [ ] Cloud misconfigurations cheat sheet for bug bounty
- [ ] Screenshots of your S3 misconfiguration → detection → remediation cycle

---

### Week 24: Month 6 Capstone — Threat Intelligence Report + Infrastructure Pivoting

**Study:**
- VirusTotal Graph documentation (free)
- WHOIS lookup tools (whois.domaintools.com, who.is)
- TryHackMe "Autopsy" room (free — for forensic investigation practice)

**Labs:**
1. **APT Research**: Pick a known APT group (choose one: Lazarus, APT29/Cozy Bear, Turla, FIN7, or Sandworm). Research using only free sources:
   - MITRE ATT&CK group page
   - AlienVault OTX pulses tagged to the group
   - VirusTotal searches for known malware hashes
   - Open-source vendor reports (Mandiant, CrowdStrike, Kaspersky — all publish free reports)
2. **Infrastructure Pivoting Lab**: Take a known malicious IP associated with your chosen APT. Pivot through:
   - WHOIS → find the domain registered to that IP
   - VirusTotal → find other files communicating with that domain
   - VirusTotal Graph → map the relationships visually (IP → domain → files → other IPs)
   - Passive DNS → find other domains that resolved to the same IP
3. Build a visual infrastructure map using VirusTotal Graph. Export it.
4. Write YARA rules for 2 malware samples associated with the APT.
5. Write Sigma rules for 2 TTPs commonly used by the APT.
6. CyberDefenders — complete 1 free network forensics challenge. Map findings to MITRE.
7. **Capstone Deliverable**: Write a 3-page APT Threat Profile PDF:
   - Page 1: Actor overview (origin, motivation, targeted sectors, active since when)
   - Page 2: TTPs mapped to MITRE ATT&CK with your Sigma/YARA rules
   - Page 3: Infrastructure map + IOCs table (hashes, IPs, domains)

**Deliverables:**
- [ ] 3-page APT Threat Profile (PDF or markdown, pushed to GitHub)
- [ ] VirusTotal Graph infrastructure map
- [ ] 2 APT-specific YARA rules
- [ ] 2 APT-specific Sigma rules
- [ ] CyberDefenders challenge write-up
- [ ] Infrastructure pivoting documentation (the chain: IP → domain → registrant → related assets)

---

# PHASE 3: INCIDENT RESPONSE & CDSA PREP
**Focus:** Full kill-chain analysis, professional forensics reporting, and CDSA exam readiness.

---

## Month 7: Forensics Deep Dive
*All tools are free — KAPE, EZTools, Volatility 3*

### Week 25: Disk Forensics with KAPE & EZTools

**Study:**
- KAPE documentation (kroll.com, free download)
- Eric Zimmerman's tools documentation (ericzimmerman.github.io)
- 13Cubed "Introduction to KAPE" (free YouTube)
- 13Cubed "Windows Forensics" playlist (free YouTube)

**Labs:**
1. Set up a Windows 10 VM in VirtualBox. Install Sysmon with SwiftOnSecurity config. Browse the web, install programs, create files — generate realistic artifacts.
2. Download and install KAPE on the VM. Run a triage collection targeting:
   - Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT)
   - Prefetch files
   - Event logs (.evtx)
   - MFT ($MFT)
   - AmCache
   - ShimCache
   - Jump Lists
   - Recent files (LNK files)
3. Transfer the KAPE output to your Linux analysis machine.
4. Parse artifacts with EZTools:
   - `MFTECmd.exe` → parse $MFT into CSV, identify recently created/modified files
   - `PECmd.exe` → parse Prefetch files, determine what programs executed and when
   - `EvtxECmd.exe` → parse event logs, filter for security-relevant events
   - `RECmd.exe` → parse registry hives, extract UserAssist entries
   - `AmcacheParser.exe` → identify installed programs and execution evidence
5. 13Cubed "Introduction to KAPE" walkthrough — follow along and compare your results.
6. Cross-reference findings: use MFT timestamps + Prefetch + AmCache to build a timeline of when a program was first installed, first executed, and last executed.
7. **Anti-Forensics Awareness Lab**: On the VM, run `cipher /w:C:` (wipe free space), delete prefetch files, clear event logs with `wevtutil cl Security`. Then run KAPE again and note what evidence remains vs. what was destroyed.

**Deliverables:**
- [ ] KAPE triage collection from your Windows VM
- [ ] Parsed output from at least 5 EZTools
- [ ] Cross-reference timeline (MFT + Prefetch + AmCache)
- [ ] Anti-forensics findings: what survived, what didn't
- [ ] Notes from 13Cubed walkthrough

---

### Week 26: Registry, MFT & Evidence of Execution

**Study:**
- 13Cubed "Windows Forensics" playlist — deep dive episodes (free YouTube)
- SANS DFIR cheat sheets (free PDFs from sans.org)
- CyberDefenders free forensics labs

**Labs:**
1. **UserAssist Deep Dive**: Parse UserAssist registry entries from your KAPE collection. UserAssist tracks GUI programs run by the user. Decode the ROT13-encoded program names. Identify: what programs ran, how many times, last execution timestamp.
2. **ShimCache/AppCompatCache Lab**: Parse ShimCache entries. These record program execution even after the program is deleted. Compare ShimCache findings with Prefetch — what does ShimCache catch that Prefetch misses?
3. **AmCache Investigation**: Parse AmCache.hve. Identify installed programs with their SHA1 hashes. Cross-reference the hashes with VirusTotal — are any of the programs flagged as malicious?
4. **MFT Timeline Lab**: Use `MFTECmd` to parse the $MFT. Filter for files created in the last 24 hours. Identify:
   - Files created in suspicious directories (`C:\Users\Public\`, `C:\ProgramData\`, temp folders)
   - Executable files (.exe, .dll, .ps1, .bat) created recently
   - Files with timestomped MACB timestamps (Created before Modified — indicator of tampering)
5. **USN Journal Lab**: Parse the $UsnJrnl (USN Journal) — this records file system changes. Identify file renames, deletions, and moves that might indicate cleanup activity.
6. CyberDefenders — complete **2 free forensics challenges**. Document your methodology for each.
7. Build a master "Windows Forensic Artifact Cheat Sheet" for your portfolio:
   - Artifact → Location → What it proves → Tool to parse → Survivability (does it survive reboot? deletion? anti-forensics?)

**Deliverables:**
- [ ] UserAssist analysis with decoded program names
- [ ] ShimCache vs. Prefetch comparison table
- [ ] AmCache hash cross-reference with VirusTotal
- [ ] MFT timeline filtered for suspicious files
- [ ] USN Journal analysis
- [ ] 2 CyberDefenders forensics challenge write-ups
- [ ] Windows Forensic Artifact Cheat Sheet (pushed to GitHub)

---

### Week 27: Memory Forensics with Volatility 3

**Study:**
- Volatility 3 documentation (volatilityfoundation.org)
- 13Cubed "Introduction to Memory Forensics" (free YouTube)
- MemLabs challenges (github.com/stuxnet999/MemLabs)
- TryHackMe "Volatility" room (free)

**Labs:**
1. Install Volatility 3: `pip install volatility3`. Verify it runs: `vol -h`.
2. Download MemLabs Lab 1 (beginner difficulty). Analyze with Volatility 3:
   - `windows.pslist` — list all running processes. Identify suspicious ones.
   - `windows.pstree` — view parent-child relationships. Look for unusual parent processes.
   - `windows.cmdline` — extract command-line arguments. Look for encoded PowerShell, suspicious flags.
   - `windows.netscan` — identify network connections. Look for connections to known-bad IPs or unusual ports.
   - `windows.malfind` — detect injected code in process memory (RWX sections, MZ headers in non-image regions).
   - `windows.dlllist` — enumerate loaded DLLs per process.
   - `windows.handles` — list open handles (files, registry keys, mutexes).
3. Complete MemLabs Lab 2 and Lab 3 (escalating difficulty).
4. TryHackMe "Volatility" room — complete all tasks.
5. **Process Injection Detection Lab**: Create a memory dump of a Windows VM where you've run Atomic Red Team test T1055 (Process Injection). Use `windows.malfind` to find the injected code. Dump the injected region with `windows.memmap` and analyze the bytes.
6. **Network IOC Extraction Lab**: From a memory dump, extract all network connections. Cross-reference destination IPs with VirusTotal and AbuseIPDB. Write a brief intelligence report on what you found.
7. **Strings Analysis Lab**: Run `strings` on a memory dump and grep for:
   - URLs (`http://`, `https://`)
   - Email addresses
   - IP addresses (regex: `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
   - Suspicious commands (`powershell`, `cmd.exe`, `whoami`, `net user`)

**Deliverables:**
- [ ] MemLabs Labs 1–3 completed with write-ups
- [ ] Completed TryHackMe "Volatility" room
- [ ] Process injection detection report (malfind output + analysis)
- [ ] Network IOC extraction report with VirusTotal cross-reference
- [ ] Strings analysis findings from memory dump
- [ ] Volatility 3 cheat sheet for your portfolio

---

### Week 28: Month 7 Capstone — Full Investigation + Timeline Analysis

**Study:**
- Review all forensic techniques from Weeks 25–27
- Blue Team Labs Online free challenges
- CyberDefenders free challenges

**Labs:**
1. **The Big One**: Pick the hardest available free challenge from CyberDefenders or BTLO. This should combine multiple evidence types (disk image, memory dump, network capture, logs).
2. Conduct a full investigation using every skill you've built:
   - Disk: KAPE collection → EZTools parsing → artifact analysis
   - Memory: Volatility 3 → process analysis → injection detection → network IOCs
   - Network: Wireshark → protocol analysis → C2 identification
   - Logs: Splunk/ELK → event correlation → timeline building
3. Build a **Master Timeline** in CSV format:
   ```
   Timestamp | Source | Artifact | Action | Evidence | MITRE Technique
   ```
   Populate it with findings from ALL evidence types. Sort chronologically to tell the full story of the attack.
4. Write a **Professional Incident Report**:
   - Executive Summary (1 paragraph, non-technical)
   - Scope of Investigation
   - Key Findings (with evidence screenshots)
   - Attack Timeline (from your Master Timeline)
   - Indicators of Compromise (table: Type | Value | Context)
   - MITRE ATT&CK Mapping
   - Recommendations (containment, eradication, recovery, lessons learned)
5. Complete **1 additional free challenge** from a different platform (if you did CyberDefenders, do BTLO, or vice versa).
6. Write Sigma rules that would detect 3 key phases of the attack you investigated.

**Deliverables:**
- [ ] Master Timeline CSV
- [ ] Professional Incident Report (this is your portfolio showpiece)
- [ ] 2 investigation challenge write-ups
- [ ] 3 Sigma rules based on investigation findings
- [ ] All pushed to GitHub with proper README

---

## Month 8: CDSA Sprint & Catch-Up
*Review, report writing drills, and filling gaps*

### Week 29: Review — Incident Handling + Gap Assessment

**Study:**
- LetsDefend "Incident Response" course (free tier)
- TryHackMe "Incident Handling with Splunk" (review if not completed)
- TryHackMe "The Hive" room (free — SOAR/case management)
- Review ALL your Month 4–7 deliverables

**Labs:**
1. LetsDefend "Incident Response" course — complete the free tier modules.
2. TryHackMe "The Hive" room — understand case management and incident ticketing.
3. Triage **10 SOC alerts** on LetsDefend's simulator. For each, write:
   - Alert classification (True Positive / False Positive / Benign True Positive)
   - Evidence that supports your classification
   - MITRE technique identified
   - Recommended action
4. **Honest Self-Assessment**: Go through every week's deliverables from Months 4–7. Rate yourself 1–5 on each topic. Identify your 3 weakest areas.
5. Re-do the exercises you struggled with. If YARA was weak, write 3 more rules. If memory forensics was shaky, do another MemLab. If SPL queries were slow, run 20 queries in Splunk.
6. Speed drill: Open a past CyberDefenders challenge you already solved. Redo it from scratch. Time yourself. Your goal is to complete it in half the original time.

**Deliverables:**
- [ ] 10 LetsDefend alert triage write-ups
- [ ] Self-assessment matrix (topic | rating | gap | action taken)
- [ ] Completed gap-filling exercises
- [ ] Completed TryHackMe "The Hive"
- [ ] Speed drill results (time comparison)

---

### Week 30: Detection + Forensics Integration

**Study:**
- Re-read your own Sigma rules and YARA rules
- Review Volatility 3 and KAPE workflows
- TryHackMe "Retracted" room (free — multi-phase investigation)

**Labs:**
1. **Kill Chain Detection Map**: Take your best investigation from Month 7. For each phase of the attack, write a Sigma rule that would have detected it:
   - Initial Access → what log entry would trigger?
   - Execution → what process creation event?
   - Persistence → what registry change or scheduled task?
   - Lateral Movement → what authentication event from unusual source?
   - Exfiltration → what network anomaly?
2. Deploy all these Sigma rules in your Splunk/ELK lab. Run Atomic Red Team tests to simulate each phase. Verify your rules fire.
3. TryHackMe "Retracted" room — practice multi-phase investigation that connects detection with forensics.
4. **Detection Coverage Assessment**: Using your ATT&CK Navigator heatmap from Month 5, update it with all the new techniques you can now detect. How many techniques do you cover? What gaps remain?
5. Write a "Detection Playbook" document: For your top 10 Sigma rules, write a response playbook (If this rule fires → investigate X → check Y → escalate if Z).
6. CyberDefenders — complete 1 more free challenge. Focus on speed and methodology.

**Deliverables:**
- [ ] Kill chain detection map with Sigma rules for every phase
- [ ] Atomic Red Team validation results
- [ ] Updated ATT&CK Navigator heatmap
- [ ] Detection Playbook document (top 10 rules)
- [ ] CyberDefenders challenge write-up
- [ ] All pushed to GitHub

---

### Week 31: Report Writing Drill

**Study:**
- Read real incident reports: Mandiant M-Trends (free annual report), CrowdStrike Threat Report (free)
- Study report structure from published IR case studies
- TryHackMe "Summit" room (free — Pyramid of Pain capstone)

**Labs:**
1. Read at least 2 published incident reports from Mandiant or CrowdStrike. Take notes on: structure, language, how they present evidence, how they format timelines, what they include in recommendations.
2. **Report Rewrite Drill**: Take your best investigation from Month 7 and rewrite the report **from scratch**. Don't look at your original. Make it better:
   - Executive Summary: 1 paragraph a CEO could understand
   - Technical Findings: Evidence-backed, with screenshots
   - Timeline: Precise, chronological, every action timestamped
   - IOCs: Clean table format (Type | Value | Context | Confidence)
   - MITRE Mapping: Visual + text
   - Recommendations: Prioritized (immediate / short-term / long-term)
3. Time yourself. Your target: complete the full report in under 4 hours. The CDSA exam is time-pressured.
4. TryHackMe "Summit" room — capstone exercise applying Pyramid of Pain concepts.
5. **Peer Review**: If you have a study partner or Discord community, share your report and ask for feedback. If not, set it aside for 48 hours, then review it yourself with fresh eyes. Look for: unclear language, unsupported claims, missing evidence, formatting inconsistencies.
6. Write an "Incident Report Template" in markdown that you can reuse for every future investigation. Push to GitHub.

**Deliverables:**
- [ ] Rewritten incident report (polished, professional grade)
- [ ] Report completion time logged (target: <4 hours)
- [ ] Incident Report Template on GitHub
- [ ] Notes from published IR report analysis
- [ ] Completed TryHackMe "Summit"

---

### Week 32: Mock Exam — 24-Hour Investigation

**Study:**
- No new material. Pure execution.

**Labs:**
1. **Set aside a full weekend. This is your dress rehearsal.**
2. Pick the hardest available free challenge from CyberDefenders or BTLO that you haven't done yet. Ideally one that combines multiple evidence types.
3. Start a timer. You have **24 hours** to:
   - Analyze all evidence
   - Build the timeline
   - Identify the full kill chain
   - Write the complete incident report
4. Rules: No walkthroughs. No hints. No pausing the timer for sleep (plan your sleep strategically — the real CDSA is also time-pressured). Use every tool you've learned.
5. After completing (or when time expires), write an honest self-assessment:
   - What went well?
   - Where did you get stuck?
   - What tools/techniques did you fumble with?
   - What would you do differently on the real exam?
   - What areas need more drilling in Week 33?
6. If you finished early, pick a second challenge and do a speed run.

**Deliverables:**
- [ ] Complete investigation + report done under exam conditions
- [ ] Self-assessment document (brutally honest)
- [ ] List of specific drill items for Week 33

---

## Month 9: Certification & Portfolio Polish
*CDSA exam + final portfolio push*

### Week 33: Final Polish & Weak Spot Drilling

**Labs:**
1. Review your mock exam self-assessment. Drill your 3 weakest areas with targeted exercises.
2. Speed drills: Pick 3 past challenges and redo them with a strict 2-hour time limit each. Focus on methodology efficiency.
3. Tool fluency check: Can you fire up Volatility 3, KAPE, Splunk, ELK, YARA, and pySigma from memory without looking at documentation? Practice until you can.
4. **Portfolio Final Review**: Ensure your GitHub portfolio is complete and professional:
   ```
   cybersecurity-analyst-portfolio/
   ├── README.md (professional overview, skills, certifications)
   ├── sigma-rules/ (organized by MITRE tactic)
   ├── yara-rules/ (with test results)
   ├── investigations/ (write-ups from CyberDefenders, BTLO)
   ├── incident-reports/ (polished reports)
   ├── threat-intel/ (APT profile, infrastructure maps)
   ├── soc-lab/ (architecture doc, dashboard configs)
   ├── detection-playbooks/ (top 10 rules + response procedures)
   ├── cheat-sheets/ (forensics artifacts, Volatility commands, SPL/KQL)
   └── purple-team/ (bug bounty → detection rule write-up)
   ```
5. Proofread everything. Fix typos, broken links, inconsistent formatting.
6. Write a LinkedIn post announcing your portfolio and CDSA exam readiness (draft it, post after the exam).

**Deliverables:**
- [ ] Weak spots drilled with evidence
- [ ] Speed drill results
- [ ] Portfolio fully polished and organized on GitHub
- [ ] LinkedIn post drafted

---

### Week 34: CDSA EXAM ATTEMPT

You've been building toward this for 8 months. Trust your preparation.

- [ ] Take the HTB CDSA exam.
- [ ] CDSA certification (or a clear, specific action plan for retake).

---

### Week 35: Rest & Recovery

No mandatory labs. Breathe. You earned it.

If you feel like it: watch a DEF CON talk, read a write-up, do a casual TryHackMe room, or triage some LetsDefend alerts for fun. No pressure.

---

### Week 36: Portfolio Final Update & Job Application Prep

**Labs:**
1. Update your CV with the CDSA cert and all new skills acquired.
2. Add a redacted exam methodology write-up to your portfolio (NO actual exam content — just your approach, tools used, and time management strategy).
3. Update your GitHub README with final stats: total Sigma rules, YARA rules, investigations completed, detections built.
4. Update your HackerOne profile (byteoverride) to reflect your new defensive capabilities alongside offensive.
5. Start applying. You're ready.

**Deliverables:**
- [ ] Updated CV
- [ ] Portfolio finalized
- [ ] Applications sent

---

## KEY CHANGES FROM ORIGINAL PLAN

| Change | Why |
|--------|-----|
| **Zero HTB subscription** | Every resource is free or open-source. Only CDSA exam is paid. |
| **Cloud security added (Week 23)** | AWS Free Tier + CloudTrail fills the cloud gap every job posting mentions. |
| **Purple team bridge (Week 20)** | Write detection for your own Hover ATO finding. No other candidate can do this. |
| **Local lab replaces cloud labs** | Your 32GB Ryzen 7 runs Splunk + ELK + Windows VM + Sysmon simultaneously. |
| **CyberDefenders + BTLO replace HTB Sherlocks** | Free, browser-based, industry-respected. |
| **Splunk Academic Alliance** | Apply with ISBAT email → free full training catalog. Free money on the table. |
| **Massively expanded labs** | Every week has 5–10 hands-on exercises, not just 1–2. |
| **Real rest week (Week 35)** | Burnout kills more plans than difficulty does. |

---

## IMMEDIATE ACTION ITEMS (DO THIS WEEK)

- [ ] Apply for Splunk Academic Alliance with your ISBAT student email
- [ ] Install Docker and pull ELK stack image (`docker-elk` by deviantony on GitHub)
- [ ] Download and install Splunk Free (splunk.com — 500MB/day, no expiry)
- [ ] Bookmark free TryHackMe rooms: github.com/winterrdog/tryhackme-free-rooms
- [ ] Create an AWS Free Tier account (you'll need it in Month 6)
- [ ] Clone SigmaHQ repo: `git clone https://github.com/SigmaHQ/sigma.git`
- [ ] Download KAPE from kroll.com (free)
- [ ] Download EZTools from ericzimmerman.github.io (free)
- [ ] Install Volatility 3: `pip install volatility3`
- [ ] Set up a Windows 10 VM in VirtualBox for lab work
