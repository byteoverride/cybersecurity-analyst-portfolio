# Month 4: The SIEM — Splunk & Detection Engineering

**Author:** byteoverride
**Date:** April 2026
**Platform:** Splunk Free (local lab) + Splunk BOTS v1 (bots.splunk.com)
**Focus:** SIEM deployment, SPL fundamentals, brute force detection, and full kill-chain investigation

---

## Overview

This month was about going from "I can read logs manually" to "I can hunt through millions of events and tell you exactly what happened." Month 3 taught me where evidence lives on a Linux box. Month 4 taught me how to ingest that evidence into a SIEM and make it searchable, alertable, and actionable at scale.

Two main exercises:

1. **Lab 1 — Local Brute Force Investigation**: Built a 3-machine attack lab, ran Hydra against a target, and detected + investigated the brute force in real time through Splunk.
2. **Lab 2 — Splunk BOTS v1**: Investigated a full APT-style intrusion against Wayne Enterprises — from vulnerability scanning through brute force, webshell upload, and website defacement — using enterprise-scale Splunk telemetry.

**Skills demonstrated:**
- Splunk deployment and log ingestion (Linux `secure`/`auth.log` forwarding)
- SPL query construction (stats, rex, eval, timechart, tstats, geostats)
- Brute force detection and attacker attribution
- HTTP traffic analysis via `stream:http`
- Kill-chain reconstruction from SIEM data
- MITRE ATT&CK mapping of observed techniques
- OSINT pivoting from SIEM indicators to external threat intel

**MITRE ATT&CK coverage:**

| Technique | ID | Exercise |
|-----------|-----|----------|
| Brute Force: Password Guessing | T1110.001 | Lab 1, BOTS Q7/Q12–Q17 |
| Active Scanning: Vulnerability Scanning | T1595.002 | BOTS Q1–Q2 |
| Exploit Public-Facing Application | T1190 | BOTS Q3 |
| Server Software Component: Web Shell | T1505.003 | BOTS Q8–Q9 |
| Command and Scripting Interpreter | T1059 | BOTS Q8 |
| Phishing: Spearphishing Attachment | T1566.001 | BOTS Q10–Q11 |
| Defacement: External Defacement | T1491.002 | BOTS Q4–Q5 |

---

# Lab 1 — SSH Brute Force Detection (Local Lab)

## Lab Architecture

| Machine | Role | OS | IP |
|---------|------|-----|-----|
| Kali Linux | Attacker | Kali | 192.168.1.139 |
| Debian | Splunk SIEM | Debian | 192.168.1.62 |
| Red Hat | Victim (SSH target) | RHEL | 192.168.1.24 |

The victim machine forwards `/var/log/secure` to the Splunk instance via a Universal Forwarder on port 9997. This mirrors a production SOC setup where endpoints ship logs to a centralized SIEM.

## Attack Execution

From the Kali attacker machine, I ran Hydra with custom username and password wordlists:

```bash
hydra -L names.txt -P pass.txt -t 4 -o wave1.txt ssh://192.168.1.24
```

- `-L names.txt` — username wordlist
- `-P pass.txt` — password wordlist
- `-t 4` — 4 parallel threads (keeps it slow enough to watch in real time)
- `-o wave1.txt` — save successful creds to file

<!-- IMAGE: Hydra running against the Red Hat victim -->
> **[IMAGE PLACEHOLDER — Lab 1: Hydra execution on Kali showing brute force attempts against 192.168.1.24]**

## Detection in Splunk

### Step 1 — Confirm the attack is visible

The moment Hydra starts, failed authentication events begin flooding into Splunk from the Red Hat victim's `/var/log/secure`:

```spl
index="main" sourcetype="linux_secure" "Failed Password" | head 20
```

<!-- IMAGE: Splunk search results showing Failed Password events -->
> **[IMAGE PLACEHOLDER — Lab 1: Splunk showing "Failed Password" events with source IP, usernames, and timestamps]**

The logs immediately reveal the attack pattern: rapid-fire failed password attempts from the same source IP (`192.168.1.139`), cycling through different usernames. The `from` field in each log entry points directly to the attacker's IP.

### Step 2 — Identify the successful login

During the brute force, Hydra eventually guesses the correct credentials. The log pattern shifts from `Failed password` to `Accepted password`:

<!-- IMAGE: Splunk showing the moment Hydra guesses the correct password -->
> **[IMAGE PLACEHOLDER — Lab 1: Splunk log showing "Accepted password" event from the attacker IP — the moment the brute force succeeds]**

### Step 3 — Confirm the attacker logged in

After Hydra reports the successful credential, the attacker proceeds to log in with the discovered credentials. The session establishment appears in the logs:

<!-- IMAGE: Splunk showing the authenticated session from the attacker -->
> **[IMAGE PLACEHOLDER — Lab 1: Splunk showing successful SSH session opened from 192.168.1.139 to the victim]**

### Step 4 — Attribution query (internet-facing variant)

If this were an internet-facing SSH server being attacked from external IPs, you'd want geographic attribution. This query extracts source IPs, geolocates them, and plots them on a map:

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| iplocation src_ip
| stats count by src_ip, Country, lat, lon
| geostats count by Country
```

This produces a Splunk geographic heatmap showing where brute force attempts originate — exactly the kind of dashboard panel a SOC uses for real-time monitoring.

### Key Takeaways

- The detection is straightforward: `"Failed password" | stats count by src_ip` catches brute force every time. The hard part in production is tuning the threshold to avoid false positives from legitimate fat-fingered users.
- The transition from `Failed password` to `Accepted password` from the same source IP is the critical moment — that's when the attacker gets in.
- Hydra's `-t 4` (4 threads) is visible as 4 near-simultaneous attempts per second. Higher thread counts are louder but faster. Attackers balance speed vs. detection risk.

---

# Lab 2 — Splunk BOTS v1: Full Walkthrough

<!-- IMAGE: BOTS v1 landing page or challenge interface -->
> **[IMAGE PLACEHOLDER — BOTS v1: Challenge landing page at bots.splunk.com]**

## About the Lab

BOTS v1 simulates two intrusions against a fictional company called Wayne Enterprises. The dataset is real Splunk telemetry pulled from a controlled lab environment containing web logs (Apache, IIS, Nginx, `stream:http`), endpoint logs (Sysmon, Windows Event Logs), proxy logs (Suricata), and antivirus logs (Symantec). The two scenarios are independent but share the same dataset.

**Scenario 1** is a public-facing website (`imreallynotbatman.com`) that gets defaced. The investigation tracks the attacker through reconnaissance, brute force, payload delivery, and the actual defacement.

**Scenario 2** is a ransomware infection that hits an internal endpoint, encrypts files, and tries to call out to a C2 channel.

I focused on Scenario 1 (Web Defacement) for this write-up because it covers the full kill chain from recon to impact.

## My Approach

Before clicking around, I set ground rules to avoid the "Google the answer" trap:

1. **Always use `index=botsv1` with `earliest=0 latest=now`** — some events fall outside the default 24-hour window.
2. **Run a recon search first** — start every question with `| stats count by sourcetype` to map the data before narrowing down.
3. **Pivot, don't grep** — once I have one indicator (IP, hash, username), pivot every subsequent search around it instead of keyword-searching in the dark.
4. **Document the reasoning, not just the answer** — so the write-up actually teaches me something six months from now.

## Data Reconnaissance

First thing I did was map what data I'm working with:

```spl
index=botsv1 earliest=0 latest=now
| stats count by sourcetype
| sort -count
```

<!-- IMAGE: Sourcetype count results -->
> **[IMAGE PLACEHOLDER — BOTS: Sourcetype distribution showing event counts per data source]**

The most useful sourcetypes for the web defacement scenario:

| Sourcetype | What It Contains | When I Used It |
|------------|-----------------|----------------|
| `stream:http` | Full HTTP request/response capture | Payload analysis, brute force extraction |
| `iis` | IIS web server logs | Scanner detection, access patterns |
| `suricata` | IDS alerts | Exploit signature confirmation |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation, network connections, file ops | Endpoint kill chain |
| `WinEventLog:Security` | Auth events, account changes | Lateral movement attempts |
| `fgt_utm` | Fortinet UTM logs | Outbound C2 confirmation |

Knowing which sourcetype answers which question saves you from running 10 useless searches. A question about user agents → `stream:http`. A question about process execution → Sysmon. This mapping is the first thing you should build on any BOTS dataset.

---

## Scenario 1: Web Defacement

### The Kill Chain

Someone scanned the public site, found it was running a vulnerable Joomla install, brute forced the admin login, uploaded a webshell, and replaced the homepage with a defaced page. Textbook OWASP top-of-the-list stuff — but the value is in tracking the attacker through Splunk end to end.

---

### Q1: What is the likely IPv4 address of someone from the Po1s0n1vy group scanning imreallynotbatman.com?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http dest=imreallynotbatman.com
| stats count, dc(uri) as unique_uris by src_ip
| sort -count
```

**Why this works:** A vulnerability scanner generates massive request volume against many unique URIs in a short window. A real user touches a handful of pages. The combination of high `count` and very high `dc(uri)` is the scanner signature.

**Confirmation pivot:**

```spl
index=botsv1 sourcetype=stream:http src=40.80.148.42
| stats count by useragent
```

The user agent string returned scanner-specific markers including Acunetix strings. No legitimate browser includes scanner names in its UA.

<!-- IMAGE: Stats showing the top src_ip with high count and URI diversity -->
> **[IMAGE PLACEHOLDER — Q1: SPL results showing 40.80.148.42 with dominant request count and unique URI count]**

**Answer:** `40.80.148.42`

---

### Q2: What company created the web vulnerability scanner?

**SPL:**

```spl
index=botsv1 sourcetype="stream:http" src_ip="40.80.148.42"
| stats count by http_user_agent
| sort -count
```

The user agent contained `Acunetix-Aspect` and request bodies had `acunetix` markers. The user agent string is the cleanest fingerprint of which scanner ran.

<!-- IMAGE: User agent results showing Acunetix -->
> **[IMAGE PLACEHOLDER — Q2: SPL results showing Acunetix user agent strings from the scanner IP]**

**Answer:** `Acunetix`

---

### Q3: What content management system is imreallynotbatman.com likely using?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http dest=imreallynotbatman.com
| head 30
```

Any CMS leaves URI fingerprints. Joomla has `/administrator/`, `/components/`, `/templates/`. WordPress has `/wp-admin/`, `/wp-content/`. The scanner naturally hits all CMS-specific paths — requests to non-existent CMS paths return 404 quickly while real CMS paths get explored deeper.

I saw heavy traffic to `/joomla/` and `/joomla/administrator/index.php`, plus the scanner kept probing Joomla components specifically.

<!-- IMAGE: HTTP requests showing Joomla paths -->
> **[IMAGE PLACEHOLDER — Q3: SPL results showing URI paths with /joomla/ and /administrator/ patterns]**

**Answer:** `Joomla`

---

### Q4: What is the name of the file that defaced imreallynotbatman.com?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http src_ip=192.168.250.70
| dedup uri
| table _time, dest_ip, uri
```

A defacement involves swapping or planting an image on the site. The defacement file gets requested heavily after the swap because every visitor to the homepage pulls it. A new image suddenly appearing at the top of the count list is the candidate.

<!-- IMAGE: URI table showing the defacement image file -->
> **[IMAGE PLACEHOLDER — Q4: SPL results showing poisonivy-is-coming-for-you-batman.jpeg in the URI list]**

**Answer:** `poisonivy-is-coming-for-you-batman.jpeg`

The naming is the attacker bragging — Po1s0n1vy is signing their work.

---

### Q5: This attack used dynamic DNS to resolve to the malicious IP. What FQDN is associated with this attack?

**SPL:**

```spl
index=botsv1 sourcetype="stream:http" "poisonivy-is-coming-for-you-batman.jpeg"
| stats values(site)
```

Dynamic DNS providers have well-known suffixes (`no-ip.org`, `dyndns.org`, `hopto.org`, `ddns.net`). Filtering for those narrows it down. I also pivoted from the attacker IPs to find what hostnames resolved to them.

<!-- IMAGE: Site values showing the FQDN -->
> **[IMAGE PLACEHOLDER — Q5: SPL results showing the dynamic DNS FQDN hosting the defacement image]**

**Answer:** `prankglassinebracket.tumblr.com`

The attacker pointed dynamic DNS at attacker-controlled infrastructure to host the payload.

---

### Q6: What IPv4 address has Po1s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

**SPL:**

```spl
index=botsv1 "prankglassinebracket.jumpingcrab.com"
| stats values(src_ip)
```

Cross-referenced threat intel sources included in the BOTS dataset for known Po1s0n1vy infrastructure.

<!-- IMAGE: Source IP values tied to the Po1s0n1vy domain -->
> **[IMAGE PLACEHOLDER — Q6: SPL results showing 23.22.63.114 tied to Po1s0n1vy infrastructure]**

**Answer:** `23.22.63.114`

This same IP is the brute force source in Q7 — attackers reuse infrastructure across phases more often than people assume.

---

### Q7: What IPv4 address is likely attempting a brute force password attack against imreallynotbatman.com?

**SPL:**

```spl
index=botsv1 sourcetype="stream:http" http_method=POST imreallynotbatman.com
| stats count by src_ip
```

Brute force is a flood of POST requests to a login endpoint. Filtering by HTTP POST plus the admin URI plus high count by source IP catches it cleanly. The scanner from Q1 used a different IP for recon than for exploitation — a deliberate operational choice to make attribution harder.

<!-- IMAGE: POST count by src_ip showing the brute force source -->
> **[IMAGE PLACEHOLDER — Q7: SPL results showing 23.22.63.114 with dominant POST request count]**

**Answer:** `23.22.63.114`

Same IP as Q6. The attacker used their staging infrastructure to launch the brute force.

---

### Q8: What is the name of the executable uploaded by Po1s0n1vy?

**SPL:**

```spl
index=botsv1 sourcetype="stream:http" http_method=POST "*.exe"
```

The attacker uploaded an executable through the Joomla admin after gaining access. POST requests with `.exe` in either the URI or the form data capture the upload moment.

<!-- IMAGE: HTTP POST showing the executable upload -->
> **[IMAGE PLACEHOLDER — Q8: SPL results showing 3791.exe in the HTTP POST data]**

**Answer:** `3791.exe`

The filename is just a number — generated names like that come from automation, not a human picking a filename.

---

### Q9: What is the MD5 hash of the executable uploaded?

**SPL:**

```spl
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="3791.exe"
```

In a real investigation you'd take this MD5 straight to VirusTotal, ANY.RUN, or your internal sandbox. In BOTS, this hash matches a known Po1s0n1vy payload.

<!-- IMAGE: Sysmon event showing the MD5 hash -->
> **[IMAGE PLACEHOLDER — Q9: Sysmon event log showing MD5 hash for 3791.exe]**

**Answer:** `AAE3F5A29935E6ABCC2C2754D12A9AF0`

---

### Q10: What is the SHA256 of the custom malware Po1s0n1vy sends in spear phishing if initial compromise fails?

This question requires OSINT pivots, not Splunk searches. Po1s0n1vy is a fictional group invented for BOTS, but the lab seeded real threat intel write-ups about them, including infrastructure analysis with hashes.

I took the IP from Q6 (`23.22.63.114`) and cross-referenced it against threat intel sources documented in the BOTS reference material.

**Answer:** `9709473ab351387aab9e816eff3910b9f28a7a70202e250ed46dba8f820f34a8`

---

### Q11: What special hex code is associated with the customized malware in Q10?

The hint says "It's not in Splunk!" — pure threat intel research. I took the SHA256 from Q10, dropped it into VirusTotal, and looked at embedded strings, YARA matches, and behavioral analysis. The custom malware contains an attacker signature in the form of a hex string used as a marker.

In a real investigation you'd find this by reverse engineering the binary in Ghidra or pulling it from a sandbox report.

**Answer:** `0xb887bd8a6f4ea8a517fa7b4e6d265027`

---

### Q12: What was the first brute force password used?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com http_method=POST src=23.22.63.114
| rex field=form_data "passwd=(?<password>[^&]+)"
| sort _time
| table _time, password
| head 5
```

Brute force scripts iterate through a wordlist in order. Sorting POST requests from the attacker IP by `_time` ascending and pulling the first password attempt gives you the wordlist's first entry.

<!-- IMAGE: First password attempts sorted by time -->
> **[IMAGE PLACEHOLDER — Q12: SPL results showing the first brute force password attempts in chronological order]**

**Answer:** `12345678`

The classic first entry of every dictionary attack.

---

### Q13: One of the passwords is James Brodsky's favorite Coldplay song. Six-character word.

**SPL:**

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com http_method=POST src=23.22.63.114
| rex field=form_data "passwd=(?<password>[^&]+)"
| eval len=len(password)
| where len=6
| stats count by password
| sort password
```

Filter captured passwords to length 6, then scan for Coldplay song titles. Six-character Coldplay songs: "Yellow", "Sparks", "Clocks". The one that appears in the brute force list is the answer.

**Answer:** `yellow`

---

### Q14: What was the correct password for admin access to the CMS?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com http_method=POST src=23.22.63.114
| rex field=form_data "passwd=(?<password>[^&]+)"
| sort _time
| reverse
| table _time, password, src_ip
| head 10
```

The successful password is the **last one tried** before the attacker stops brute forcing and switches to authenticated actions. Sort descending by time and look at the most recent password attempt right before the activity pattern changes.

You can confirm by looking at what password preceded a `200 OK` response with a redirect to the dashboard, while all earlier attempts returned the login page.

**Answer:** `batman`

A six-character password, dictionary word, themed to the target. Predictable and exactly what a Batman-themed wordlist would catch.

---

### Q15: What was the average password length used in the brute forcing attempt?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com http_method=POST src=23.22.63.114 uri="*administrator*"
| rex field=form_data "passwd=(?<password>[^&]+)"
| eval password_length=len(password)
| stats avg(password_length) as avg_len
| eval avg_len=round(avg_len, 0)
```

`len()` calculates each password's character count, `avg()` gives the mean, `round()` to 0 decimal places matches the expected format.

<!-- IMAGE: Average password length result -->
> **[IMAGE PLACEHOLDER — Q15: SPL result showing average password length of 6]**

**Answer:** `6`

Makes sense — most generic password wordlists center around 6–8 characters because that's where most weak human-chosen passwords land.

---

### Q16: How many seconds elapsed between the brute force scan identifying the correct password and the compromised login?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http http_method=POST uri="*administrator*" form_data="*passwd=batman*"
| stats earliest(_time) as t by src_ip
| eval t_str=strftime(t, "%Y-%m-%d %H:%M:%S.%6N")
| table src_ip, t_str, t
| sort t
```

The brute force IP (`23.22.63.114`) submitted `batman` as part of the dictionary attack. A separate, cleaner login then used `batman` from the original recon IP (`40.80.148.42`). The time difference between the brute force discovering the password and the actual login is the answer.

<!-- IMAGE: Time comparison between the two IPs submitting "batman" -->
> **[IMAGE PLACEHOLDER — Q16: SPL results showing timestamps for both IPs submitting the "batman" password]**

**Answer:** `92.17`

The attacker found the password, then waited about a minute and a half before using it. That delay is operational tradecraft, not a technical limitation — it avoids triggering "brute force immediately followed by login" detection rules.

---

### Q17: How many unique passwords were attempted in the brute force?

**SPL:**

```spl
index=botsv1 sourcetype=stream:http imreallynotbatman.com http_method=POST src=23.22.63.114 uri="*administrator*"
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats dc(password) as unique_passwords
```

`dc()` is distinct count — it deduplicates the password list. Filtering to the brute force IP only ensures legitimate user attempts don't pollute the count.

<!-- IMAGE: Distinct password count result -->
> **[IMAGE PLACEHOLDER — Q17: SPL result showing 412 unique passwords attempted]**

**Answer:** `412`

A small-to-medium wordlist. Quick brute force tools like Hydra default to wordlists in the few hundreds when targeting a CMS admin login over HTTP because going larger triggers IDS faster.

---

## Kill Chain Reconstruction

Putting it all together — the full attack timeline as Splunk told it:

| Phase | What Happened | Attacker IP | Evidence Source |
|-------|--------------|-------------|-----------------|
| **Recon** | Acunetix vulnerability scan against imreallynotbatman.com | 40.80.148.42 | `stream:http` user agent + URI diversity |
| **Weaponization** | Pre-staged infrastructure on dynamic DNS (jumpingcrab.com) | 23.22.63.114 | DNS records + threat intel |
| **Initial Access** | Brute forced Joomla admin with 412 passwords | 23.22.63.114 | `stream:http` POST form_data |
| **Credential Access** | Discovered password `batman` | 23.22.63.114 | `stream:http` sorted by time |
| **Execution** | Logged in 92 seconds later from recon IP | 40.80.148.42 | `stream:http` time delta |
| **Persistence** | Uploaded `3791.exe` webshell via Joomla media manager | 40.80.148.42 | `stream:http` POST + Sysmon |
| **Impact** | Defaced homepage with `poisonivy-is-coming-for-you-batman.jpeg` | — | `stream:http` URI analysis |

---

## Lessons Learned

1. **Recon and exploitation IPs are often different.** Q1 and Q7 are different IPs even though it's the same actor. Always check both ends.
2. **`stream:http` is gold for web investigations.** The full request body lets you extract POST parameters with `rex`, which is how every brute force question gets solved.
3. **Time math is your friend.** Q16 is just `latest(_time) - earliest(_time)`. Many BOTS questions reduce to time deltas.
4. **`dc()` vs `count`.** Distinct count is for "how many unique" questions. Regular count is for "how many total."
5. **Some questions are not in Splunk.** Q10 and Q11 require OSINT and threat intel pivots. Real investigations cross the boundary between SIEM and external research.
6. **`stats count by X` solves more BOTS questions than any other command.** Frequency analysis is the unsung hero of SPL.
7. **The successful brute force password is the last one tried before activity changes.** Sort descending by time, find where the failures stop and the authenticated activity starts.
8. **Wordlist signatures are recognizable.** A wordlist that starts with `12345` and ends with `batman` after 412 attempts has a clear thematic flavor — you can almost reconstruct the attacker's tooling from the password order.

---

## SPL Cheat Sheet

Built this as a personal reference during the labs:

```spl
# ===== DATA RECON =====
# Always start here — map what you're working with
index=botsv1 earliest=0 latest=now
| stats count by sourcetype | sort -count

# ===== ATTACKER IDENTIFICATION =====
# Top IPs by request volume + URI diversity (scanner detection)
index=botsv1 sourcetype=stream:http
| stats count, dc(uri) as unique_uris by src_ip | sort -count

# Scanner fingerprinting via user agent
index=botsv1 sourcetype=stream:http
| stats count by useragent | sort -count

# ===== BRUTE FORCE ANALYSIS =====
# Extract POST passwords from form_data
index=botsv1 sourcetype=stream:http http_method=POST uri="*administrator*"
| rex field=form_data "passwd=(?<password>[^&]+)"
| table _time, src_ip, password

# First password attempted (wordlist start)
... | sort _time | head 1

# Last password attempted (likely the successful one)
... | sort _time | reverse | head 1

# Average password length
... | eval len=len(password) | stats avg(len)

# Distinct password count
... | stats dc(password)

# ===== TIME ANALYSIS =====
# Time delta between two events
... | stats earliest(_time) as t1, latest(_time) as t2
| eval delta=t2-t1

# ===== NETWORK PIVOTS =====
# DNS: FQDN to IP resolution
index=botsv1 sourcetype=stream:dns
| search answer=<attacker_ip>
| stats values(query) by answer

# ===== FILE UPLOAD DETECTION =====
index=botsv1 sourcetype=stream:http http_method=POST
| search form_data="*.exe*" OR uri="*.exe"

# ===== GEOGRAPHIC ATTRIBUTION =====
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| iplocation src_ip
| stats count by src_ip, Country, lat, lon
| geostats count by Country
```

---

## MITRE ATT&CK Mapping (Combined)

| Phase | Technique | ID | Where I Saw It |
|-------|-----------|-----|----------------|
| Recon | Active Scanning: Vulnerability Scanning | T1595.002 | Acunetix scan from `40.80.148.42` |
| Initial Access | Exploit Public-Facing Application | T1190 | Joomla admin exposed to internet |
| Credential Access | Brute Force: Password Guessing | T1110.001 | 412 unique passwords from `23.22.63.114` + Hydra in local lab |
| Execution | Command and Scripting Interpreter | T1059 | `3791.exe` upload and execution |
| Persistence | Server Software Component: Web Shell | T1505.003 | Webshell via Joomla media manager |
| Initial Access (alt) | Phishing: Spearphishing Attachment | T1566.001 | Custom Po1s0n1vy malware (OSINT) |
| Impact | Defacement: External Defacement | T1491.002 | Homepage replaced with attacker image |

---

## What I'd Do Differently Next Time

- **Build saved searches keyed to MITRE techniques up front** instead of going question by question. That way the investigation follows the kill chain, not the quiz order.
- **Use `tstats` instead of `stats`** for performance on large indexes — `tstats` queries indexed metadata and is significantly faster.
- **Build a kill chain dashboard** with one panel per phase so the whole attack story is visible at a glance. That's what I'm carrying into BOTS v2.

---

## What's Next

Month 5 takes the SPL skills built here and translates them into **Sigma rules** — vendor-agnostic detection logic that works across any SIEM. The brute force queries from Lab 1 become Sigma rules. The web shell upload pattern from BOTS becomes a Sigma rule. The goal is to go from "I can investigate after the fact" to "I can write detections that catch it in real time."
