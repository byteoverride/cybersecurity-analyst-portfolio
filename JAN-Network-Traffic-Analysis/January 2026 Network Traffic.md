# January 2026 — Network Traffic Analysis Report

## Overview

In January 2026, I focused on developing a strong foundation in **Network Traffic Analysis (NTA)** as part of my transition toward a Cybersecurity Analyst / SOC Analyst role.

The primary goal was to understand how network data can be used to:
- Detect malicious activity
- Identify attack patterns
- Troubleshoot network and security incidents
- Build repeatable analysis methodologies applicable in real SOC environments

This month combined **theoretical learning**, **hands-on labs**, and **full investigative analysis** using real packet captures.

---

## Resources Used

### Training & Courses
- **Hack The Box Academy**
  - *Introduction to Network Traffic Analysis*  
  - Link: https://academy.hackthebox.com/module/81/section/773

- **Practical Packet Analysis** — Chris Sanders  
  - Followed all chapters and completed all associated labs

### Hands-On Labs
- **CyberDefenders**
  - *PacketDetective Lab* (Full investigation)

---

## Key Learning Objectives

- Understand normal vs abnormal network behavior
- Recognize common attack patterns in packet captures
- Apply structured methodologies to traffic analysis
- Use Wireshark effectively for security investigations
- Correlate traffic evidence to security incidents

---

## Lessons Learned

### 1. Attack Pattern Recognition
- Identifying scanning behavior, beaconing, and suspicious sessions
- Differentiating legitimate services from malicious misuse
- Recognizing C2-style traffic characteristics

### 2. Network Troubleshooting via Traffic Analysis
- Using packet analysis to identify misconfigurations
- Understanding latency, retransmissions, and protocol errors
- Identifying failed connections and abnormal responses

### 3. Analysis Methodology
- Following a **structured workflow** instead of random packet inspection
- Reducing noise early through filtering
- Building conclusions based on evidence, not assumptions

---

## Network Traffic Analysis Workflow

The following workflow was applied consistently throughout all labs and investigations.

### 1. Define the Problem

**Question:**  
What is the issue or suspicious activity observed?

**Objective:**  
Provide a clear and concise summary of the suspected problem.

---

### 2. Define Scope and Goal

- What are we looking for?
- Which time period is relevant?
- What initiated the investigation?

**Scope Includes:**
- Affected hosts or networks
- Relevant protocols
- Timeframe of interest

**Supporting Information:**
- PCAP files
- Logs (if available)
- Alerts or prior indicators

---

### 3. Define Targets

- Target hosts (IP addresses)
- Network segments
- Protocols of interest (HTTP, DNS, TCP, etc.)

---

### 4. Traffic Acquisition

- Analyze provided PCAP files
- Verify capture completeness
- Validate timestamps and capture duration

---

### 5. Traffic Filtering

Filter out:
- Known benign baseline traffic
- Broadcasts and irrelevant services

Focus on:
- Suspicious IPs
- Unusual ports
- Abnormal protocol behavior

---

### 6. Deep Traffic Analysis

- Inspect packet flows and conversations
- Analyze payloads where applicable
- Track session behavior over time

---

### 7. Documentation & Evidence Collection

Throughout the investigation, the following were documented:

- Timeframes of suspicious activity
- Involved IP addresses and ports
- Packet numbers and timestamps
- Protocol anomalies
- Extracted files or indicators (if applicable)

Clear note-taking ensured traceability and reproducibility.

---

### 8. Findings Summary

After analysis, findings were summarized to answer:

- What happened?
- How did it happen?
- Which systems were affected?
- What evidence supports the conclusion?

---

### 9. Final Assessment

The final assessment provides decision-makers with:
- Clear incident understanding
- Confidence in evidence-based conclusions
- Guidance for containment or escalation

---

## Practical Lab: PacketDetective (CyberDefenders)

In the PacketDetective lab, I applied the complete workflow to a real-world packet capture involving suspicious host activity.

Key skills demonstrated:
- Host identification
- Timeline reconstruction
- Protocol analysis
- Evidence-driven conclusions

This lab reinforced the importance of discipline, patience, and structured thinking in packet analysis.

---

## Skills Developed

- Network Traffic Analysis (Wireshark)
- Incident Investigation Methodology
- Attack Detection via PCAP
- Evidence Documentation
- SOC-Style Reporting

---

## Reflection

January established a strong analytical foundation for future SOC-focused learning.  
The focus on **methodology over tools** ensured skills developed are transferable across environments and organizations.

This month serves as the baseline for deeper work in:
- Threat detection
- Incident response
- SIEM analysis
- Endpoint and log correlation

---

## Tools & Common Commands Used
---

### Tcpdump — Packet Capture & Quick Inspection

Tcpdump was used for fast validation, filtering, and initial inspection of traffic before deep analysis.

#### Common Commands

```bash
tcpdump -D
````

List available network interfaces for capture.

```bash
tcpdump -i eth0 -w capture.pcap
```

Capture traffic on a specific interface and write to a PCAP file for offline analysis.

```bash
tcpdump -r capture.pcap
```

Read traffic from an existing PCAP file.

```bash
tcpdump -i eth0 host 10.0.0.5
```

Filter traffic to or from a specific host.

```bash
tcpdump -i eth0 port 443
```

Capture traffic related to a specific port.

```bash
tcpdump -i eth0 proto tcp
```

Filter traffic by protocol.

```bash
tcpdump -nn -X -r capture.pcap
```

Disable name resolution and display packet contents in hex and ASCII for payload inspection.

---

### Wireshark — Deep Protocol Analysis

Wireshark was the primary tool for detailed inspection, stream reconstruction, and behavioral analysis.

#### Common Display Filters

```text
ip.addr == 192.168.1.10
```

Display traffic involving a specific host.

```text
tcp.port == 80
```

Filter traffic for a specific TCP port.

```text
dns
```

Isolate DNS traffic for analysis.

```text
http
```

Display HTTP protocol traffic.

```text
tcp.stream eq 5
```

Follow a specific TCP stream to reconstruct a session.

```text
ftp || ftp-data
```

Inspect FTP control and data channel activity.

---

### Tshark — Command-Line Packet Analysis

Tshark was used when command-line analysis or automation was preferred.

```bash
tshark -D
```

List available capture interfaces.

```bash
tshark -i eth0 -f "host 192.168.1.10"
```

Capture traffic for a specific host.

```bash
tshark -r capture.pcap
```

Read traffic from a PCAP file.

```bash
tshark -c 100
```

Capture a fixed number of packets for quick sampling.

---

### Supporting Commands

```bash
which tcpdump
```

Verify tool availability on the system.

```bash
sudo apt install wireshark
```

Install required analysis tools.

```bash
man tcpdump
```

Consult manual pages for advanced usage.

---

## Why These Commands Matter

Rather than relying solely on GUI-based analysis, these commands enable:

* Faster triage of large PCAPs
* Noise reduction before deep inspection
* Repeatable and defensible analysis steps
* Flexibility across restricted or headless environments

This reinforces analyst independence from any single tool or interface.

---

## Next Steps (February 2026)

- Transition from packet-level analysis to **alert-driven investigations**
- Introduce SIEM and log correlation
- Continue applying structured investigation workflows





