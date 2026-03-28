# Month 3: Linux Forensics

**Author:** byteoverride
**Date:** March 2026
**Platform:** Red Hat Linux (RHEL-based VM)
**Focus:** Log analysis, persistence detection, process investigation, and forensic evidence recovery

---

## Overview

This month focused on the forensic fundamentals every analyst needs on Linux systems: understanding where evidence lives, how attackers persist, and how to investigate a compromised host using nothing but the command line. Every lab simulates a real attacker action, then walks through detecting it purely from log artifacts and system state — the way you'd do it during an actual incident response engagement.

**Skills demonstrated:**
- Linux authentication log analysis (`/var/log/secure`, `/var/log/auth.log`, `/var/log/audit/audit.log`)
- User lifecycle forensics (creation, privilege escalation, deletion)
- Persistence mechanism detection (cron jobs, `.bashrc` injection, SSH `authorized_keys`)
- Process investigation and renamed binary detection
- Live system triage under simulated load

**MITRE ATT&CK coverage:**

| Technique | ID | Lab |
|-----------|-----|-----|
| Create Account: Local Account | T1136.001 | Lab 1, Lab 2 |
| Scheduled Task/Job: Cron | T1053.003 | Lab 3 |
| Event Triggered Execution: Unix Shell Configuration Modification | T1546.004 | Lab 5 |
| Masquerading: Rename System Utilities | T1036.003 | Lab 7 |
| Discovery: Process Discovery | T1057 | Lab 6 |

---

## Lab 1 — Create, Escalate, Delete: Full Log Trail

**Goal:** Prove a deleted user existed using only log files.

**Scenario:** An attacker creates a local account, escalates to that user, performs actions, then deletes the account to cover their tracks. Your job is to recover the forensic evidence that the account ever existed.

**MITRE ATT&CK:** T1136.001 (Create Account: Local Account)

### Attack Simulation

**Step 1 — Create the user and set a password:**

```bash
sudo useradd -m testuser
sudo passwd testuser
```

**Step 2 — Escalate to the new user and confirm identity:**

```bash
su - testuser
whoami
# Output: testuser
```

<!-- IMAGE: Screenshot showing user creation, password set, su to testuser, and whoami output -->
> **[IMAGE PLACEHOLDER — Lab 1: User creation and privilege escalation terminal output]**

**Step 3 — Delete the user and remove their home directory:**

```bash
sudo userdel -r testuser
```

At this point, the user is gone from `/etc/passwd`, their home directory is deleted, and a casual admin might think they never existed.

### Forensic Detection

The key insight: **Linux logs everything to `/var/log/secure` (RHEL/CentOS) or `/var/log/auth.log` (Debian/Ubuntu).** Even after a user is deleted, the log entries remain unless the attacker explicitly clears them.

**Recover the evidence:**

```bash
sudo grep "testuser" /var/log/secure
```

**What the logs reveal — the complete lifecycle of the deleted user:**

| Timestamp | Log Entry | What It Proves |
|-----------|-----------|----------------|
| Mar 18 21:24:42 | `useradd[3140]: new group: name=testuser, GID=1001` | Group was created |
| Mar 18 21:24:42 | `useradd[3140]: new user: name=testuser, UID=1001, GID=1001, home=/home/testuser, shell=/bin/bash` | User was created with full details |
| Mar 18 21:24:54 | `sudo[3153]: psalms : COMMAND=/sbin/passwd testuser` | Admin set the password |
| Mar 18 21:25:03 | `passwd[3155]: pam_unix(passwd:chauthtok): password changed for testuser` | Password was successfully changed |
| Mar 18 21:25:17 | `su[3168]: pam_unix(su-l:session): session opened for user testuser(uid=1001) by psalms(uid=1000)` | Someone escalated to this account |
| Mar 18 21:25:30 | `su[3168]: pam_unix(su-l:session): session closed for user testuser` | Session ended |
| Mar 18 21:27:51 | `sudo[3232]: psalms : COMMAND=/sbin/userdel -r testuser` | **Deletion command executed** |
| Mar 18 21:27:51 | `userdel[3234]: delete user 'testuser'` | User deleted |
| Mar 18 21:27:51 | `userdel[3234]: removed group 'testuser' owned by 'testuser'` | Group removed |
| Mar 18 21:27:51 | `userdel[3234]: removed shadow group 'testuser' owned by 'testuser'` | Shadow entry removed |

<!-- IMAGE: Screenshot showing grep output of /var/log/secure with the full testuser lifecycle highlighted -->
> **[IMAGE PLACEHOLDER — Lab 1: /var/log/secure showing the complete deletion evidence with highlighted entries]**

### Key Takeaways

- `/var/log/secure` (or `auth.log`) is the **single most important file** for user account forensics on Linux.
- Even after `userdel -r`, the log trail persists. Attackers who don't clean logs leave a complete audit trail.
- The `UID` and `GID` in the creation log are critical — they can be cross-referenced with file ownership on disk to find artifacts the attacker left behind, even after their account is deleted.
- **Detection rule idea:** Alert on `userdel` commands, especially when the user was created recently (short-lived accounts are a red flag).

---

## Lab 2 — Failed Sudo Attempts (Brute-Force Detection)

**Goal:** Simulate a brute-force / wrong-password scenario and find it in logs.

**Scenario:** An attacker gains access to a low-privilege account and attempts to escalate privileges by repeatedly trying `su` with wrong passwords. This generates authentication failures that should trigger alerts.

**MITRE ATT&CK:** T1136.001 (Create Account), T1110 (Brute Force)

### Attack Simulation

**Step 1 — Create a low-privilege attacker account:**

```bash
sudo useradd -m attacker
```

**Step 2 — Attempt `su` with wrong passwords multiple times:**

```bash
su - attacker
# Enter wrong password
# Authentication failure
su - attacker
# Authentication failure
su - attacker
# Authentication failure
```

<!-- IMAGE: Screenshot showing repeated su attempts with "Authentication failure" messages -->
> **[IMAGE PLACEHOLDER — Lab 2: Terminal showing repeated su authentication failures]**

### Forensic Detection — Three Log Sources

Linux records authentication failures in multiple locations. A thorough investigation checks all of them.

**Source 1: `/var/log/audit/audit.log`**

```bash
cat audit.log | grep "attacker"
```

The audit log captures every authentication event at the kernel level with full detail — UIDs, PIDs, session IDs, executable paths, and success/failure status. This is the most granular source.

<!-- IMAGE: Screenshot of audit.log output showing the attacker authentication events -->
> **[IMAGE PLACEHOLDER — Lab 2: audit.log showing authentication failure events with PIDs and UIDs]**

Key fields to look for in audit.log:
- `res=failed` — authentication was rejected
- `acct="attacker"` — target account
- `exe="/usr/bin/su"` — the tool used to escalate
- `auid=` — the audit UID, which tracks the original user across `su`/`sudo` sessions

**Source 2: `/var/log/secure`**

```bash
sudo grep "attacker" /var/log/secure
```

This gives a more readable view. The key entries:

| Timestamp | Event | Meaning |
|-----------|-------|---------|
| Mar 18 21:33:46 | `useradd[3383]: new user: name=attacker, UID=1001, GID=1001` | Attacker account created |
| Mar 18 21:34:00 | `unix_chkpwd[3401]: password check failed for user (attacker)` | Wrong password attempt #1 |
| Mar 18 21:34:09 | `pam_unix(su-l:auth): authentication failure; logname=psalms uid=1000` | PAM confirmed the failure |
| Mar 18 21:34:09 | `unix_chkpwd[3406]: password check failed for user (attacker)` | Wrong password attempt #2 |
| Mar 18 21:34:16 | `su[3415]: password check failed for user (attacker)` | Wrong password attempt #3 |
| Mar 18 21:34:16 | `pam_unix(su-l:auth): authentication failure; logname=psalms uid=1000` | PAM failure again |

<!-- IMAGE: Screenshot of /var/log/secure showing authentication failures highlighted -->
> **[IMAGE PLACEHOLDER — Lab 2: /var/log/secure showing failed password attempts with highlighted failure entries]**

**Searching specifically for failures:**

```bash
sudo grep FAILED /var/log/secure
```

### Key Takeaways

- Authentication failures generate entries in **three separate log files**: `audit.log`, `secure`/`auth.log`, and potentially `syslog`. Always check all of them.
- The `logname=` field in `/var/log/secure` reveals **who was logged in when the brute force happened** — this is how you trace the attack back to the initial compromise.
- `unix_chkpwd` entries with "password check failed" are the clearest indicator of brute-force activity.
- **Detection rule idea:** Alert when >3 `unix_chkpwd` failures for the same user occur within 60 seconds. Map to MITRE T1110 (Brute Force).

---

## Lab 3 — Plant & Detect a Malicious Cron Job

**Goal:** Simulate an attacker establishing persistence via cron, then detect it forensically.

**Scenario:** After gaining access, an attacker sets up a cron job that beacons out every minute. In a real attack, this would be a reverse shell or C2 callback. Here we use `ping` as a safe stand-in.

**MITRE ATT&CK:** T1053.003 (Scheduled Task/Job: Cron)

### Attack Simulation

**Plant the cron job as a low-privilege user:**

```bash
crontab -e
# Add the following line:
* * * * * ping -c 4 8.8.8.8 > /tmp/ping_log.txt 2>&1
```

This runs every minute, pings Google DNS, and logs output to a file in `/tmp/` — mimicking a beacon that phones home on a schedule.

### Forensic Detection

**Step 1 — Check the user's crontab:**

```bash
crontab -l
# Output: * * * * * ping -c 4 8.8.8.8 > /tmp/ping_log.txt 2>&1
```

**Step 2 — Check the cron spool directly (works even if the user tries to hide it):**

```bash
sudo cat /var/spool/cron/psalms
# Output: * * * * * ping -c 4 8.8.8.8 > /tmp/ping_log.txt 2>&1
```

**Step 3 — Verify the cron job actually ran by checking its output:**

```bash
ls -lrt /tmp/ | grep ping_log
# Output: -rw-r--r--. 1 psalms psalms 615 Mar 18 21:55 ping_log.txt
```

<!-- IMAGE: Screenshot showing crontab -l, cat /var/spool/cron/psalms, and ls -lrt showing the ping_log.txt file -->
> **[IMAGE PLACEHOLDER — Lab 3: Crontab listing, spool file contents, and evidence of execution in /tmp/]**

**Step 4 — Check system-level crons (attackers often target these for root persistence):**

```bash
sudo grep -r "ping" /etc/cron*
cat /etc/crontab
ls -la /etc/cron.d/
ls -la /etc/cron.hourly/ /etc/cron.daily/
```

### Complete Cron Investigation Checklist

When investigating cron-based persistence, check **all** of these locations:

| Location | What Lives There | Who Can Modify |
|----------|-----------------|----------------|
| `crontab -l` | Current user's scheduled jobs | The user |
| `/var/spool/cron/<username>` | Raw crontab files per user | Root (direct edit) |
| `/etc/crontab` | System-wide cron jobs | Root only |
| `/etc/cron.d/` | Package-installed cron jobs | Root only |
| `/etc/cron.hourly/` | Scripts that run every hour | Root only |
| `/etc/cron.daily/` | Scripts that run daily | Root only |
| `/etc/cron.weekly/` | Scripts that run weekly | Root only |
| `/etc/cron.monthly/` | Scripts that run monthly | Root only |

### Key Takeaways

- Cron is one of the **most common persistence mechanisms** on Linux. Always check it during triage.
- `/var/spool/cron/` contains the raw crontab files — even if an attacker runs `crontab -r` to remove their entry, the file modification timestamp may still reveal when it was last changed.
- Output files in `/tmp/` are strong indicators — look for recently created files owned by unexpected users.
- **Detection rule idea:** Monitor for new entries in `/var/spool/cron/` or `crontab -e` execution in process logs. Alert on cron jobs that make network connections.

---

## Lab 5 — .bashrc Persistence

**Goal:** Plant a command in `.bashrc` that runs on every login, then find it.

**Scenario:** An attacker appends a malicious command to the user's `.bashrc` file. Every time the user opens a terminal or logs in via SSH, the command executes silently. This is stealthy because `.bashrc` is a legitimate file that's supposed to have commands in it.

**MITRE ATT&CK:** T1546.004 (Event Triggered Execution: Unix Shell Configuration Modification)

### Attack Simulation

**Inject a persistent command:**

```bash
echo 'ping -c 1 8.8.8.8 > /tmp/.hidden_ping &' >> ~/.bashrc
```

This appends a background ping command that runs on every login. The `&` sends it to the background so the user doesn't notice. The output file is prefixed with a dot (`.hidden_ping`) to hide it from casual `ls` commands.

### Forensic Detection

**Step 1 — Inspect `.bashrc` for non-standard entries:**

```bash
cat ~/.bashrc | grep -v "^#"
```

The `-v "^#"` filter removes comments, making injected lines stand out. The last line is immediately suspicious:

```
ping -c 1 8.8.8.8 > /tmp/.hidden_ping &
```

<!-- IMAGE: Screenshot showing cat ~/.bashrc with the malicious ping line highlighted at the bottom -->
> **[IMAGE PLACEHOLDER — Lab 5: .bashrc contents with injected ping command visible at the bottom, highlighted]**

**Step 2 — Compare against the default `.bashrc` template:**

```bash
diff ~/.bashrc /etc/skel/.bashrc
```

`/etc/skel/.bashrc` is the default template that gets copied to new users' home directories. Any lines that appear in the diff but not in the template are either user customizations or attacker injections.

**Step 3 — Check for evidence of execution:**

```bash
ls -la /tmp/.hidden_ping
# The dot prefix hides it from regular ls, but ls -la reveals it
```

### Investigation Checklist — Shell Config Persistence

An attacker can inject persistence into multiple shell configuration files. Check all of them:

| File | When It Runs | Scope |
|------|-------------|-------|
| `~/.bashrc` | Every interactive non-login shell (new terminal) | Per-user |
| `~/.bash_profile` | Login shells (SSH, console login) | Per-user |
| `~/.profile` | Login shells (fallback if no `.bash_profile`) | Per-user |
| `~/.bash_logout` | On logout (used for cleanup or exfil on exit) | Per-user |
| `/etc/profile` | All login shells, all users | System-wide |
| `/etc/profile.d/*.sh` | All login shells, all users | System-wide |
| `/etc/bash.bashrc` | All interactive shells, all users | System-wide |
| `~/.zshrc` | Zsh interactive shells | Per-user (if zsh) |

### Key Takeaways

- `.bashrc` persistence is **extremely stealthy** because the file is supposed to contain commands. Attackers blend in with legitimate shell configuration.
- Always `diff` against `/etc/skel/.bashrc` to identify additions. This is faster than reading every line.
- The `&` (background execution) and `.` prefix (hidden file) are classic attacker tradecraft for staying invisible.
- **Detection rule idea:** Monitor for `echo >> ~/.bashrc` or `>>` operators targeting any shell config file. Also use `auditd` rules to watch for modifications to `.bashrc` files: `auditctl -w /home/ -p wa -k bashrc_mod`.

---

## Lab 6 — Investigate a "Slow Server"

**Goal:** Build a real-world investigation command sheet by simulating CPU load, then triaging the system live.

**Scenario:** You get a ticket: "The server is slow." No other details. You need to systematically investigate CPU usage, identify the offending processes, check network connections, and resolve the issue. This is the most common real-world triage you'll do as an analyst.

**MITRE ATT&CK:** T1057 (Process Discovery), T1049 (System Network Connections Discovery)

### Attack Simulation

**Simulate CPU load with multiple background processes:**

```bash
dd if=/dev/zero of=/dev/null &
dd if=/dev/zero of=/dev/null &
dd if=/dev/zero of=/dev/null &
dd if=/dev/zero of=/dev/null &
```

This spawns 4 `dd` processes that consume 100% CPU each, simulating a cryptominer, resource-intensive malware, or a fork bomb.

<!-- IMAGE: Screenshot showing the 4 dd processes being spawned with their PIDs -->
> **[IMAGE PLACEHOLDER — Lab 6: Terminal showing 4 background dd processes with PIDs 4137, 4138, 4141, 4143]**

### Investigation Walkthrough

**Step 1 — Get the big picture with `top`:**

```bash
top -b -n 1 | head -20
```

| PID | USER | %CPU | %MEM | COMMAND |
|-----|------|------|------|---------|
| 4143 | attacker | 52.9 | 0.0 | dd |
| 4138 | attacker | 47.1 | 0.0 | dd |
| 4141 | attacker | 47.1 | 0.0 | dd |
| 4137 | attacker | 41.2 | 0.0 | dd |

Immediately suspicious: 4 processes by the same user (`attacker`) consuming nearly all CPU. The `dd` command is a legitimate utility, but running 4 instances writing to `/dev/null` is abnormal.

<!-- IMAGE: Screenshot of top output showing the 4 dd processes consuming all CPU -->
> **[IMAGE PLACEHOLDER — Lab 6: top output showing attacker-owned dd processes dominating CPU usage]**

**Step 2 — Get more detail on the suspicious processes:**

```bash
ps aux | grep dd
# Shows full command line including arguments
```

**Step 3 — Check what files the process has open:**

```bash
ls -la /proc/<PID>/fd/
# Shows file descriptors — what the process is reading/writing
ls -la /proc/<PID>/exe
# Shows the actual binary path — reveals renamed binaries
```

**Step 4 — Check network connections tied to processes:**

```bash
ss -tulpn
# or
netstat -tulpn 2>/dev/null || ss -tulpn
```

<!-- IMAGE: Screenshot of ss -tulpn showing network connections with associated PIDs -->
> **[IMAGE PLACEHOLDER — Lab 6: ss -tulpn output showing listening ports and associated processes]**

This reveals which processes have open network connections. If the CPU-eating process also has a network socket open, it's likely phoning home (C2) or participating in a DDoS.

**Step 5 — Kill the offending processes:**

```bash
kill -9 4137 4138 4141 4143
# Or kill all processes by a specific user:
pkill -u attacker
```

### Slow Server Investigation Command Sheet

Use this sequence for any "slow server" triage:

```bash
# 1. System overview — who's eating resources?
top -b -n 1 | head -20
uptime                          # load average context
free -h                         # memory pressure

# 2. Process deep dive
ps auxf --sort=-%cpu | head -20 # tree view, sorted by CPU
ps auxf --sort=-%mem | head -20 # sorted by memory

# 3. Inspect suspicious processes
ls -la /proc/<PID>/exe          # real binary path
cat /proc/<PID>/cmdline         # full command line
ls -la /proc/<PID>/fd/          # open file descriptors
cat /proc/<PID>/status          # UID, GID, threads

# 4. Network — is anything phoning home?
ss -tulpn                       # listening ports + PIDs
ss -tnp                         # established connections + PIDs
lsof -i -P -n                   # all network files by process

# 5. Disk — is something thrashing IO?
iotop -o -n 1                   # IO by process (if available)
iostat -x 1 3                   # disk utilization

# 6. Recent changes — what happened on this box?
last -20                        # recent logins
lastlog                         # last login per user
journalctl --since "1 hour ago" # recent system events
find /tmp -mmin -60 -ls         # files modified in last hour
```

### Key Takeaways

- Always start with `top` or `htop` for the big picture, then drill into `ps aux` for detail.
- `/proc/<PID>/exe` is your best friend — it reveals the **actual binary** even if the process name has been changed (see Lab 7).
- Network connections (`ss -tulpn`) are critical — a CPU-eating process with an established outbound connection is almost certainly malicious.
- The `attacker` username owning all suspicious processes is an obvious indicator here, but in the real world, attackers often run as existing service accounts or even root.

---

## Lab 7 — Renamed Binary (Process Hiding)

**Goal:** Rename a binary to look benign, run it, then detect the disguise.

**Scenario:** An attacker copies a legitimate binary (like `ping`) to a new location with a misleading name (like `sshd-helper`) to blend in with normal system processes. In `ps` output, it looks like a legitimate SSH-related process. This is a real technique — attackers frequently rename tools like `nmap`, `nc`, or custom implants to look like system services.

**MITRE ATT&CK:** T1036.003 (Masquerading: Rename System Utilities)

### Attack Simulation

**Copy and rename the binary:**

```bash
cp /usr/bin/ping /tmp/sshd-helper
/tmp/sshd-helper -c 100 8.8.8.8 &
```

Now if someone runs `ps aux`, they see a process called `sshd-helper` — which looks like a legitimate OpenSSH helper process. Most admins wouldn't look twice.

<!-- IMAGE: Screenshot showing the cp command, execution, and the ping output from the renamed binary -->
> **[IMAGE PLACEHOLDER — Lab 7: Terminal showing binary rename, execution, and ICMP ping output from "sshd-helper"]**

### Forensic Detection

**Step 1 — Find the process in `ps`:**

```bash
ps aux | grep "sshd-helper"
```

The process appears in the process list under its fake name. Without further investigation, it looks legitimate.

<!-- IMAGE: Screenshot of ps aux showing the sshd-helper process -->
> **[IMAGE PLACEHOLDER — Lab 7: ps aux output showing sshd-helper process running as attacker user]**

**Step 2 — Unmask it using `/proc`:**

```bash
ls -la /proc/<PID>/exe
```

This shows a symlink to the **actual binary on disk** — not the name the process was started with. Even if the attacker deleted the original binary after running it, this link reveals the truth (it would show `(deleted)` but still point to the original path).

**Step 3 — Compare the binary hash:**

```bash
md5sum /tmp/sshd-helper
md5sum /usr/bin/ping
# If the hashes match, sshd-helper IS ping, just renamed
```

**Step 4 — Check the `file` command:**

```bash
file /tmp/sshd-helper
# Output: ELF 64-bit LSB executable... (same as /usr/bin/ping)
```

**Step 5 — Check from where it was executed:**

```bash
cat /proc/<PID>/cmdline | tr '\0' ' '
# Shows: /tmp/sshd-helper -c 100 8.8.8.8
# Execution from /tmp/ is a massive red flag
```

### Red Flags for Renamed Binaries

| Indicator | Why It's Suspicious |
|-----------|-------------------|
| Binary running from `/tmp/`, `/dev/shm/`, or `/var/tmp/` | Legitimate binaries live in `/usr/bin/`, `/usr/sbin/`, etc. |
| Process name doesn't match `/proc/<PID>/exe` target | The binary was renamed or copied |
| Hash matches a known system utility | Attacker is reusing legitimate tools under fake names |
| Process owned by a non-root user but named like a system service | Real system services run as root or dedicated service accounts |
| Binary has recent creation timestamp in a temp directory | Dropped by an attacker recently |

### Key Takeaways

- **Never trust process names in `ps` output.** Always verify with `/proc/<PID>/exe` to see the real binary.
- Binaries running from `/tmp/`, `/dev/shm/`, or any world-writable directory are suspicious by default.
- Hash comparison (`md5sum` or `sha256sum`) definitively proves whether a binary is a renamed copy of something else.
- **Detection rule idea:** Monitor for process execution from `/tmp/`, `/dev/shm/`, or other temporary directories. Alert on any binary where the process name doesn't match the filename in `/proc/<PID>/exe`. Use `auditd`: `auditctl -w /tmp/ -p x -k tmp_exec`.

---

## Month 3 Summary

### What I Built

| Deliverable | Description | Lab |
|-------------|-------------|-----|
| User lifecycle log trail | Complete forensic evidence of a deleted user via `/var/log/secure` | Lab 1 |
| Brute-force detection across 3 log sources | `audit.log`, `secure`, and `FAILED` grep patterns | Lab 2 |
| Cron persistence detection checklist | All cron locations, detection commands, and investigation steps | Lab 3 |
| Shell config persistence checklist | All `.bashrc`/`.profile`/`.bash_profile` locations and `diff` technique | Lab 5 |
| Slow server investigation command sheet | Complete triage sequence from `top` to `ss` to `lsof` | Lab 6 |
| Renamed binary detection methodology | `/proc/<PID>/exe` verification, hash comparison, red flag indicators | Lab 7 |

### Tools Used

- `grep`, `cat`, `diff`, `ls`, `find` — core forensic commands
- `ps aux`, `top`, `ss`, `netstat`, `lsof` — process and network investigation
- `/proc` filesystem — ground truth for process analysis
- `md5sum` — binary verification
- `auditd` / `audit.log` — kernel-level audit trail
- Red Hat Linux VM — lab environment

### What's Next

Month 4 shifts from manual investigation to **automated detection** — taking everything learned here and building SIEM queries and dashboards in Splunk and ELK that would catch these attacks in real time. The forensic knowledge from this month becomes the foundation for writing detection rules that actually work because they're based on real attacker behavior, not theoretical checklists.
