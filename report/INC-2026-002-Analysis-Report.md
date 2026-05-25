# SOC Assessment 2: Network Packet Capture Analysis
**Analyst:** Effiong Okon
**Institution:** AltSchool Africa
**Date:** May 2026
**Severity:** 🔴 High
**Status:** ✅ Closed, Analysis Complete

---

## 1. Executive Summary

An endpoint on the Astley Financial internal network (`10.0.2.10`) 
was flagged for abnormal behaviour. Packet capture analysis of 
`tcpdump_challenge.pcap` confirmed the host was infected with 
**LummaC2 (LummaStealer)**. An information-stealing malware 
available as a Malware-as-a-Service (MaaS).

The malware performed an ICMP connectivity check to a Cloudflare IP, 
contacted a Telegram-based C2 fallback channel using its signature 
`TeslaBrowser/5.5` user-agent, exfiltrated credentials via plain HTTP 
POST, and conducted an automated brute-force attack against an FTP 
server, successfully logging in and retrieving a file.

---

## 2. Scope & Tools

| Field | Detail |
|---|---|
| Capture File | `tcpdump_challenge.pcap` |
| Analysis Tools | `tcpdump`, `whois`, `curl` |
| Environment | Ubuntu VM (VirtualBox) |
| Framework | MITRE ATT&CK |

---

## 3. Findings Summary

| # | Question | Answer |
|---|---|---|
| 1 | Total packets in capture | **1344** |
| 2 | Total ICMP packets | **132** |
| 3 | ASN of pinged destination | **AS13335 (Cloudflare, Inc.)** |
| 4 | HTTP POST requests | **2** |
| 5 | Password found in HTTP payload | **ilovecats9102** |
| 6 | Second most frequent destination port | **53 (DNS)** |
| 7 | FTP credentials (username:password) | **demo:password** |
| 8 | File retrieved from FTP server | **readme.txt** |
| 9 | Malware family identified | **LummaC2 / LummaStealer** |
| 10 | Defanged C2 URL | **hxxp://t[.]me/+zz0192lskaaa** |

---

## 4. Detailed Analysis

### 4.1 File Reconnaissance

![Screenshot 1](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/01-file-recon.png)
The capture file was confirmed as a valid pcap format, **372KB** in 
size, recorded using EN10MB (Ethernet) link type with a snapshot 
length of 262144 bytes. File size indicates a focused, targeted 
capture rather than long-term monitoring.

---

### 4.2 Total Packet Count

![Screenshot 2](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/02-total-packets.png)
**1344 packets** were present in the capture. 

---

### 4.3 Conversation Summary (Top Talkers)

![Screenshot 3](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/03-conversation-summary.png)
Filtering for unique source→destination pairs immediately identified 
`10.0.2.10` as the infected endpoint communicating with four 
distinct external servers:

| External IP | Role |
|---|---|
| `184.84.32.104` | Primary HTTP destination |
| `172.67.72.15` | ICMP ping target (Cloudflare) |
| `194.108.117.16` | FTP brute-force target |
| `149.154.167.99` | Telegram C2 server |

A normal workstation communicating with four separate external 
servers across multiple protocols in a short timeframe is a 
significant red flag warranting immediate investigation.

---

### 4.4 ICMP Analysis — Connectivity Check

![Screenshot 4](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/04-icmp-packets.png)
The endpoint sent repeated **ICMP echo requests** (pings) to 
`172.67.72.15`. Sequence numbers incremented from 1 upward in 
consistent ~1-second intervals, a pattern characteristic of 
automated malware behaviour, not manual use of the `ping` command.

LummaStealer uses this ICMP connectivity check to confirm internet 
access before initiating its exfiltration routines.

> **MITRE ATT&CK:** T1016 — System Network Configuration Discovery

---

### 4.5 ASN Lookup of Pinged Destination

![Screenshot 5](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/05-asn-lookup.png)
Destination IP:  172.67.72.15
Organisation:    Cloudflare, Inc.
ASN:             AS13335

Pinging Cloudflare infrastructure (`AS13335`) is a documented 
LummaStealer behaviour. Cloudflare's global network is 
virtually always reachable, making it a reliable connectivity 
verification target.

---

### 4.6 HTTP POST Requests: Data Exfiltration

![Screenshot 6](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/06-http-post-count.png)
**2 HTTP POST requests** were identified on port 80. HTTP POST 
is the primary mechanism info-stealers use to transmit stolen 
data (credentials, cookies, keylogger output) to a C2 server. 
Each POST request in this context warranted payload inspection.

> **MITRE ATT&CK:** T1041 — Exfiltration Over C2 Channel

---

### 4.7 Credentials Found in HTTP Payload

![Screenshot 7](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/07-http-credentials.png)
Cleartext credentials were recovered directly from an HTTP POST 
payload body:
name=bsmith&password=ilovecats9102

| Field | Value |
|---|---|
| Username | `bsmith` |
| Password | `ilovecats9102` |

This is possible because the malware communicated over **plain 
HTTP (port 80)** rather than HTTPS, leaving all payload data 
fully visible in the packet capture. User `bsmith` at Astley 
Financials have been fully compromised.

> **Key Learning:** This is exactly why HTTPS enforcement 
> matters organisation-wide. Any credential submitted over 
> plain HTTP is readable by any analyst or attacker, with 
> access to network traffic.

---

### 4.8 User-Agent Analysis & Malware Identification

![Screenshot 8](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/08-user-agent-analysis.png)

Among dozens of identical legitimate Chromium browser strings, 
One anomalous user-agent was identified:
User-Agent: TeslaBrowser/5.5       ← MALICIOUS
User-Agent: Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.1
... Chromium/14.0.825.0  ← Legitimate (repeated)

`TeslaBrowser/5.5` is a **hardcoded, non-existent browser** 
string embedded in LummaStealer's source code. It is one of 
the most well-documented IOCs for this malware family, 
referenced in threat intelligence reports from Microsoft, 
Darktrace and AhnLab.

**Malware identified: LummaC2 (LummaStealer)**

> LummaStealer is an info-stealer written in C, sold as a 
> Malware-as-a-Service on Russian-speaking forums since 
> August 2022. It targets passwords, browser data, 
> cryptocurrency wallets, and 2FA extensions.

---

### 4.9 C2 URL Reconstruction: Telegram Fallback Channel

![Screenshot 9](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/09-teslabrowser-url.png)
Method:    GET
Path:      /+zz0192lskaaa
Host:      t.me
Dest IP:   149.154.167.99
Port:      80
Full URL:  http://t.me/+zz0192lskaaa
Defanged:  hxxp://t[.]me/+zz0192lskaaa

`t.me` is Telegram's domain. LummaStealer uses hardcoded 
Telegram channels as a **fallback C2 mechanism** — when 
Primary C2 servers are unreachable, and the malware contacts 
This channel to receive updated server addresses. Telegram 
is rarely blocked in corporate environments, making it an 
effective evasion technique.

> **MITRE ATT&CK:** T1102.002 — Web Service: Bidirectional 
> Communication

---

### 4.10 Port Frequency Analysis

![Screenshot 10](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/10-port-frequency.png)
Port 80  → 439 packets  (HTTP)   — Primary C2 channel
Port 53  → 143 packets  (DNS)    — Domain resolution
Port 21  →  67 packets  (FTP)    — Brute-force target

**Port 53 (DNS)** was the second most frequent well-known 
destination port. 143 DNS queries in a short window is 
consistent with the malware resolving multiple C2 domains 
before establishing connections, a volume worth alerting on.

**Port 21 (FTP)**, while lower in volume, led directly to 
The credential brute-force discovery.

---

### 4.11 FTP Brute Force & File Retrieval

![Screenshot 11](https://raw.githubusercontent.com/effiong-okon/pcap-threat-analysis-lab/main/screenshots/11-ftp-brute-force.png)

The infected endpoint ran an automated credential attack 
against FTP server `194.108.117.16`:

| Attempt | Username | Password | Result |
|---|---|---|---|
| 1 | admin | admin | ❌ Failed |
| 2 | root | pass123 | ❌ Failed |
| 3 | administrator | password | ❌ Failed |
| 4 | admin | password123 | ❌ Failed |
| 5 | demo | password | ✅ **230 Login SUCCESS** |

Immediately after successful login:
RETR readme.txt  →  File downloaded from FTP server

**Valid credentials:** `demo:password`
**File retrieved:** `readme.txt`

> **MITRE ATT&CK:**
> - T1110.001 — Brute Force: Password Guessing
> - T1048 — Exfiltration Over Alternative Protocol (FTP)

---

## 5. Attack Timeline
15:53:51  ICMP pings begin
10.0.2.10 → 172.67.72.15 (Cloudflare AS13335)
Malware verifying internet connectivity
[~15:54]  HTTP POST × 2 → port 80
Credentials of bsmith exfiltrated in plaintext
15:54:27  HTTP GET → hxxp://t[.]me/+zz0192lskaaa
LummaStealer contacts Telegram C2 fallback channel
Identified by: User-Agent: TeslaBrowser/5.5
15:53:56  FTP brute force begins → 194.108.117.16:21
Automated credential list attack (4 failures)
15:54:16  FTP login SUCCESS
230 User 'demo' logged in (demo:password)
15:54:21  RETR readme.txt
File downloaded from compromised FTP server

---

## 6. Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| IPv4 | `10.0.2.10` | Infected endpoint |
| IPv4 | `149.154.167.99` | Telegram C2 server |
| IPv4 | `194.108.117.16` | FTP brute-force target |
| IPv4 | `172.67.72.15` | ICMP connectivity check target |
| URL (defanged) | `hxxp://t[.]me/+zz0192lskaaa` | Telegram C2 channel |
| User-Agent | `TeslaBrowser/5.5` | LummaStealer HTTP fingerprint |
| Credentials | `bsmith:ilovecats9102` | Exfiltrated via HTTP POST |
| Credentials | `demo:password` | Compromised FTP account |
| Filename | `readme.txt` | Retrieved from FTP server |
| Malware Family | LummaC2 / LummaStealer | MaaS info-stealer |

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|---|---|---|---|
| Discovery | T1016 | System Network Config Discovery | ICMP to Cloudflare |
| Command & Control | T1102.002 | Web Service: Bidirectional C2 | Telegram channel |
| Credential Access | T1110.001 | Brute Force: Password Guessing | FTP attack |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | HTTP POST credentials |
| Exfiltration | T1048 | Exfiltration Over Alt Protocol | FTP file retrieval |

---

## 8. Recommendations

1. **Block `TeslaBrowser/5.5` at the web proxy**: Any HTTP 
   Request with this user-agent should trigger an immediate 
   alert and be dropped.

2. **Restrict outbound FTP (port 21)**: Endpoints should 
   never initiate FTP connections to external IPs. Block at 
   the firewall and alert on any attempt.

3. **Enforce HTTPS organisation-wide**: credentials 
   transmitted over plain HTTP are fully visible to anyone 
   with network access. All internal applications must use 
   TLS.

4. **Remove default FTP credentials**: `demo:password` 
   must not exist on any server. Audit all FTP servers 
   for weak or default accounts immediately.

5. **Alert on high-volume DNS from single endpoints**: 143 DNS queries in minutes from one workstation warrants 
   automated SIEM detection.

6. **Review Telegram access policy**: If Telegram is not 
   a business requirement, block `t.me` and `149.154.167.99` 
   at the perimeter firewall.

---

*Report prepared as part of AltSchool Africa SOC Analyst curriculum.*
*Analyst: Effiong Okon | GitHub: github.com/effiong-okon*
