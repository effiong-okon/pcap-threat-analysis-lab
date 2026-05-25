# SOC Lab 2: PCAP Threat Analysis — LummaC2 Info-Stealer

## Overview
Packet capture analysis of a suspected info-stealer infection on an 
endpoint at Astley Financial. Using tcpdump on the command line, 
I analysed 1,344 packets to identify the malware family, reconstruct 
the attack timeline, recover stolen credentials, and map all activity 
to MITRE ATT&CK.

**Tools Used:** tcpdump, whois, curl
**Environment:** Ubuntu VM (VirtualBox)
**Framework:** MITRE ATT&CK

---

## Key Findings

| Finding | Detail |
|---|---|
| Infected Host | 10.0.2.10 |
| Malware Family | LummaC2 (LummaStealer) |
| Malware Indicator | User-Agent: TeslaBrowser/5.5 |
| C2 Channel | Telegram (hxxp://t[.]me/+zz0192lskaaa) |
| FTP Brute Force Target | 194.108.117.16 |
| Credentials Compromised | demo:password |
| File Retrieved | readme.txt |

---

## Attack Chain
Connectivity Check (ICMP → Cloudflare AS13335)
↓
C2 Contact via Telegram fallback channel
↓
HTTP POST credential exfiltration (port 80)
↓
FTP brute force → successful login (demo:password)
↓
File retrieval (readme.txt)

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Description |
|---|---|---|
| Discovery | T1016 | Network Configuration Discovery |
| Command & Control | T1102.002 | Web Service — Bidirectional C2 |
| Credential Access | T1110.001 | Brute Force: Password Guessing |
| Exfiltration | T1041 | Exfiltration over C2 Channel |
| Exfiltration | T1048 | Exfiltration over Alternative Protocol |

---

## Repository Structure
├── report/      → Full written incident report
├── screenshots/ → Evidence from tcpdump analysis
└── iocs/        → Indicators of Compromise

---

## Connect
- LinkedIn: https://linkedin.com/in/okon-effiong/
- SOC Lab 1 (Splunk/AWS): https://github.com/effiong-okon/soc-threat-detection-lab
