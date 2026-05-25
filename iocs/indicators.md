# Indicators of Compromise — INC-2026-002

## Network IOCs

| Type | Value | Context |
|---|---|---|
| IPv4 | 10.0.2.10 | Infected endpoint |
| IPv4 | 149.154.167.99 | Telegram C2 server |
| IPv4 | 194.108.117.16 | FTP brute force target |
| IPv4 | 172.67.72.15 | ICMP ping target (Cloudflare AS13335) |
| URL (defanged) | hxxp://t[.]me/+zz0192lskaaa | LummaC2 Telegram C2 channel |

## Host IOCs

| Type | Value | Context |
|---|---|---|
| User-Agent | TeslaBrowser/5.5 | LummaStealer HTTP fingerprint |
| Credentials | demo:password | Compromised FTP account |
| Filename | readme.txt | File retrieved from FTP server |

## Malware

| Field | Detail |
|---|---|
| Family | LummaC2 / LummaStealer |
| Type | Info-Stealer / MaaS |
| First seen | August 2022 |
| C2 Method | HTTP POST + Telegram fallback |
