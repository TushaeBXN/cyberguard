# CyberGuard AI — Live Threat Log

Real attackers caught by the CyberGuard AI honeypot network. All incidents verified against AbuseIPDB. Full DOCX reports in this directory.

---

## June 29, 2026 — 4 Attackers in 24 Hours

| Incident | Time (UTC) | IP | Origin | Classification | AbuseIPDB Reports |
|---|---|---|---|---|---|
| CGI-20260629-001 | 07:17 | 176.65.148.253 | Netherlands (Pfcloud UG) | Port Scanner | 1,602 from 180 sources |
| CGI-20260629-002 | 05:00 | 35.216.201.9 | Switzerland (Google GCP) | Full Exploit Scanner | 4,249 from 797 sources |
| CGI-20260629-003 | 04:49 | 94.156.152.234 | Romania (bulletproof hosting) | Suspected Mirai Botnet Node | 1,761 from 284 sources |
| CGI-20260629-004 | 05:12 | 4.193.139.29 | Singapore (Microsoft Azure) | JBoss RCE Exploit Scanner | 174 from 151 sources |

**Combined: 7,786 AbuseIPDB reports from 1,412 distinct sources worldwide — all active on the same day.**

### Payloads Captured

**001 — 176.65.148.253**
```
GET /login HTTP/1.1
```
Classic credential-stuffing reconnaissance. 100% abuse confidence.

**002 — 35.216.201.9**
```
GET /
GET /.git/config
GET /server-status
GET /.env
GET /config.json
GET /telescope/requests
GET /info.php
[RAW TLS PROBE]
```
Full automated exploit scanner. 9 probes in 5 seconds. Targeting source code, credentials, PHP, Laravel, Apache. Fingerprinted as EXPLOIT_SCANNER by CounterScrape deception system.

**003 — 94.156.152.234**
```
GET /login HTTP/1.1
```
Mirai botnet behavior. German Mirai-detector honeypot captured commands from this IP same day. Relentless repeat probing (24+ attempts logged by single reporter). IoT DDoS recruitment pattern.

**004 — 4.193.139.29**
```
HEAD /invoker/EJBInvokerServlet HTTP/1.1
HEAD /jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo HTTP/1.1
HEAD /invoker/JMXInvokerServlet HTTP/1.1
HEAD /web-console/ServerInfo.jsp HTTP/1.1
```
Purpose-built JBoss RCE scanner targeting CVE-2010-0738 and CVE-2012-0874 (unauthenticated remote code execution). Spoofs Firefox 38 user agent. Only 10 days old at time of capture.

---

## Honeypot Infrastructure

- **Platform:** Microsoft Azure VM (East US) — `cyberguard-honeypot`
- **Ports:** 2222 (SSH trap), 8080 (Web trap), 3307 (MySQL trap)
- **Logging:** All hits stored to `kerrigan_db.honeypot_events` via reverse SSH tunnel
- **AI Analysis:** Kerrigan-Fantasma processes each hit and stores attack patterns to adaptive memory
- **Detection:** Real-time toast notifications in CyberGuard AI app on every new hit

---

*Captured by CyberGuard AI Enterprise — Brian Tushae Thomas*
