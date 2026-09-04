\# Threat Detection Alert Format



The Threat Detection Engine produces alerts in JSON format.



\## Fields



\- alert\_id — Unique alert ID

\- timestamp — Alert generation time

\- flow\_id — Related network flow

\- source.ip — Source IP address

\- source.port — Source port

\- destination.ip — Destination IP address

\- destination.port — Destination port

\- protocol — TCP / UDP / ICMP

\- threat\_class — Detected threat type

\- confidence — Detection score from 0 to 1

\- severity — LOW / MEDIUM / HIGH / CRITICAL

\- detection\_method — RULE currently; ML can be added later

\- evidence — Reasons/evidence for detection

\- mitre.tactic — MITRE tactic

\- mitre.technique\_id — Technique ID when verified

\- mitre.verify — Whether technique mapping needs verification

\- status — Current alert status



\## Current Threats



Currently implemented:



\- DDoS

\- Port Scan



Future threats:



\- DGA / DNS Tunnelling

\- Botnet C2 Beaconing

\- Data Exfiltration

\- Malicious Encrypted Traffic



\## Important



Frontend should use the JSON alert structure and should not depend

directly on Threat Detection Python internals.



The expected architecture is:



Threat Detection

&#x20;       ↓

Alert JSON

&#x20;       ↓

Backend API / WebSocket

&#x20;       ↓

Frontend Dashboard

