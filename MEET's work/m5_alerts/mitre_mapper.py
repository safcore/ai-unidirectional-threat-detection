"""
M5 — MITRE ATT&CK Mapper
==========================
Maps detected threats to MITRE ATT&CK Enterprise framework tactics
and techniques. This gives the dashboard a structured kill-chain context.

Reference: https://attack.mitre.org/

Mapping table (Threat Class → MITRE):
  DDOS        → Impact / T1499 (Endpoint DoS)
  RECON       → Discovery / T1046 (Network Service Discovery)
  BEACON      → Command and Control / T1071 (Application Layer Protocol)
  DGA         → Command and Control / T1568.002 (DGA)
  TLS_ANOMALY → Command and Control / T1573 (Encrypted Channel)
  EXFIL       → Exfiltration / T1041 (Exfiltration Over C2 Channel)
  DNS_TUNNEL  → Exfiltration / T1048.003 (Exfil via DNS)
"""

from m5_alerts.schema import Alert

# ── MITRE ATT&CK mapping table ────────────────────────────────────────────────

MITRE_MAP = {
    "DDOS": {
        "tactic":        "Impact",
        "technique":     "Endpoint Denial of Service",
        "technique_id":  "T1499",
        "subtechniques": {
            "SYN_FLOOD":         ("T1499.002", "Service Exhaustion Flood"),
            "UDP_AMPLIFICATION": ("T1499.002", "Service Exhaustion Flood"),
            "VOLUMETRIC_DDOS":   ("T1499",     "Endpoint Denial of Service"),
        },
    },
    "RECON": {
        "tactic":        "Discovery",
        "technique":     "Network Service Discovery",
        "technique_id":  "T1046",
        "subtechniques": {
            "PORT_SCAN":     ("T1046",     "Network Service Discovery"),
            "NETWORK_SWEEP": ("T1018",     "Remote System Discovery"),
        },
    },
    "BEACON": {
        "tactic":        "Command and Control",
        "technique":     "Application Layer Protocol",
        "technique_id":  "T1071",
        "subtechniques": {
            "C2_BEACONING": ("T1071.001", "Web Protocols"),
        },
    },
    "DGA": {
        "tactic":        "Command and Control",
        "technique":     "Dynamic Resolution",
        "technique_id":  "T1568",
        "subtechniques": {
            "DGA_DOMAIN": ("T1568.002", "Domain Generation Algorithms"),
        },
    },
    "TLS_ANOMALY": {
        "tactic":        "Command and Control",
        "technique":     "Encrypted Channel",
        "technique_id":  "T1573",
        "subtechniques": {
            "TLS_JA3_ANOMALY":   ("T1573.002", "Asymmetric Cryptography"),
            "TLS_CERT_ANOMALY":  ("T1573",     "Encrypted Channel"),
        },
    },
    "EXFIL": {
        "tactic":        "Exfiltration",
        "technique":     "Exfiltration Over C2 Channel",
        "technique_id":  "T1041",
        "subtechniques": {
            "DATA_EXFILTRATION": ("T1041", "Exfiltration Over C2 Channel"),
        },
    },
    "DNS_TUNNEL": {
        "tactic":        "Exfiltration",
        "technique":     "Exfiltration Over Alternative Protocol",
        "technique_id":  "T1048",
        "subtechniques": {
            "DNS_TUNNEL": ("T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol"),
        },
    },
}


class MitreMapper:
    """
    Enriches Alert objects with MITRE ATT&CK tactic + technique information.
    """

    def enrich(self, alert: Alert) -> Alert:
        """Mutate alert in-place with MITRE context."""
        entry = MITRE_MAP.get(alert.threat_class)
        if not entry:
            return alert

        alert.mitre_tactic     = entry["tactic"]
        alert.mitre_technique  = entry["technique"]
        alert.mitre_technique_id = entry["technique_id"]

        # Override with subtechnique if available
        subtechs = entry.get("subtechniques", {})
        if alert.threat_subtype in subtechs:
            tid, tname = subtechs[alert.threat_subtype]
            alert.mitre_technique_id = tid
            alert.mitre_technique    = tname

        return alert

    def enrich_dict(self, alert_dict: dict) -> dict:
        """Enrich a raw alert dict in-place."""
        tc = alert_dict.get("threat_class", "")
        ts = alert_dict.get("threat_subtype", "")
        entry = MITRE_MAP.get(tc)
        if not entry:
            return alert_dict

        alert_dict["mitre_tactic"]        = entry["tactic"]
        alert_dict["mitre_technique"]     = entry["technique"]
        alert_dict["mitre_technique_id"]  = entry["technique_id"]

        subtechs = entry.get("subtechniques", {})
        if ts in subtechs:
            tid, tname = subtechs[ts]
            alert_dict["mitre_technique_id"] = tid
            alert_dict["mitre_technique"]    = tname

        return alert_dict
