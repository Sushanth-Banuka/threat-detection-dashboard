ATTACK_DEFINITIONS = {
    "Brute Force": {"mitre_id": "T1110", "description": "Attempting to gain access to accounts by guessing passwords or credentials."},
    "Port Scan": {"mitre_id": "T1046", "description": "Scanning a network to identify open ports and services."},
    "SQL Injection": {"mitre_id": "T1190", "description": "Exploiting vulnerabilities in web applications to execute destructive SQL queries."},
    "DDoS": {"mitre_id": "T1498", "description": "Network denial of service using high volume of traffic to degrade or disrupt service."},
    "Malware": {"mitre_id": "T1204", "description": "Malicious software executed to compromise systems or exfiltrate data."},
    "Phishing": {"mitre_id": "T1566", "description": "Deceptive emails or messages to fool targets into revealing sensitive information."},
    "Ransomware": {"mitre_id": "T1486", "description": "Encrypting data on target systems for impact, demanding payment for decryption."},
    "Lateral Movement": {"mitre_id": "T1570", "description": "Moving through a network from one system to another."}
}

def classify_threat(threat: dict) -> dict:
    attack_type = threat.get("Attack Type", "Unknown")
    definition = ATTACK_DEFINITIONS.get(attack_type, {"mitre_id": "Unknown", "description": "Unknown attack pattern."})
    
    enriched = threat.copy()
    enriched["MITRE ID"] = definition["mitre_id"]
    enriched["Description"] = definition["description"]
    
    # Adjust severity based on confidence score and type
    if threat.get("Confidence Score", 0) > 90 and attack_type in ["Ransomware", "SQL Injection"]:
        enriched["Adjusted Severity"] = "Critical"
    else:
        enriched["Adjusted Severity"] = threat.get("Severity", "Low")
        
    return enriched

def get_threat_summary(threats: list) -> dict:
    total = len(threats)
    by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    by_type = {}
    by_country = {}
    by_status = {}
    
    for t in threats:
        sev = t.get("Adjusted Severity", t.get("Severity"))
        if sev in by_severity:
            by_severity[sev] += 1
        else:
            by_severity[sev] = 1
            
        atype = t.get("Attack Type", "Unknown")
        by_type[atype] = by_type.get(atype, 0) + 1
        
        country = t.get("Country", "Unknown")
        by_country[country] = by_country.get(country, 0) + 1
        
        status = t.get("Status", "Unknown")
        by_status[status] = by_status.get(status, 0) + 1
        
    return {
        "Total": total,
        "By Severity": by_severity,
        "By Type": by_type,
        "By Country": by_country,
        "By Status": by_status
    }
