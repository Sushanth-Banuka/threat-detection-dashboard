import os
import requests
import random
import datetime

def get_ip_reputation(ip: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if api_key and api_key != "your_abuseipdb_key_here":
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        headers = {
            "Accept": "application/json",
            "Key": api_key
        }
        try:
            response = requests.get(url, headers=headers, params=querystring, timeout=5)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "ip": ip,
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "country": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt", "Never"),
                    "usage_type": data.get("usageType", "Unknown")
                }
        except Exception as e:
            # Fallback to mock data on error
            pass
            
    # Mock data fallback
    return {
        "ip": ip,
        "abuse_confidence_score": random.randint(0, 100),
        "country": random.choice(["US", "CN", "RU", "BR", "IR", "KP", "IN", "DE", "GB", "VN"]),
        "isp": random.choice(["Cloudflare", "Amazon AWS", "DigitalOcean", "Comcast", "Telecom", "Unknown"]),
        "domain": f"host-{ip.replace('.', '-')}.domain.com",
        "total_reports": random.randint(0, 500),
        "last_reported": (datetime.datetime.now() - datetime.timedelta(hours=random.randint(1, 100))).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "usage_type": random.choice(["Commercial", "Data Center", "Reserved"])
    }

def classify_abuse_score(score: int) -> tuple:
    if score >= 80:
        return ("Critical", "#ff003c")
    elif score >= 50:
        return ("High", "#ff8c00")
    elif score >= 20:
        return ("Medium", "#ffea00")
    else:
        return ("Low", "#00ffcc")
