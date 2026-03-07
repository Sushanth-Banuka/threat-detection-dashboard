import random
import datetime
from typing import List, Dict

ATTACK_TYPES = ["Brute Force", "Port Scan", "SQL Injection", "DDoS", "Malware", "Phishing", "Ransomware", "Lateral Movement"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHTS = [0.1, 0.3, 0.4, 0.2]
TARGET_RESOURCES = ["Web Server", "Database", "API Gateway", "Active Directory", "Email Server", "VPN Gateway", "Endpoint", "Payment Gateway"]
STATUSES = ["Blocked", "Investigating", "Ignored", "Escalated"]

# 10 realistic countries with avg lat/long
COUNTRIES = [
    {"Country": "United States", "Country Code": "US", "Latitude": 37.0902, "Longitude": -95.7129},
    {"Country": "China", "Country Code": "CN", "Latitude": 35.8617, "Longitude": 104.1954},
    {"Country": "Russia", "Country Code": "RU", "Latitude": 61.5240, "Longitude": 105.3188},
    {"Country": "Brazil", "Country Code": "BR", "Latitude": -14.2350, "Longitude": -51.9253},
    {"Country": "Iran", "Country Code": "IR", "Latitude": 32.4279, "Longitude": 53.6880},
    {"Country": "North Korea", "Country Code": "KP", "Latitude": 40.3399, "Longitude": 127.5101},
    {"Country": "India", "Country Code": "IN", "Latitude": 20.5937, "Longitude": 78.9629},
    {"Country": "Germany", "Country Code": "DE", "Latitude": 51.1657, "Longitude": 10.4515},
    {"Country": "United Kingdom", "Country Code": "GB", "Latitude": 55.3781, "Longitude": -3.4360},
    {"Country": "Vietnam", "Country Code": "VN", "Latitude": 14.0583, "Longitude": 108.2772}
]

def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def generate_mock_threats(count: int = 50) -> List[Dict]:
    threats = []
    now = datetime.datetime.now()
    for _ in range(count):
        country_info = random.choice(COUNTRIES)
        # Randomize lat/long slightly
        lat = country_info["Latitude"] + random.uniform(-2.0, 2.0)
        lon = country_info["Longitude"] + random.uniform(-2.0, 2.0)
        
        threat = {
            "Timestamp": (now - datetime.timedelta(minutes=random.randint(0, 1440))).strftime("%Y-%m-%d %H:%M:%S"),
            "Source IP": generate_ip(),
            "Country": country_info["Country"],
            "Country Code": country_info["Country Code"],
            "Latitude": round(lat, 4),
            "Longitude": round(lon, 4),
            "Attack Type": random.choice(ATTACK_TYPES),
            "Severity": random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0],
            "Target Resource": random.choice(TARGET_RESOURCES),
            "Status": random.choice(STATUSES),
            "Confidence Score": random.randint(40, 100)
        }
        threats.append(threat)
    
    # Sort by timestamp descending
    threats.sort(key=lambda x: x["Timestamp"], reverse=True)
    return threats
