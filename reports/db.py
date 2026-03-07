import sqlite3
import os
import json

DB_PATH = os.path.join(os.path.dirname(__file__), "threat_history.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_threats INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            timestamp TEXT,
            source_ip TEXT,
            country TEXT,
            attack_type TEXT,
            severity TEXT,
            target_resource TEXT,
            status TEXT,
            mitre_id TEXT,
            FOREIGN KEY(scan_id) REFERENCES threat_scans(scan_id)
        )
    """)
    
    conn.commit()
    conn.close()

def save_threats(threats: list, summary: dict):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    sev = summary.get("By Severity", {})
    cursor.execute("""
        INSERT INTO threat_scans (total_threats, critical_count, high_count, medium_count, low_count)
        VALUES (?, ?, ?, ?, ?)
    """, (
        summary.get("Total", 0),
        sev.get("Critical", 0),
        sev.get("High", 0),
        sev.get("Medium", 0),
        sev.get("Low", 0)
    ))
    
    scan_id = cursor.lastrowid
    
    events = []
    for t in threats:
        events.append((
            scan_id,
            t.get("Timestamp"),
            t.get("Source IP"),
            t.get("Country"),
            t.get("Attack Type"),
            t.get("Adjusted Severity", t.get("Severity")),
            t.get("Target Resource"),
            t.get("Status"),
            t.get("MITRE ID")
        ))
        
    cursor.executemany("""
        INSERT INTO threat_events (scan_id, timestamp, source_ip, country, attack_type, severity, target_resource, status, mitre_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, events)
    
    conn.commit()
    conn.close()

def get_scan_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, total_threats, critical_count, high_count FROM threat_scans ORDER BY timestamp ASC")
    rows = cursor.fetchall()
    conn.close()
    
    return [
        {"timestamp": row[0], "total": row[1], "critical": row[2], "high": row[3]}
        for row in rows
    ]
