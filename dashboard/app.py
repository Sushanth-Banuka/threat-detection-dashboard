import streamlit as st
import pandas as pd
import plotly.express as px
import folium
from streamlit_folium import st_folium
import os
import sys
import json
from dotenv import load_dotenv

# Add parent dir to path to allow importing from related modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.mock_threats import generate_mock_threats
from detectors.threat_classifier import classify_threat, get_threat_summary
from detectors.ip_reputation import get_ip_reputation, classify_abuse_score
from reports.db import init_db, save_threats, get_scan_history
from reports.report_gen import generate_pdf_report

load_dotenv()

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")

# CSS Styling rules
st.markdown("""
<style>
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Courier New', Courier, monospace;
    }
    h1, h2, h3, h4, h5, h6 {
        text-transform: uppercase;
        letter-spacing: 2px;
        color: #00ffcc !important;
    }
    .metric-box {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 5px;
        padding: 15px;
        text-align: center;
    }
    .metric-value {
        font-size: 24px;
        font-weight: bold;
        color: #ff007f;
    }
    .metric-label {
        font-size: 12px;
        text-transform: uppercase;
        color: #8b949e;
    }
</style>
""", unsafe_allow_html=True)

# Authentication
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("SYSTEM LOGIN EXPOSED")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("AUTHENTICATE")
        
        if submit:
            if username == "admin" and password == "cybersecurity":
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("ACCESS DENIED")
    st.stop()

# Initialize DB
init_db()

# Sidebar
with st.sidebar:
    st.header("CONTROLS")
    if st.button("LOGOUT"):
        st.session_state.authenticated = False
        st.rerun()
        
    st.markdown("---")
    threat_volume = st.slider("THREAT VOLUME", min_value=20, max_value=200, value=50)
    if st.button("INITIATE THREAT SCAN"):
        raw_threats = generate_mock_threats(threat_volume)
        enriched_threats = [classify_threat(t) for t in raw_threats]
        summary = get_threat_summary(enriched_threats)
        
        save_threats(enriched_threats, summary)
        
        st.session_state.threats = enriched_threats
        st.session_state.summary = summary
        st.success("SCAN COMPLETE")

if "threats" not in st.session_state:
    st.info("Initiate a threat scan from the sidebar to begin.")
    st.stop()

threats = st.session_state.threats
summary = st.session_state.summary

# Header Metrics Row
col1, col2, col3, col4, col5, col6 = st.columns(6)
def metric_card(col, label, value):
    col.markdown(f"""
        <div class="metric-box">
            <div class="metric-value">{value}</div>
            <div class="metric-label">{label}</div>
        </div>
    """, unsafe_allow_html=True)

metric_card(col1, "TOTAL", summary["Total"])
metric_card(col2, "CRITICAL", summary.get("By Severity", {}).get("Critical", 0))
metric_card(col3, "HIGH", summary.get("By Severity", {}).get("High", 0))
metric_card(col4, "MEDIUM", summary.get("By Severity", {}).get("Medium", 0))
metric_card(col5, "LOW", summary.get("By Severity", {}).get("Low", 0))
metric_card(col6, "BLOCKED", summary.get("By Status", {}).get("Blocked", 0))

st.markdown("---")

# Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs(["THREAT MAP", "ANALYTICS", "IP REPUTATION", "ALERT LOG", "EXPORT"])

# Severity Colors Mapping
SEVERITY_COLORS = {
    "Critical": "#ff003c",
    "High": "#ff8c00",
    "Medium": "#ffea00",
    "Low": "#00ffcc"
}

# STATUS Colors Mapping
STATUS_COLORS = {
    "Blocked": "#3fb950",
    "Investigating": "#ffea00",
    "Ignored": "#8b949e",
    "Escalated": "#ff003c"
}

# Theme settings for Plotly
PLOTLY_THEME = dict(
    paper_bgcolor="#0d1117",
    plot_bgcolor="#161b22",
    font=dict(color="#c9d1d9", family="Courier New")
)

with tab1:
    st.header("THREAT MAP")
    m = folium.Map(location=[20, 0], zoom_start=2, tiles="CartoDB dark_matter")
    for t in threats:
        color = SEVERITY_COLORS.get(t.get("Adjusted Severity", "Low"), "#ffffff")
        popup_html = f"<b>IP:</b> {t['Source IP']}<br><b>Country:</b> {t['Country']}<br><b>Attack:</b> {t['Attack Type']}<br><b>Target:</b> {t['Target Resource']}"
        folium.CircleMarker(
            location=[t["Latitude"], t["Longitude"]],
            radius=5,
            color=color,
            fill=True,
            fill_color=color,
            fill_opacity=0.7,
            popup=folium.Popup(popup_html, max_width=300)
        ).add_to(m)
    st_folium(m, width=1200, height=500, returned_objects=[])

with tab2:
    st.header("ANALYTICS")
    c1, c2 = st.columns(2)
    
    # Donut chart (severity)
    df_sev = pd.DataFrame(list(summary.get("By Severity", {}).items()), columns=["Severity", "Count"])
    if not df_sev.empty:
        fig_sev = px.pie(df_sev, names="Severity", values="Count", hole=0.5, color="Severity", 
                         color_discrete_map=SEVERITY_COLORS)
        fig_sev.update_layout(**PLOTLY_THEME)
        c1.plotly_chart(fig_sev, use_container_width=True)
    
    # Horizontal bar chart (attack types)
    df_attack = pd.DataFrame(list(summary.get("By Type", {}).items()), columns=["Attack Type", "Count"])
    if not df_attack.empty:
        df_attack = df_attack.sort_values("Count", ascending=True)
        fig_attack = px.bar(df_attack, x="Count", y="Attack Type", orientation='h', color_discrete_sequence=["#00ffcc"])
        fig_attack.update_layout(**PLOTLY_THEME)
        c2.plotly_chart(fig_attack, use_container_width=True)
    
    c3, c4 = st.columns(2)
    # Bar chart (top 10 countries)
    df_country = pd.DataFrame(list(summary.get("By Country", {}).items()), columns=["Country", "Count"])
    if not df_country.empty:
        df_country = df_country.sort_values("Count", ascending=False).head(10)
        fig_country = px.bar(df_country, x="Country", y="Count", color_discrete_sequence=["#ff007f"])
        fig_country.update_layout(**PLOTLY_THEME)
        c3.plotly_chart(fig_country, use_container_width=True)
    
    # Line chart (historical trends)
    history = get_scan_history()
    if history:
        df_hist = pd.DataFrame(history)
        fig_hist = px.line(df_hist, x="timestamp", y=["total", "critical", "high"], 
                           color_discrete_map={"total": "#00ffcc", "critical": "#ff003c", "high": "#ff8c00"})
        fig_hist.update_layout(**PLOTLY_THEME)
        c4.plotly_chart(fig_hist, use_container_width=True)
    else:
        c4.info("No historical data available yet.")

with tab3:
    st.header("IP REPUTATION")
    
    sc1, sc2 = st.columns([3, 1])
    target_ip = sc1.text_input("ENTER IP ADDRESS", placeholder="e.g. 192.168.1.1")
    scan_clicked = sc2.button("SCAN IP")
    
    st.markdown("### QUICK SCAN FROM CURRENT FEED:")
    unique_ips = list(set([t["Source IP"] for t in threats]))[:10]
    cols = st.columns(5)
    for i, ip_opt in enumerate(unique_ips):
        if cols[i%5].button(ip_opt):
            target_ip = ip_opt
            scan_clicked = True
            
    if scan_clicked and target_ip:
        with st.spinner("QUERYING REPUTATION DATABASE..."):
            rep_data = get_ip_reputation(target_ip)
            label, color = classify_abuse_score(rep_data["abuse_confidence_score"])
            
            st.markdown(f"""
            <div style="border: 2px solid {color}; padding: 20px; border-radius: 10px; margin-top: 20px; background-color: #161b22;">
                <h3 style="color: {color}; margin-top: 0;">{target_ip} - {label.upper()} ({rep_data["abuse_confidence_score"]}/100)</h3>
                <table style="width: 100%; color: #c9d1d9;">
                    <tr><td><b>Country:</b> {rep_data['country']}</td><td><b>ISP:</b> {rep_data['isp']}</td></tr>
                    <tr><td><b>Domain:</b> {rep_data['domain']}</td><td><b>Usage Type:</b> {rep_data['usage_type']}</td></tr>
                    <tr><td><b>Total Reports:</b> {rep_data['total_reports']}</td><td><b>Last Reported:</b> {rep_data['last_reported']}</td></tr>
                </table>
            </div>
            """, unsafe_allow_html=True)

with tab4:
    st.header("ALERT LOG")
    lc1, lc2, lc3 = st.columns(3)
    
    severities = list(set([t.get("Adjusted Severity", "Low") for t in threats]))
    attacks = list(set([t.get("Attack Type", "Unknown") for t in threats]))
    statuses = list(set([t.get("Status", "Unknown") for t in threats]))
    
    sel_sev = lc1.multiselect("FILTER BY SEVERITY", severities, default=severities)
    sel_attack = lc2.multiselect("FILTER BY ATTACK TYPE", attacks, default=attacks)
    sel_status = lc3.multiselect("FILTER BY STATUS", statuses, default=statuses)
    
    filtered_threats = [
        t for t in threats 
        if t.get("Adjusted Severity", "Low") in sel_sev and t.get("Attack Type", "Unknown") in sel_attack and t.get("Status", "Unknown") in sel_status
    ]
    
    df_alerts = pd.DataFrame(filtered_threats)
    if not df_alerts.empty:
        df_alerts = df_alerts[["Timestamp", "Source IP", "Country", "Attack Type", "Adjusted Severity", "Target Resource", "Status", "MITRE ID"]]
        
        def highlight_severity(val):
            color = SEVERITY_COLORS.get(val, "#ffffff")
            return f'color: {color}; font-weight: bold;'
            
        def highlight_status(val):
            color = STATUS_COLORS.get(val, "#ffffff")
            return f'color: {color};'

        styled_df = df_alerts.style.map(highlight_severity, subset=["Adjusted Severity"]).map(highlight_status, subset=["Status"])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
    else:
        st.warning("NO ALERTS MATCH THE CURRENT FILTERS.")

with tab5:
    st.header("EXPORT DATA")
    st.write("Download threat intelligence reports and raw data.")
    
    # PDF
    report_path = "threat_report.pdf"
    if st.button("GENERATE PDF REPORT"):
        generate_pdf_report(threats, summary, report_path)
        if os.path.exists(report_path):
            with open(report_path, "rb") as f:
                pdf_bytes = f.read()
            st.download_button(label="DOWNLOAD PDF", data=pdf_bytes, file_name="threat_report.pdf", mime="application/pdf")
        else:
            st.error("Report generation failed.")
        
    # CSV
    csv_data = pd.DataFrame(threats).to_csv(index=False).encode('utf-8')
    st.download_button("DOWNLOAD CSV", data=csv_data, file_name="threats.csv", mime="text/csv")
    
    # JSON
    json_data = json.dumps(threats, indent=4).encode('utf-8')
    st.download_button("DOWNLOAD JSON", data=json_data, file_name="threats.json", mime="application/json")
