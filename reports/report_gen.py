from fpdf import FPDF
import datetime
import os

class DarkReport(FPDF):
    def header(self):
        self.set_fill_color(13, 17, 23) # #0d1117 background
        self.rect(0, 0, 210, 297, 'F')
        self.set_font('Courier', 'B', 15)
        self.set_text_color(0, 255, 204) # #00ffcc neon cyan
        self.cell(0, 10, 'THREAT DETECTION DASHBOARD - SECURITY REPORT', 0, 1, 'C')
        self.set_font('Courier', '', 10)
        self.set_text_color(201, 209, 217) # #c9d1d9 font color
        self.cell(0, 10, f'Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Courier', 'I', 8)
        self.set_text_color(201, 209, 217)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(threats: list, summary: dict, output_path: str):
    pdf = DarkReport()
    pdf.add_page()
    
    # Executive Summary
    pdf.set_font('Courier', 'B', 14)
    pdf.set_text_color(255, 0, 127) # pink
    pdf.cell(0, 10, 'EXECUTIVE SUMMARY', 0, 1, 'L')
    pdf.set_font('Courier', '', 11)
    pdf.set_text_color(201, 209, 217)
    pdf.multi_cell(0, 8, f"Scan analyzed {summary.get('Total', 0)} events. "
                         f"Critical: {summary.get('By Severity', {}).get('Critical', 0)}, "
                         f"High: {summary.get('By Severity', {}).get('High', 0)}.")
    pdf.ln(5)
    
    # Top Threat Origins
    pdf.set_font('Courier', 'B', 14)
    pdf.set_text_color(255, 0, 127)
    pdf.cell(0, 10, 'TOP THREAT ORIGINS', 0, 1, 'L')
    pdf.set_font('Courier', '', 11)
    pdf.set_text_color(201, 209, 217)
    sorted_countries = sorted(summary.get("By Country", {}).items(), key=lambda x: x[1], reverse=True)[:5]
    for country, count in sorted_countries:
        pdf.cell(0, 8, f"{country}: {count} threats", 0, 1, 'L')
    pdf.ln(5)
    
    # Attack Type Breakdown
    pdf.set_font('Courier', 'B', 14)
    pdf.set_text_color(255, 0, 127)
    pdf.cell(0, 10, 'ATTACK TYPE BREAKDOWN', 0, 1, 'L')
    pdf.set_font('Courier', '', 11)
    pdf.set_text_color(201, 209, 217)
    sorted_types = sorted(summary.get("By Type", {}).items(), key=lambda x: x[1], reverse=True)
    for atype, count in sorted_types:
        pdf.cell(0, 8, f"{atype}: {count} threats", 0, 1, 'L')
    pdf.ln(5)
    
    # Critical Incidents
    pdf.set_font('Courier', 'B', 14)
    pdf.set_text_color(255, 0, 127)
    pdf.cell(0, 10, 'CRITICAL INCIDENTS', 0, 1, 'L')
    pdf.set_font('Courier', '', 10)
    pdf.set_text_color(201, 209, 217)
    critical_threats = [t for t in threats if t.get("Adjusted Severity") == "Critical"][:10]
    if not critical_threats:
        pdf.cell(0, 8, "No critical incidents detected.", 0, 1, 'L')
    else:
        for t in critical_threats:
            text_line = (f"[{t['Timestamp']}] {t['Source IP']} ({t['Country']}) - "
                         f"{t['Attack Type']} [Target: {t['Target Resource']}]")
            # Manually wrap text to max 85 chars per line
            import textwrap
            wrapped = textwrap.wrap(text_line, width=85)
            for line in wrapped:
                pdf.cell(0, 6, line, 0, 1, 'L')            
    pdf.output(output_path)
    return output_path
