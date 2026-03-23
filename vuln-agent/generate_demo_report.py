#!/usr/bin/env python3
"""
generate_demo_report.py — Create a professional demo Excel report for LinkedIn portfolio
Generates a realistic but fictional vulnerability report to showcase VulnAgent capabilities.
"""

from datetime import datetime, timedelta
from pathlib import Path
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

# ── Column definitions ────────────────────────────────────────────────────────
COLUMNS = [
    ("ID",                 18),
    ("IP_Address",         16),
    ("Operating_System",   28),
    ("DNS_Name",           28),
    ("Status",             14),
    ("CVE_Name",           18),
    ("CVSS_Score",         12),
    ("Remediation_Target", 20),
    ("Summary",            55),
    ("Solution",           55),
    ("Public_Exploit",     16),
    ("Vulnerability",      35),
    ("Reference",          55),
]

# ── Color scheme (severity) ───────────────────────────────────────────────────
HEADER_COLOR = "1F3864"
CRITICAL_COLOR = "D32F2F"    # Red
HIGH_COLOR = "F57C00"         # Orange
MEDIUM_COLOR = "FBC02D"       # Yellow
LOW_COLOR = "7CB342"          # Green

# ── Demo vulnerability data ───────────────────────────────────────────────────
DEMO_VULNERABILITIES = [
    {
        "cve_id": "CVE-2024-3157",
        "cvss_score": 9.8,
        "port": 443,
        "service": "OpenSSL",
        "summary": "Critical buffer overflow in OpenSSL TLS handshake processing. Allows remote code execution with zero authentication.",
        "solution": "Update OpenSSL to version 3.0.14 or later. Apply security patches immediately. Monitor network traffic for exploitation attempts.",
        "public_exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-3157"
    },
    {
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.2,
        "port": 3306,
        "service": "MySQL",
        "summary": "Authentication bypass vulnerability in MySQL Server. Allows unauthenticated remote attackers to execute arbitrary SQL queries.",
        "solution": "Upgrade to MySQL 8.0.37 or 5.7.45. Implement network segmentation. Restrict database port access to trusted hosts only.",
        "public_exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    },
    {
        "cve_id": "CVE-2023-4891",
        "cvss_score": 7.5,
        "port": 80,
        "service": "Apache",
        "summary": "HTTP request smuggling in Apache httpd. Allows request processing logic to be bypassed, enabling cache poisoning and session hijacking.",
        "solution": "Update Apache httpd to 2.4.58 or later. Validate all HTTP request inputs. Consider implementing a WAF.",
        "public_exploit": "No",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-4891"
    },
    {
        "cve_id": "CVE-2024-2156",
        "cvss_score": 6.8,
        "port": 5432,
        "service": "PostgreSQL",
        "summary": "SQL injection vulnerability in query parameter sanitization. Allows authenticated users to execute arbitrary SQL.",
        "solution": "Upgrade PostgreSQL to 15.4 or later. Use parameterized queries exclusively. Apply input validation at application layer.",
        "public_exploit": "No",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-2156"
    },
    {
        "cve_id": "CVE-2023-2891",
        "cvss_score": 5.3,
        "port": 25,
        "service": "Sendmail",
        "summary": "Insecure temporary file handling in Sendmail. Allows local privilege escalation through symbolic link attacks.",
        "solution": "Upgrade Sendmail to 8.17.2 or later. Restrict file permissions on temp directories. Monitor /tmp for suspicious links.",
        "public_exploit": "No",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-2891"
    },
    {
        "cve_id": "CVE-2024-5678",
        "cvss_score": 3.7,
        "port": 22,
        "service": "OpenSSH",
        "summary": "Information disclosure in SSH banners. Server version leaked without authentication.",
        "solution": "Update OpenSSH to version 9.3 or later. Configure custom SSH banners that don't reveal version info.",
        "public_exploit": "No",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-5678"
    }
]


def _severity_color(score: float) -> str:
    """Return hex color based on CVSS score."""
    if score >= 9.0:
        return CRITICAL_COLOR
    elif score >= 7.0:
        return HIGH_COLOR
    elif score >= 4.0:
        return MEDIUM_COLOR
    return LOW_COLOR


def _thin_border() -> Border:
    thin = Side(style="thin", color="CCCCCC")
    return Border(left=thin, right=thin, top=thin, bottom=thin)


def _style_header_row(ws, num_cols: int) -> None:
    for col_idx in range(1, num_cols + 1):
        cell = ws.cell(row=3, column=col_idx)
        cell.font = Font(name="Calibri", bold=True, color="FFFFFF", size=11)
        cell.fill = PatternFill(fill_type="solid", fgColor=HEADER_COLOR)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = _thin_border()


def _style_data_row(ws, row: int, cvss_score: float, num_cols: int) -> None:
    bg_color = "FFFFFF" if row % 2 == 0 else "F5F5F5"
    for col_idx in range(1, num_cols + 1):
        cell = ws.cell(row=row, column=col_idx)
        cell.font = Font(name="Calibri", size=10)
        cell.fill = PatternFill(fill_type="solid", fgColor=bg_color)
        cell.alignment = Alignment(vertical="top", wrap_text=True)
        cell.border = _thin_border()

    # Highlight CVSS cell with severity color
    cvss_cell = ws.cell(row=row, column=7)  # Column G = CVSS_Score
    cvss_cell.fill = PatternFill(fill_type="solid", fgColor=_severity_color(cvss_score))
    cvss_cell.font = Font(
        name="Calibri", bold=True, size=10,
        color="FFFFFF" if cvss_score >= 7.0 else "000000"
    )
    cvss_cell.alignment = Alignment(horizontal="center", vertical="top")


def generate_demo_report(output_path: Path | None = None) -> Path:
    """
    Generate a professional demo Excel report for LinkedIn portfolio.

    Args:
        output_path: override default report path

    Returns:
        Path to generated .xlsx file
    """
    if not output_path:
        output_path = Path("./reports/DEMO_Vulnerability_Report.xlsx")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Vulnerabilities"

    # ── Title row ─────────────────────────────────────────────────────────────
    title_cell = ws.cell(row=1, column=1, value="VulnAgent — Vulnerability Report (DEMO)")
    ws.merge_cells(f"A1:M1")
    title_cell.font = Font(name="Calibri", bold=True, size=14, color="FFFFFF")
    title_cell.fill = PatternFill(fill_type="solid", fgColor=HEADER_COLOR)
    title_cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 30

    # ── Sub-header: scan metadata ─────────────────────────────────────────────
    meta = f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  Target: 192.168.1.100  |  Total Findings: {len(DEMO_VULNERABILITIES)}"
    meta_cell = ws.cell(row=2, column=1, value=meta)
    ws.merge_cells(f"A2:M2")
    meta_cell.font = Font(name="Calibri", italic=True, size=9, color="666666")
    meta_cell.alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[2].height = 18

    # ── Header row ────────────────────────────────────────────────────────────
    for col_idx, (col_name, col_width) in enumerate(COLUMNS, start=1):
        cell = ws.cell(row=3, column=col_idx, value=col_name.replace("_", " "))
        ws.column_dimensions[chr(64 + col_idx)].width = col_width
    _style_header_row(ws, len(COLUMNS))
    ws.row_dimensions[3].height = 22

    # ── Data rows ─────────────────────────────────────────────────────────────
    for row_idx, vuln in enumerate(DEMO_VULNERABILITIES, start=4):
        remediation_date = (datetime.now() + timedelta(days=7 if vuln["cvss_score"] >= 9.0 else 30)).strftime("%Y-%m-%d")

        row_data = [
            f"V{str(row_idx-3).zfill(4)}",  # ID
            "192.168.1.100",                 # IP_Address
            "Ubuntu 22.04 LTS",              # Operating_System
            "demo-server.local",             # DNS_Name
            "Open",                          # Status
            vuln["cve_id"],                  # CVE_Name
            vuln["cvss_score"],              # CVSS_Score
            remediation_date,                # Remediation_Target
            vuln["summary"],                 # Summary
            vuln["solution"],                # Solution
            vuln["public_exploit"],          # Public_Exploit
            f"{vuln['service'].upper()} (port {vuln['port']}) — {'CRITICAL' if vuln['cvss_score'] >= 9.0 else 'HIGH' if vuln['cvss_score'] >= 7.0 else 'MEDIUM' if vuln['cvss_score'] >= 4.0 else 'LOW'}",
            vuln["reference"]                # Reference
        ]

        for col_idx, value in enumerate(row_data, start=1):
            ws.cell(row=row_idx, column=col_idx, value=value)

        _style_data_row(ws, row_idx, vuln["cvss_score"], len(COLUMNS))
        ws.row_dimensions[row_idx].height = 80  # tall for wrapped text

    # ── Freeze panes & filter ─────────────────────────────────────────────────
    ws.freeze_panes = "A4"
    ws.auto_filter.ref = f"A3:M3"

    # ── Summary sheet ─────────────────────────────────────────────────────────
    ws2 = wb.create_sheet("Summary")
    _write_summary_sheet(ws2)

    # ── Save ──────────────────────────────────────────────────────────────────
    tmp_path = output_path.with_suffix(".tmp.xlsx")
    wb.save(tmp_path)
    tmp_path.rename(output_path)

    print(f"[OK] Demo report generated: {output_path}")
    return output_path


def _write_summary_sheet(ws) -> None:
    """Write a summary statistics sheet."""
    ws.title = "Summary"
    ws.column_dimensions["A"].width = 25
    ws.column_dimensions["B"].width = 15

    critical = sum(1 for v in DEMO_VULNERABILITIES if v["cvss_score"] >= 9.0)
    high     = sum(1 for v in DEMO_VULNERABILITIES if 7.0 <= v["cvss_score"] < 9.0)
    medium   = sum(1 for v in DEMO_VULNERABILITIES if 4.0 <= v["cvss_score"] < 7.0)
    low      = sum(1 for v in DEMO_VULNERABILITIES if 0 < v["cvss_score"] < 4.0)
    exploitable = sum(1 for v in DEMO_VULNERABILITIES if v["public_exploit"] == "Yes")

    rows = [
        ("SCAN SUMMARY", ""),
        ("Generated", datetime.now().strftime("%Y-%m-%d %H:%M")),
        ("Target Scanned", "192.168.1.100 (demo-server.local)"),
        ("OS Detected", "Ubuntu 22.04 LTS"),
        ("Scan Duration", "66 seconds"),
        ("Total Findings", len(DEMO_VULNERABILITIES)),
        ("", ""),
        ("SEVERITY BREAKDOWN", ""),
        ("Critical (CVSS 9-10)", critical),
        ("High (CVSS 7-8.9)",    high),
        ("Medium (CVSS 4-6.9)",  medium),
        ("Low (CVSS 0.1-3.9)",   low),
        ("", ""),
        ("With Public Exploit",  exploitable),
        ("Requires Immediate Action", critical + exploitable),
    ]

    for row_idx, (label, value) in enumerate(rows, start=1):
        label_cell = ws.cell(row=row_idx, column=1, value=label)
        value_cell = ws.cell(row=row_idx, column=2, value=value)

        if not value:  # section headers
            label_cell.font = Font(bold=True, size=11, color="FFFFFF")
            label_cell.fill = PatternFill(fill_type="solid", fgColor=HEADER_COLOR)
        elif label in ["SCAN SUMMARY", "SEVERITY BREAKDOWN"]:
            label_cell.font = Font(bold=True, size=11)
            label_cell.fill = PatternFill(fill_type="solid", fgColor="F5F5F5")

        value_cell.alignment = Alignment(horizontal="left")


if __name__ == "__main__":
    generate_demo_report()
