# VulnAgent — System Architecture

## Why Not Nessus
| Dimension | Nessus | VulnAgent |
|-----------|--------|-----------|
| Cost | $3,990+/year | Free |
| Source | Closed binary | Open Python |
| AI Analysis | None | Groq LLaMA 3.3 contextual summaries |
| Learning value | Zero | Every module you built |
| Customization | Limited | Full control |
| Remediation | Generic | AI-prioritized with SLA dates |
| Export | PDF/CSV | Custom Excel with your schema |
| Scheduler | Manual or agent install | Built-in Python `schedule` |

## Data Flow
```
config.py (targets, schedule)
       │
       ▼
  validation.py ──► startup config + API key checks
       │
       ▼
  agent.py  ──────────────────────────────────────┐
  (orchestrator)                                    │
       │                                            │
       ├──► scanner.py          ──► raw_findings[]  │
       │    (socket port scan,                      │
       │     PowerShell OS detect,                  │
       │     DNS reverse lookup,                    │
       │     installed software inventory)          │
       │                                            │
       ├──► cve_lookup.py       ──► cve_data[]      │
       │    (NIST NVD API v2,                       │
       │     maps service/port → CVE list,          │
       │     fetches CVSS, public exploit flag,     │
       │     CPE-based product validation)          │
       │                                            │
       ├──► ai_analyst.py       ──► ai_output[]     │
       │    (Groq llama-3.3-70b-versatile,          │
       │     generates summary, solution,           │
       │     remediation target date)               │
       │                                            │
       ├──► reporter.py         ──► .xlsx file      │
       │    (merges all data,                       │
       │     writes Excel report)                   │
       │                                            │
       ├──► trend.py            ──► vuln-agent.db   │
       │    (SQLite: logs each scan,                │
       │     30-day rolling trend summary)          │
       │                                            │
       └──► STATE.md updated                        │
                                                    │
  scheduler.py ──────────────────────────────────►─┘
  (wraps agent.py on interval)
```

## Module Contracts

### scanner.py
**Input:** `target: str` (IP or hostname), `ports: range`
**Output:** `ScanResult` dataclass
```python
@dataclass
class ScanResult:
    ip: str
    dns_name: str                    # reverse DNS, "" if not found
    os: str                          # OS string or "Unknown"
    open_ports: list[PortInfo]
    installed_software: list[SoftwareInfo]  # PowerShell registry inventory

@dataclass
class PortInfo:
    port: int
    service: str         # "http", "ssh", "ftp", etc.
    banner: str          # grabbed banner if available
    state: str           # "open"

@dataclass
class SoftwareInfo:
    name: str
    version: str
    publisher: str
```

### cve_lookup.py
**Input:** `service: str`, `port: int`, `os: str`
**Output:** `list[CVERecord]`
```python
@dataclass
class CVERecord:
    cve_id: str               # "CVE-2024-1234"
    description: str          # raw NVD description
    cvss_score: float         # 0.0-10.0
    cvss_severity: str        # critical/high/medium/low
    cvss_version: str         # "3.1", "3.0", or "2.0"
    public_exploit: bool      # CISA KEV + NVD reference signals
    references: list[str]     # NVD URLs
    published: datetime
    related_service: str      # port/service that triggered the lookup
    nvd_affected_product: str # vendor + product extracted from CPE data
```

### ai_analyst.py
**Input:** `ScanResult`, `CVERecord`
**Output:** `AIAnalysis`
```python
@dataclass
class AIAnalysis:
    summary: str           # 2-3 sentence plain-English explanation
    solution: str          # step-by-step remediation
    remediation_target: date  # calculated from CVSS + SLA config
```

### reporter.py
**Input:** merged scan + CVE + AI data per row
**Output:** `./reports/vuln_report_YYYY-MM-DD_HH-MM.xlsx`

**Excel Schema (13 columns):**
| Col | Field | Source |
|-----|-------|--------|
| A | ID | UUID4 short |
| B | IP_Address | scanner |
| C | Operating_System | scanner (PowerShell/TTL) |
| D | DNS_Name | scanner (reverse DNS) |
| E | Status | "Open" default, user-editable |
| F | CVE_Name | NVD |
| G | CVSS_Score | NVD |
| H | Remediation_Target | AI (CVSS × SLA config) |
| I | Summary | Groq AI |
| J | Solution | Groq AI + NVD |
| K | Public_Exploit | NVD boolean → "Yes"/"No" |
| L | Vulnerability | nvd_affected_product or port/service |
| M | Reference | NVD URL |

### validation.py
**Input:** `config` module values
**Output:** `bool` — `True` if all required config present, `False` otherwise
**Checks:** `GROQ_API_KEY` (required), `NVD_API_KEY` (optional warning), `TARGETS`, `SCAN_PORTS`, `MAX_SOFTWARE_SEARCHES`

### trend.py
**Input:** `ScanResult`, `list[CVERecord]`
**Output:** SQLite rows in `vuln-agent.db`
**Queries:** `get_trend_summary(days=30)` → `{scans, avg_cves_per_scan, critical_cves, exploited_cves}`

### scheduler.py
**Input:** `config.SCHEDULE_INTERVAL`, `config.SCHEDULE_TIME`
**Behavior:** Wraps `agent.py` run on interval using `schedule` library
**Modes:** `daily@HH:MM`, `weekly@DAY@HH:MM`, `every N hours`, `every N minutes`

## Directory Layout
```
vuln-agent/
├── CLAUDE.md                  # Claude Code instructions
├── ARCHITECTURE.md            # This file
├── STATE.md                   # Scan state (auto-updated)
├── .env                       # GROQ_API_KEY, NVD_API_KEY (never committed)
├── .env.example               # Template (committed)
├── .gitignore
├── requirements.txt           # Runtime dependencies
├── requirements-dev.txt       # Dev/test dependencies (includes pytest)
├── config.py                  # User configuration
├── agent.py                   # Orchestrator + CLI entry point
├── scanner.py                 # Network scanning + software inventory
├── cve_lookup.py              # NIST NVD API client + CPE validation
├── ai_analyst.py              # Groq AI integration
├── reporter.py                # Excel report generator
├── scheduler.py               # Interval scheduling
├── validation.py              # Startup config validation
├── trend.py                   # SQLite trend tracking
├── setup.py                   # Interactive first-run setup wizard
├── generate_demo_report.py    # Demo Excel report for portfolio
├── tests/
│   ├── test_cve_lookup.py     # Version parsing + CPE extraction tests
│   └── test_trend.py          # Trend DB isolation tests
├── cache/                     # JSON cache of scan results
│   └── scan_YYYY-MM-DD.json
└── reports/                   # Generated Excel files
    └── vuln_report_YYYY-MM-DD_HH-MM.xlsx
```

## API References
- **NIST NVD API v2:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - Rate: 5 req/30s (no key), 50 req/30s (with key)
  - Filter by keyword: `?keywordSearch=apache`
  - Pagination: `startIndex` + `totalResults` handled automatically
  - No auth required for basic use
- **Groq API:** `llama-3.3-70b-versatile` model, free tier: 500 req/day
  - Used for: summary, solution, remediation date
  - Prompt: system + one CVERecord per call
  - Key: `GROQ_API_KEY` in `.env`

## Security Notes
- Agent scans only targets listed in `config.TARGETS`
- Default target is `127.0.0.1` (localhost only)
- No credentials stored — `.env` excluded from git
- Socket scanning is non-intrusive (SYN equivalent via connect())
- All output stays local — no external reporting endpoints
- NVD CPE filtering anchors AI summaries to actual affected products
