"""
test_trend.py - Unit tests for trend tracking
"""

import sys
import pytest
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import ScanResult, SoftwareInfo
from cve_lookup import CVERecord
import trend


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect DB_PATH to a temp file so tests never touch the production database.
    Also reset the init flag so each test gets a fresh schema."""
    monkeypatch.setattr(trend, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(trend, "_db_initialized", False)


def test_trend_db_init():
    """Test database initialization."""
    trend.init_db()  # Should not raise


def test_log_and_query():
    """Test logging a scan and querying trends against an isolated database."""
    scan = ScanResult(
        ip="127.0.0.1",
        dns_name="localhost",
        os="Windows 11",
        installed_software=[
            SoftwareInfo(name="Test App", version="1.0.0", publisher="Test Publisher"),
        ],
    )

    cves = [
        CVERecord(
            cve_id="CVE-2024-0001",
            description="Test critical CVE",
            cvss_score=9.8,
            cvss_severity="critical",
            cvss_version="3.1",
            public_exploit=True,
            published=datetime.now(),
        ),
        CVERecord(
            cve_id="CVE-2024-0002",
            description="Test high CVE",
            cvss_score=7.5,
            cvss_severity="high",
            cvss_version="3.1",
            public_exploit=False,
            published=datetime.now(),
        ),
    ]

    trend.log_scan(scan, cves)
    result = trend.get_trend_summary(days=1)

    assert result["scans"] == 1, f"Expected exactly 1 scan, got {result['scans']}"
    assert result["critical_cves"] == 1, f"Expected 1 critical CVE, got {result['critical_cves']}"
    assert result["exploited_cves"] == 1, f"Expected 1 exploited CVE, got {result['exploited_cves']}"
    assert result["avg_cves_per_scan"] == 2.0, f"Expected avg 2.0 CVEs, got {result['avg_cves_per_scan']}"


def test_clean_scan_logged():
    """A scan with no CVEs should still appear in trend counts."""
    scan = ScanResult(ip="192.168.1.1", dns_name="", os="Unknown")
    trend.log_scan(scan, [])
    result = trend.get_trend_summary(days=1)
    assert result["scans"] == 1
    assert result["critical_cves"] == 0
    assert result["avg_cves_per_scan"] == 0.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
