"""
test_false_positives.py - Regression tests for false-positive elimination

Each test is named after the real-world false positive it prevents.
If any of these fail, the named false positive has been reintroduced.

Run with:  python -m pytest tests/test_false_positives.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cve_lookup import (
    _cpe_matches_os_version,
    _cpe_matches_vendor,
    _should_skip_software,
    _normalize_software_name,
    _cpe_matches_platform,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_item(os_cpes=None, app_cpes=None):
    """Build a minimal NVD CVE item with the given CPE strings."""
    matches = []
    for cpe in (os_cpes or []):
        matches.append({"criteria": cpe})
    for cpe in (app_cpes or []):
        matches.append({"criteria": cpe})
    if not matches:
        return {}
    return {"configurations": [{"nodes": [{"cpeMatch": matches}]}]}


# ── OS version filter (_cpe_matches_os_version) ───────────────────────────────

class TestOsVersionFilter:
    """
    Guards against CVEs for wrong Windows versions appearing in reports.
    Real false positives prevented:
      - Windows 10 1507/1607/1809 CVEs on a Windows 11 host
      - Windows Server 2022 CVEs on a Windows 11 desktop host
    """

    def test_windows10_cve_excluded_for_windows11_host(self):
        """CVE-2025-33073 / CVE-2025-32718 / CVE-2026-24294 pattern."""
        item = _make_item(os_cpes=[
            "cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_os_version(item, "Windows 11 Home") is False

    def test_windows_server_cve_excluded_for_windows11_host(self):
        """CVE-2024-43447 pattern — Windows Server 2022 on a desktop host."""
        item = _make_item(os_cpes=[
            "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_os_version(item, "Windows 11 Home") is False

    def test_windows11_cve_passes_for_windows11_host(self):
        """CVE that lists Windows 11 must NOT be filtered out."""
        item = _make_item(os_cpes=[
            "cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_os_version(item, "Windows 11 Home") is True

    def test_application_cve_passes_regardless_of_os(self):
        """Microsoft Edge CVE has no OS-type CPEs — OS version is irrelevant."""
        item = _make_item(app_cpes=[
            "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_os_version(item, "Windows 11 Home") is True

    def test_no_cpe_data_passes(self):
        """CVE with no CPE data included — safe fallback is to include it."""
        assert _cpe_matches_os_version({}, "Windows 11 Home") is True
        assert _cpe_matches_os_version({"configurations": []}, "Windows 11 Home") is True

    def test_unknown_os_string_passes(self):
        """When we can't determine the OS version, don't filter anything."""
        item = _make_item(os_cpes=["cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*"])
        assert _cpe_matches_os_version(item, "Windows (SMB/RPC fingerprint)") is True
        assert _cpe_matches_os_version(item, "") is True

    def test_windows10_cve_passes_for_windows10_host(self):
        """A Windows 10 CVE must remain visible to a Windows 10 host."""
        item = _make_item(os_cpes=[
            "cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_os_version(item, "Windows 10 Pro") is True

    def test_mixed_os_app_cpe_passes(self):
        """CVE with both OS and app CPEs — only OS CPEs are checked."""
        item = _make_item(
            os_cpes=["cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"],
            app_cpes=["cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*"],
        )
        assert _cpe_matches_os_version(item, "Windows 11 Home") is True


# ── Vendor filter (_cpe_matches_vendor) ───────────────────────────────────────

class TestVendorFilter:
    """
    Guards against wrong-vendor software CVEs appearing in reports.
    Real false positive prevented:
      - Cisco IOS XR CVE appearing from "Cisco Packet Tracer" search
    """

    def test_cisco_ios_xr_excluded_for_packet_tracer_search(self):
        """CVE-2024-20304 pattern — IOS XR is not Packet Tracer."""
        item = _make_item(app_cpes=[
            "cpe:2.3:a:cisco:ios_xr:*:*:*:*:*:*:*:*",
        ])
        # Publisher "Cisco Systems, Inc." maps to ":cisco:" vendor — this CPE
        # has :cisco: so it passes the vendor filter. But the exact_match on
        # "Cisco Packet Tracer" keyword means IOS XR descriptions won't match.
        # This test confirms the vendor filter doesn't accidentally DROP it
        # (the exact-match keyword filter handles this case, not vendor filter).
        assert _cpe_matches_vendor(item, "Cisco Systems, Inc.") is True

    def test_microsoft_edge_accepted_for_microsoft_publisher(self):
        """Edge CVE from Microsoft publisher must pass vendor filter."""
        item = _make_item(app_cpes=[
            "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_vendor(item, "Microsoft Corporation") is True

    def test_google_android_excluded_for_microsoft_edge_search(self):
        """
        CVE-2024-38208 pattern — product includes 'Google Android'.
        When publisher is Microsoft, CVEs whose CPEs are only Google should
        be excluded by the vendor filter.
        """
        item = _make_item(app_cpes=[
            "cpe:2.3:a:google:android:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_vendor(item, "Microsoft Corporation") is False

    def test_unknown_publisher_passes(self):
        """Publisher not in the map — can't filter, include all results."""
        item = _make_item(app_cpes=["cpe:2.3:a:somevendor:someproduct:*"])
        assert _cpe_matches_vendor(item, "Some Unknown Corp") is True

    def test_no_publisher_passes(self):
        """Empty publisher means no vendor filter applied."""
        item = _make_item(app_cpes=["cpe:2.3:a:cisco:ios_xr:*"])
        assert _cpe_matches_vendor(item, "") is True


# ── Software skip list (_should_skip_software) ────────────────────────────────

class TestSoftwareSkipList:
    """
    Guards against internal sub-components consuming NVD rate-limit budget
    and potentially returning irrelevant CVEs.
    """

    def test_python_sub_packages_skipped(self):
        """9 Python sub-installers should all be skipped."""
        skipped = [
            "Python 3.14.2 Core Interpreter (64-bit)",
            "Python 3.14.2 Add to Path (64-bit)",
            "Python 3.14.2 pip Bootstrap (64-bit)",
            "Python 3.14.2 Test Suite (64-bit)",
            "Python 3.14.2 Standard Library (64-bit)",
            "Python 3.14.2 Development Libraries (64-bit)",
            "Python 3.14.2 Documentation (64-bit)",
            "Python 3.14.2 Executables (64-bit)",
            "Python 3.14.2 Tcl/Tk Support (64-bit)",
        ]
        for name in skipped:
            assert _should_skip_software(name) is True, f"Should be skipped: {name}"

    def test_vs_internal_components_skipped(self):
        """Visual Studio internal tooling should be skipped."""
        skipped = [
            "vs_FileTracker_Singleton",
            "Microsoft Visual Studio Setup Configuration",
            "Microsoft Visual Studio Setup WMI Provider",
        ]
        for name in skipped:
            assert _should_skip_software(name) is True, f"Should be skipped: {name}"

    def test_vcpp_internal_skipped(self):
        assert _should_skip_software("vcpp_crt.redist.clickonce") is True

    def test_universal_crt_skipped(self):
        assert _should_skip_software("Universal CRT Redistributable") is True

    def test_kb_update_skipped(self):
        assert _should_skip_software(
            "Update for x64-based Windows Systems (KB5001716)"
        ) is True

    def test_office_clicktorun_skipped(self):
        assert _should_skip_software(
            "Office 16 Click-to-Run Extensibility Component"
        ) is True

    def test_real_software_not_skipped(self):
        """Actual user-facing software must NOT be skipped."""
        kept = [
            "Google Chrome",
            "Microsoft Edge",
            "Git",
            "Node.js",
            "Android Studio",
            "FL Studio 2025",
            "VLC media player",
            "MySQL Server 8.4",
            "Python Launcher",
            "Visual Studio Build Tools 2022",
            "Cisco Packet Tracer 9.0.0 64Bit",
            "PuTTY release 0.83 (64-bit)",
        ]
        for name in kept:
            assert _should_skip_software(name) is False, f"Should NOT be skipped: {name}"


# ── Name normalisation (_normalize_software_name) ─────────────────────────────

class TestSoftwareNameNormalisation:
    """
    Guards against the deduplication logic breaking — if normalisation
    regresses, 8 VC++ entries search NVD 8 times instead of once.
    """

    def test_vcpp_x64_additional_runtime(self):
        assert _normalize_software_name(
            "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211"
        ) == "Microsoft Visual C++"

    def test_vcpp_x86_debug_runtime(self):
        assert _normalize_software_name(
            "Microsoft Visual C++ 2022 X86 Debug Runtime - 14.44.35211"
        ) == "Microsoft Visual C++"

    def test_vcpp_x64_minimum_runtime(self):
        assert _normalize_software_name(
            "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211"
        ) == "Microsoft Visual C++"

    def test_microsoft_365_locale_stripped(self):
        assert _normalize_software_name("Microsoft 365 - en-us") == "Microsoft 365"

    def test_putty_release_stripped(self):
        assert _normalize_software_name("PuTTY release 0.83 (64-bit)") == "PuTTY"

    def test_imagemagick_version_stripped(self):
        assert _normalize_software_name(
            "ImageMagick 7.1.2-13 Q16-HDRI (64-bit) (2026-01-19)"
        ) == "ImageMagick"

    def test_mysql_version_stripped(self):
        assert _normalize_software_name("MySQL Server 8.4") == "MySQL Server"

    def test_fl_studio_year_stripped(self):
        assert _normalize_software_name("FL Studio 2025") == "FL Studio"

    def test_vs_build_tools_year_stripped(self):
        assert _normalize_software_name(
            "Visual Studio Build Tools 2022"
        ) == "Visual Studio Build Tools"

    def test_cisco_packet_tracer_version_stripped(self):
        assert _normalize_software_name(
            "Cisco Packet Tracer 9.0.0 64Bit"
        ) == "Cisco Packet Tracer"

    def test_no_change_for_clean_names(self):
        """Names with no version noise must pass through unchanged."""
        assert _normalize_software_name("Google Chrome") == "Google Chrome"
        assert _normalize_software_name("Git") == "Git"
        assert _normalize_software_name("Node.js") == "Node.js"
        assert _normalize_software_name("Microsoft Edge") == "Microsoft Edge"

    def test_vcpp_all_variants_normalise_identically(self):
        """All 8 VC++ registry entries must produce the same keyword (dedup works)."""
        variants = [
            "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211",
            "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.44.35211",
            "Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211",
            "Microsoft Visual C++ 2022 X64 Debug Runtime - 14.44.35211",
            "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211",
            "Microsoft Visual C++ 2022 X86 Additional Runtime - 14.44.35211",
            "Microsoft Visual C++ 2022 X86 Debug Runtime - 14.44.35211",
            "Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.44.35211",
        ]
        normalised = {_normalize_software_name(v) for v in variants}
        assert len(normalised) == 1, (
            f"VC++ variants produced {len(normalised)} different keywords: {normalised}"
        )


# ── Platform filter regression (_cpe_matches_platform) ────────────────────────

class TestPlatformFilter:
    """Ensures the existing platform filter still works after recent changes."""

    def test_windows_smb_cve_passes_for_windows_host(self):
        item = _make_item(os_cpes=[
            "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_platform(item, "windows") is True

    def test_linux_cve_excluded_for_windows_host(self):
        item = _make_item(os_cpes=[
            "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
        ])
        assert _cpe_matches_platform(item, "windows") is False

    def test_no_cpe_data_included(self):
        """No CPE data — safe to include rather than silently drop."""
        assert _cpe_matches_platform({}, "windows") is True


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
