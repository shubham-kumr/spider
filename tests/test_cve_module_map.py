"""
Tests for spider.tools.cve_module_map — CVE module lookup.
"""

import pytest
from spider.tools.cve_module_map import (
    CVE_TO_MSF_MODULE,
    get_module_for_cve,
    get_exploitable_cves,
)


class TestCveModuleMap:
    def test_all_entries_have_required_fields(self):
        required = {"module", "service", "default_port", "payload", "session_type", "options", "description"}
        for cve, config in CVE_TO_MSF_MODULE.items():
            missing = required - set(config.keys())
            assert not missing, f"{cve} is missing fields: {missing}"

    def test_module_paths_format(self):
        for cve, config in CVE_TO_MSF_MODULE.items():
            module = config["module"]
            assert "/" in module, f"{cve}: module path should contain '/'"
            assert module.startswith("exploit/"), f"{cve}: module should start with 'exploit/'"

    def test_default_ports_are_valid(self):
        for cve, config in CVE_TO_MSF_MODULE.items():
            port = config["default_port"]
            assert 1 <= port <= 65535, f"{cve}: invalid port {port}"

    def test_vsftpd_cve_present(self):
        assert "CVE-2011-2523" in CVE_TO_MSF_MODULE
        cfg = CVE_TO_MSF_MODULE["CVE-2011-2523"]
        assert cfg["module"] == "exploit/unix/ftp/vsftpd_234_backdoor"
        assert cfg["default_port"] == 21

    def test_samba_cve_present(self):
        assert "CVE-2007-2447" in CVE_TO_MSF_MODULE

    def test_get_module_for_cve_found(self):
        result = get_module_for_cve("CVE-2011-2523")
        assert result is not None
        assert result["module"] == "exploit/unix/ftp/vsftpd_234_backdoor"

    def test_get_module_for_cve_not_found(self):
        result = get_module_for_cve("CVE-9999-9999")
        assert result is None

    def test_get_module_case_insensitive(self):
        result = get_module_for_cve("cve-2011-2523")
        assert result is not None

    def test_get_exploitable_cves_sorts_by_cvss(self):
        findings = [
            {"cve_id": "CVE-2007-2447", "cvss_score": 9.3, "severity": "critical", "title": "Samba"},
            {"cve_id": "CVE-2004-2687", "cvss_score": 6.8, "severity": "high", "title": "distcc"},
            {"cve_id": "CVE-2011-2523", "cvss_score": 10.0, "severity": "critical", "title": "VSFTPD"},
        ]
        result = get_exploitable_cves(findings)
        assert len(result) == 3
        scores = [r["finding"]["cvss_score"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_get_exploitable_cves_filters_unmapped(self):
        findings = [
            {"cve_id": "CVE-2011-2523", "cvss_score": 10.0, "severity": "critical", "title": "VSFTPD"},
            {"cve_id": "CVE-9999-0000", "cvss_score": 5.0, "severity": "medium", "title": "Fake"},
            {"cve_id": None, "cvss_score": 3.0, "severity": "low", "title": "No CVE"},
        ]
        result = get_exploitable_cves(findings)
        assert len(result) == 1
        assert result[0]["finding"]["cve_id"] == "CVE-2011-2523"
