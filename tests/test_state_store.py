"""
Tests for spider.state.store — StateStore CRUD operations.
"""

import os
import tempfile
import pytest
from datetime import datetime

from spider.state.store import StateStore


@pytest.fixture
def store(tmp_path):
    db_file = str(tmp_path / "test_spider.db")
    return StateStore(db_path=db_file)


class TestRunManagement:
    def test_create_run(self, store):
        run_id = store.create_run("192.168.56.101")
        assert isinstance(run_id, int)
        assert run_id > 0

    def test_create_multiple_runs(self, store):
        id1 = store.create_run("192.168.56.101")
        id2 = store.create_run("192.168.56.102")
        assert id1 != id2

    def test_update_phase(self, store):
        run_id = store.create_run("192.168.56.101")
        store.update_phase(run_id, "recon")
        runs = store.get_all_runs()
        assert any(r["id"] == run_id and r["phase"] == "recon" for r in runs)

    def test_complete_run(self, store):
        run_id = store.create_run("10.0.0.1")
        store.complete_run(run_id)
        runs = store.get_all_runs()
        run = next(r for r in runs if r["id"] == run_id)
        assert run["status"] == "complete"

    def test_get_all_runs(self, store):
        store.create_run("1.1.1.1")
        store.create_run("2.2.2.2")
        runs = store.get_all_runs()
        assert len(runs) >= 2

    def test_get_run_by_ip(self, store):
        run_id = store.create_run("192.168.1.100")
        run = store.get_run_by_ip("192.168.1.100")
        assert run is not None
        assert run.target_ip == "192.168.1.100"


class TestOpenPorts:
    def test_add_and_get_ports(self, store):
        run_id = store.create_run("10.10.10.1")
        ports = [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ftp",
             "version": "vsftpd 2.3.4", "product": "vsftpd", "extra_info": "", "banner": ""},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http",
             "version": "Apache 2.2.8", "product": "Apache", "extra_info": "", "banner": ""},
        ]
        store.add_open_ports(run_id, ports)
        result = store.get_open_ports(run_id)
        assert len(result) == 2
        assert any(p["port"] == 21 for p in result)
        assert any(p["port"] == 80 for p in result)

    def test_ports_isolated_by_run(self, store):
        id1 = store.create_run("1.1.1.1")
        id2 = store.create_run("2.2.2.2")
        store.add_open_ports(id1, [{"port": 22, "protocol": "tcp", "state": "open",
                                    "service": "ssh", "version": "", "product": "", "extra_info": "", "banner": ""}])
        assert len(store.get_open_ports(id2)) == 0


class TestFindings:
    def _sample_finding(self, **kwargs):
        base = {
            "agent": "enumeration",
            "service": "ftp",
            "port": 21,
            "title": "VSFTPD 2.3.4 Backdoor",
            "description": "VSFTPD 2.3.4 contains a backdoor.",
            "severity": "critical",
            "cvss_score": 10.0,
            "cve_id": "CVE-2011-2523",
            "attack_tactic": "Initial Access",
            "attack_technique": "T1190",
            "evidence": "vsftpd 2.3.4",
            "recommendation": "Upgrade vsftpd",
            "exploitable": False,
        }
        base.update(kwargs)
        return base

    def test_add_and_get_finding(self, store):
        run_id = store.create_run("10.0.0.5")
        finding_id = store.add_finding(run_id, self._sample_finding())
        assert isinstance(finding_id, int)
        findings = store.get_findings(run_id)
        assert len(findings) == 1
        assert findings[0]["cve_id"] == "CVE-2011-2523"

    def test_filter_by_severity(self, store):
        run_id = store.create_run("10.0.0.6")
        store.add_finding(run_id, self._sample_finding(severity="critical"))
        store.add_finding(run_id, self._sample_finding(title="Low finding", severity="low", cve_id=None))
        critical = store.get_findings(run_id, severity="critical")
        assert len(critical) == 1
        assert critical[0]["severity"] == "critical"

    def test_count_by_severity(self, store):
        run_id = store.create_run("10.0.0.7")
        store.add_finding(run_id, self._sample_finding(severity="critical"))
        store.add_finding(run_id, self._sample_finding(title="High", severity="high", cve_id=None))
        store.add_finding(run_id, self._sample_finding(title="Med", severity="medium", cve_id=None))
        counts = store.count_findings_by_severity(run_id)
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 0


class TestSessions:
    def _sample_session(self, **kwargs):
        base = {
            "msf_session_id": 1,
            "session_type": "meterpreter",
            "target_ip": "192.168.56.101",
            "target_port": 21,
            "exploit_module": "exploit/unix/ftp/vsftpd_234_backdoor",
            "cve_id": "CVE-2011-2523",
            "username": "root",
            "hostname": "metasploitable",
            "os_info": "Linux 2.6.24",
        }
        base.update(kwargs)
        return base

    def test_add_and_get_session(self, store):
        run_id = store.create_run("192.168.56.101")
        session_id = store.add_session(run_id, self._sample_session())
        assert isinstance(session_id, int)
        sessions = store.get_active_sessions(run_id)
        assert len(sessions) == 1
        assert sessions[0]["msf_session_id"] == 1

    def test_mark_session_dead(self, store):
        run_id = store.create_run("192.168.56.101")
        session_id = store.add_session(run_id, self._sample_session())
        store.mark_session_dead(session_id)
        sessions = store.get_active_sessions(run_id)
        assert len(sessions) == 0


class TestPrivescVectors:
    def test_add_and_get_privesc(self, store):
        run_id = store.create_run("10.0.0.8")
        session_id = store.add_session(run_id, {
            "msf_session_id": 2, "session_type": "shell",
            "target_ip": "10.0.0.8", "target_port": 21,
            "exploit_module": "test/module", "cve_id": None,
        })
        vector = {
            "vector_type": "suid",
            "binary_path": "/bin/bash",
            "gtfobins_command": "bash -p",
            "root_achieved": True,
            "evidence": "uid=0(root)",
        }
        store.add_privesc_vector(run_id, session_id, vector)
        vectors = store.get_privesc_vectors(run_id)
        assert len(vectors) == 1
        assert vectors[0]["root_achieved"] is True
        assert vectors[0]["binary_path"] == "/bin/bash"


class TestCredentials:
    def test_add_and_get_credential(self, store):
        run_id = store.create_run("10.0.0.9")
        session_id = store.add_session(run_id, {
            "msf_session_id": 3, "session_type": "shell",
            "target_ip": "10.0.0.9", "target_port": 445,
            "exploit_module": "test/module", "cve_id": None,
        })
        cred = {
            "cred_type": "plaintext",
            "username": "msfadmin",
            "secret": "msfadmin",
            "source_file": ".bash_history",
            "service": "ssh",
        }
        store.add_credential(run_id, session_id, cred)
        creds = store.get_credentials(run_id)
        assert len(creds) == 1
        assert creds[0]["username"] == "msfadmin"
