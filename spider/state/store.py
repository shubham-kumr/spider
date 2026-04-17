"""
SPIDER — StateStore
Thread-safe CRUD interface for SQLite via SQLAlchemy.
Single source of truth across all agents for a given run.
"""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import Session as DBSession

from spider.state.models import (
    Base, Run, OpenPort, Finding, Session as MsfSession,
    PrivescVector, Credential
)


class StateStore:
    """Thread-safe SQLite state store for SPIDER engagements."""

    def __init__(self, db_path: str = "./spider_state.db") -> None:
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            echo=False,
            connect_args={"check_same_thread": False},
        )
        self._lock = threading.Lock()
        Base.metadata.create_all(self.engine)

    # ── Run management ───────────────────────────────────────────────────────

    def create_run(self, target_ip: str, notes: str = None) -> int:
        with self._lock, DBSession(self.engine) as session:
            run = Run(target_ip=target_ip, status="running", current_phase="preflight", notes=notes)
            session.add(run)
            session.commit()
            session.refresh(run)
            return run.id

    def update_phase(self, run_id: int, phase: str) -> None:
        with self._lock, DBSession(self.engine) as session:
            run = session.get(Run, run_id)
            if run:
                run.current_phase = phase
                session.commit()

    def complete_run(self, run_id: int) -> None:
        with self._lock, DBSession(self.engine) as session:
            run = session.get(Run, run_id)
            if run:
                run.status = "complete"
                run.end_time = datetime.utcnow()
                session.commit()

    def fail_run(self, run_id: int) -> None:
        with self._lock, DBSession(self.engine) as session:
            run = session.get(Run, run_id)
            if run:
                run.status = "failed"
                run.end_time = datetime.utcnow()
                session.commit()

    def get_all_runs(self) -> list[dict]:
        with DBSession(self.engine) as session:
            runs = session.query(Run).order_by(Run.start_time.desc()).all()
            result = []
            for r in runs:
                port_count = session.query(OpenPort).filter_by(run_id=r.id).count()
                finding_count = session.query(Finding).filter_by(run_id=r.id).count()
                session_count = session.query(MsfSession).filter_by(run_id=r.id).count()
                result.append({
                    "id": r.id,
                    "target": r.target_ip,
                    "status": r.status,
                    "phase": r.current_phase,
                    "ports": port_count,
                    "findings": finding_count,
                    "sessions": session_count,
                    "timestamp": r.start_time.strftime("%Y-%m-%d %H:%M") if r.start_time else "—",
                })
            return result

    def clear_run_data(self, run_id: int) -> None:
        """Delete all data for a run (for re-runs)."""
        with self._lock, DBSession(self.engine) as session:
            run = session.get(Run, run_id)
            if run:
                session.delete(run)
                session.commit()

    def get_run_by_ip(self, target_ip: str) -> Optional[Run]:
        with DBSession(self.engine) as session:
            return (
                session.query(Run)
                .filter_by(target_ip=target_ip)
                .order_by(Run.start_time.desc())
                .first()
            )

    # ── Open ports ──────────────────────────────────────────────────────────

    def add_open_ports(self, run_id: int, ports: list[dict]) -> None:
        with self._lock, DBSession(self.engine) as session:
            for p in ports:
                session.add(OpenPort(run_id=run_id, **p))
            session.commit()

    def get_open_ports(self, run_id: int) -> list[dict]:
        with DBSession(self.engine) as session:
            rows = session.query(OpenPort).filter_by(run_id=run_id).all()
            return [
                {
                    "port": r.port,
                    "protocol": r.protocol,
                    "state": r.state,
                    "service": r.service or "",
                    "version": r.version or "",
                    "product": r.product or "",
                    "banner": r.banner or "",
                    "extra_info": r.extra_info or "",
                }
                for r in rows
            ]

    # ── Findings ─────────────────────────────────────────────────────────────

    def add_finding(self, run_id: int, finding: dict) -> int:
        with self._lock, DBSession(self.engine) as session:
            f = Finding(run_id=run_id, **finding)
            session.add(f)
            session.commit()
            session.refresh(f)
            return f.id

    def get_findings(self, run_id: int, severity: str = None) -> list[dict]:
        with DBSession(self.engine) as session:
            query = session.query(Finding).filter_by(run_id=run_id)
            if severity:
                query = query.filter_by(severity=severity)
            rows = query.order_by(Finding.cvss_score.desc()).all()
            return [
                {
                    "id": r.id,
                    "agent": r.agent,
                    "service": r.service,
                    "port": r.port,
                    "title": r.title,
                    "description": r.description,
                    "severity": r.severity,
                    "cvss_score": r.cvss_score,
                    "cve_id": r.cve_id,
                    "attack_tactic": r.attack_tactic,
                    "attack_technique": r.attack_technique,
                    "evidence": r.evidence,
                    "recommendation": r.recommendation,
                    "exploitable": r.exploitable,
                    "found_at": r.found_at.strftime("%Y-%m-%d %H:%M") if r.found_at else "",
                }
                for r in rows
            ]

    def count_findings_by_severity(self, run_id: int) -> dict:
        with DBSession(self.engine) as session:
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            rows = session.query(Finding.severity).filter_by(run_id=run_id).all()
            for (sev,) in rows:
                if sev in counts:
                    counts[sev] += 1
            return counts

    # ── Sessions ─────────────────────────────────────────────────────────────

    def add_session(self, run_id: int, session_data: dict) -> int:
        with self._lock, DBSession(self.engine) as session:
            s = MsfSession(run_id=run_id, **session_data)
            session.add(s)
            session.commit()
            session.refresh(s)
            return s.id

    def get_active_sessions(self, run_id: int) -> list[dict]:
        with DBSession(self.engine) as session:
            rows = session.query(MsfSession).filter_by(run_id=run_id, alive=True).all()
            return [
                {
                    "id": r.id,
                    "msf_session_id": r.msf_session_id,
                    "session_type": r.session_type,
                    "target_ip": r.target_ip,
                    "target_port": r.target_port,
                    "exploit_module": r.exploit_module,
                    "cve_id": r.cve_id,
                    "username": r.username,
                    "hostname": r.hostname,
                    "os_info": r.os_info,
                }
                for r in rows
            ]

    def mark_session_dead(self, session_id: int) -> None:
        with self._lock, DBSession(self.engine) as session:
            s = session.get(MsfSession, session_id)
            if s:
                s.alive = False
                s.closed_at = datetime.utcnow()
                session.commit()

    # ── Privesc vectors ──────────────────────────────────────────────────────

    def add_privesc_vector(self, run_id: int, session_id: int, vector: dict) -> None:
        with self._lock, DBSession(self.engine) as session:
            session.add(PrivescVector(run_id=run_id, session_id=session_id, **vector))
            session.commit()

    def get_privesc_vectors(self, run_id: int) -> list[dict]:
        with DBSession(self.engine) as session:
            rows = session.query(PrivescVector).filter_by(run_id=run_id).all()
            return [
                {
                    "vector_type": r.vector_type,
                    "binary_path": r.binary_path,
                    "gtfobins_command": r.gtfobins_command,
                    "root_achieved": r.root_achieved,
                    "evidence": r.evidence,
                }
                for r in rows
            ]

    # ── Credentials ──────────────────────────────────────────────────────────

    def add_credential(self, run_id: int, session_id: int, cred: dict) -> None:
        with self._lock, DBSession(self.engine) as session:
            session.add(Credential(run_id=run_id, session_id=session_id, **cred))
            session.commit()

    def get_credentials(self, run_id: int) -> list[dict]:
        with DBSession(self.engine) as session:
            rows = session.query(Credential).filter_by(run_id=run_id).all()
            return [
                {
                    "cred_type": r.cred_type,
                    "username": r.username,
                    "secret": r.secret,
                    "source_file": r.source_file,
                    "service": r.service,
                }
                for r in rows
            ]
