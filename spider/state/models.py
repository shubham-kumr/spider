"""
SPIDER — SQLAlchemy ORM Models
Defines all database tables for storing pentest engagement state.
"""

from sqlalchemy import (
    Column, Integer, String, Float, Boolean, Text, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()


class Run(Base):
    """Tracks each SPIDER engagement run."""
    __tablename__ = "runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_ip = Column(String(45), nullable=False)
    status = Column(String(20), nullable=False, default="running")
    current_phase = Column(String(20), nullable=False, default="preflight")
    start_time = Column(DateTime, server_default=func.now())
    end_time = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)

    # Relationships
    open_ports = relationship("OpenPort", back_populates="run", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="run", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="run", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_runs_target_ip", "target_ip"),
        Index("idx_runs_status", "status"),
    )


class OpenPort(Base):
    """Stores nmap scan results per run."""
    __tablename__ = "open_ports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(5), nullable=False, default="tcp")
    state = Column(String(10), nullable=False, default="open")
    service = Column(String(50), nullable=True)
    version = Column(String(100), nullable=True)
    banner = Column(Text, nullable=True)
    product = Column(String(100), nullable=True)
    extra_info = Column(Text, nullable=True)
    scanned_at = Column(DateTime, server_default=func.now())

    run = relationship("Run", back_populates="open_ports")

    __table_args__ = (
        Index("idx_open_ports_run_id", "run_id"),
        Index("idx_open_ports_port", "port"),
    )


class Finding(Base):
    """Stores all vulnerability/issue findings."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    agent = Column(String(30), nullable=False)
    service = Column(String(50), nullable=False)
    port = Column(Integer, nullable=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(10), nullable=False)
    cvss_score = Column(Float, nullable=True)
    cve_id = Column(String(20), nullable=True)
    attack_tactic = Column(String(50), nullable=True)
    attack_technique = Column(String(20), nullable=True)
    evidence = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    exploitable = Column(Boolean, nullable=False, default=False)
    found_at = Column(DateTime, server_default=func.now())

    run = relationship("Run", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_run_id", "run_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_cve_id", "cve_id"),
        Index("idx_findings_agent", "agent"),
    )


class Session(Base):
    """Tracks active Meterpreter / shell sessions opened during exploitation."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    msf_session_id = Column(Integer, nullable=False)
    session_type = Column(String(20), nullable=False)
    target_ip = Column(String(45), nullable=False)
    target_port = Column(Integer, nullable=False)
    exploit_module = Column(String(200), nullable=False)
    cve_id = Column(String(20), nullable=True)
    username = Column(String(50), nullable=True)
    hostname = Column(String(100), nullable=True)
    os_info = Column(Text, nullable=True)
    alive = Column(Boolean, nullable=False, default=True)
    opened_at = Column(DateTime, server_default=func.now())
    closed_at = Column(DateTime, nullable=True)

    run = relationship("Run", back_populates="sessions")
    privesc_vectors = relationship(
        "PrivescVector", back_populates="session", cascade="all, delete-orphan"
    )
    credentials = relationship(
        "Credential", back_populates="session", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_sessions_run_id", "run_id"),
        Index("idx_sessions_msf_session_id", "msf_session_id"),
        Index("idx_sessions_alive", "alive"),
    )


class PrivescVector(Base):
    """Stores discovered privilege escalation paths."""
    __tablename__ = "privesc_vectors"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False)
    vector_type = Column(String(30), nullable=False)  # suid / sudo / cron / writable_service / kernel
    binary_path = Column(String(255), nullable=True)
    gtfobins_command = Column(Text, nullable=True)
    root_achieved = Column(Boolean, nullable=False, default=False)
    evidence = Column(Text, nullable=True)
    found_at = Column(DateTime, server_default=func.now())

    session = relationship("Session", back_populates="privesc_vectors")

    __table_args__ = (
        Index("idx_privesc_run_id", "run_id"),
        Index("idx_privesc_session_id", "session_id"),
    )


class Credential(Base):
    """Stores harvested credentials during post-exploitation.
    
    Security Note: Values stored for report generation only. DB should never be committed.
    """
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("runs.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    cred_type = Column(String(20), nullable=False)  # plaintext / hash / ssh_key / token
    username = Column(String(100), nullable=False)
    secret = Column(Text, nullable=False)
    source_file = Column(String(255), nullable=True)
    service = Column(String(50), nullable=True)
    found_at = Column(DateTime, server_default=func.now())

    session = relationship("Session", back_populates="credentials")

    __table_args__ = (
        Index("idx_credentials_run_id", "run_id"),
        Index("idx_credentials_cred_type", "cred_type"),
    )
