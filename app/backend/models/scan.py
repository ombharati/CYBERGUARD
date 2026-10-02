"""Database models for Scans and Findings."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Text,
    DateTime,
    ForeignKey,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship
from app.backend.core.database import Base


def generate_scan_id() -> str:
    """Generate a clean human-readable scan ID with CG prefix."""
    return f"CG-{uuid.uuid4().hex[:8].upper()}"


class Scan(Base):
    """Represents a submitted cybersecurity scan."""
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_scan_id)
    input_type = Column(String(20), nullable=False, index=True)  # url, email, content
    target = Column(Text, nullable=False)
    raw_input = Column(JSON, nullable=False)
    
    # Lifecycle status: queued, processing, completed, failed
    status = Column(String(20), nullable=False, default="queued", index=True)
    
    # Results
    risk_score = Column(Integer, nullable=True)  # 0 to 100
    classification = Column(String(20), nullable=True)  # Safe, Suspicious, High Risk
    summary = Column(Text, nullable=True)
    explanation = Column(Text, nullable=True)
    signals = Column(JSON, nullable=True, default=list)
    
    # Error tracking & retries
    error_message = Column(Text, nullable=True)
    retries = Column(Integer, default=0, nullable=False)
    
    # Timestamps
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    findings = relationship(
        "ScanFinding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="ScanFinding.id",
    )

    __table_args__ = (
        Index("ix_scans_status_created", "status", "created_at"),
    )

    def to_dict(self):
        """Serialize scan for API responses."""
        return {
            "id": self.id,
            "type": self.input_type.upper(),
            "target": self.target,
            "score": self.risk_score or 0,
            "classification": self.classification or "Processing",
            "summary": self.summary or "Analysis in progress...",
            "findings": [f.to_dict() for f in self.findings],
            "signals": self.signals or [],
            "explanation": self.explanation or "",
            "status": self.status,
            "timestamp": self.created_at.isoformat() if self.created_at else None,
        }


class ScanFinding(Base):
    """Represents an individual security finding/evidence attached to a scan."""
    __tablename__ = "scan_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    
    severity = Column(String(10), nullable=False)  # low, medium, high
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=True)  # heuristic, laya, qwen, threat_intel
    
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship back to scan
    scan = relationship("Scan", back_populates="findings")

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "category": self.category,
        }
