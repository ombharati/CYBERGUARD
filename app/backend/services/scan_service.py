"""Scan Service Layer for database operations and lifecycle orchestration."""
import logging
from typing import List, Optional, Union, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from app.backend.models.scan import Scan, IdempotencyKey, generate_scan_id
from app.backend.services.orchestrator import ScanOrchestrator
from app.backend.services.queue import enqueue_scan_id, is_redis_available

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self, orchestrator: Optional[ScanOrchestrator] = None):
        self.orchestrator = orchestrator or ScanOrchestrator()

    def _extract_target_summary(self, input_type: str, data: Union[str, Dict[str, Any]]) -> str:
        """Extract a short human-readable target string for indexing and listing."""
        if input_type == "url":
            return str(data).strip()[:200]
        elif input_type == "email":
            if isinstance(data, dict):
                subject = data.get("subject", "No subject")
                sender = data.get("sender", "Unknown sender")
                return f"{subject} (from: {sender})"[:200]
            # If raw string
            first_line = str(data).strip().splitlines()[0] if str(data).strip() else "Email"
            return first_line[:200]
        elif input_type in ("identity", "headers"):
            for line in str(data).splitlines()[:10]:
                if line.lower().startswith("from:"):
                    return line.strip()[:200]
            first_line = str(data).strip().splitlines()[0] if str(data).strip() else "Email Headers"
            return first_line[:200]
        elif input_type == "logs":
            lines = str(data).strip().splitlines()
            return f"Log stream ({len(lines)} lines)"
        else:
            clean = str(data).strip()
            return (clean[:60] + "...") if len(clean) > 60 else clean

    async def create_scan(
        self,
        db: Session,
        input_type: str,
        data: Union[str, Dict[str, Any]],
        run_sync: bool = False,
        idempotency_key: Optional[str] = None,
    ) -> Scan:
        """Create a new scan record in PostgreSQL and either execute or enqueue it.
        If idempotency_key is provided and exists in idempotency_keys table, return the existing scan.
        """
        if idempotency_key:
            existing_record = db.query(IdempotencyKey).filter(IdempotencyKey.key == idempotency_key).first()
            if existing_record:
                existing_scan = db.query(Scan).filter(Scan.id == existing_record.scan_id).first()
                if existing_scan:
                    logger.info("Deduplicated scan creation: returning existing %s for key %s", existing_scan.id, idempotency_key)
                    return existing_scan

        target_summary = self._extract_target_summary(input_type, data)

        scan = Scan(
            id=generate_scan_id(),
            input_type=input_type,
            target=target_summary,
            raw_input=data,
            idempotency_key=idempotency_key,
            status="queued",
            risk_score=0,
            classification="Queued",
            summary="Scan queued for multi-engine analysis.",
            explanation="Awaiting worker processing.",
            signals=[],
        )
        db.add(scan)

        if idempotency_key:
            idempotency_record = IdempotencyKey(key=idempotency_key, scan_id=scan.id)
            db.add(idempotency_record)

        try:
            db.commit()
            db.refresh(scan)
        except IntegrityError:
            db.rollback()
            if idempotency_key:
                existing_record = db.query(IdempotencyKey).filter(IdempotencyKey.key == idempotency_key).first()
                if existing_record:
                    existing_scan = db.query(Scan).filter(Scan.id == existing_record.scan_id).first()
                    if existing_scan:
                        logger.info("Concurrency deduplicated: returning existing %s for key %s", existing_scan.id, idempotency_key)
                        return existing_scan
            raise


        if run_sync:
            # Immediate synchronous execution (used by frontend /sync endpoints)
            logger.info("Executing scan %s synchronously", scan.id)
            return await self.orchestrator.execute_scan(db, scan.id)

        # Asynchronous execution via Redis queue
        enqueued = enqueue_scan_id(scan.id)
        if not enqueued:
            logger.warning("Redis queue unavailable for scan %s. Executing inline as graceful fallback.", scan.id)
            return await self.orchestrator.execute_scan(db, scan.id)

        return scan

    def get_scan(self, db: Session, scan_id: str) -> Optional[Scan]:
        """Retrieve a scan by ID."""
        return db.query(Scan).filter(Scan.id == scan_id).first()

    def list_recent_scans(self, db: Session, limit: int = 50) -> List[Scan]:
        """List recent scans ordered by creation date."""
        return (
            db.query(Scan)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .all()
        )
