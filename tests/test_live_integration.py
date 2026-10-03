"""End-to-end integration test against live PostgreSQL and Redis services."""
import pytest
from app.backend.core.database import SessionLocal, check_db_connection
from app.backend.services.queue import is_redis_available, enqueue_scan_id, pop_scan_id
from app.backend.services.scan_service import ScanService
from app.backend.models.scan import Scan, ScanFinding


@pytest.mark.asyncio
async def test_live_postgres_and_redis_lifecycle():
    if not check_db_connection() or not is_redis_available():
        pytest.skip("PostgreSQL or Redis not available for live integration test")

    db = SessionLocal()
    service = ScanService()

    try:
        # Create a URL scan synchronously
        scan = await service.create_scan(
            db=db,
            input_type="url",
            data="https://phishing-alert-account-login.example.com",
            run_sync=True,
        )

        assert scan.status == "completed"
        assert scan.risk_score > 0
        assert scan.classification in ("Safe", "Suspicious", "High Risk")
        assert len(scan.findings) >= 1
        assert len(scan.signals) == 4

        # Verify persisted in database
        persisted = db.query(Scan).filter(Scan.id == scan.id).first()
        assert persisted is not None
        assert persisted.risk_score == scan.risk_score
        assert len(persisted.findings) == len(scan.findings)

        # Test Redis enqueue and dequeue with isolated test queue to avoid worker race
        test_q = "cyberguard:test_lifecycle_queue"
        enqueued = enqueue_scan_id(scan.id, queue_name=test_q)
        assert enqueued is True
        popped_id = pop_scan_id(timeout=2, queue_name=test_q)
        assert popped_id == scan.id

    finally:
        db.close()
