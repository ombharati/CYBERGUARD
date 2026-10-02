"""Unit tests for background scan worker, queueing, and retry semantics."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.backend.core.database import Base
from app.backend.models.scan import Scan, generate_scan_id
from app.backend.services.queue import enqueue_scan_id, pop_scan_id
from app.backend.services.worker import ScanWorker
from app.backend.services.scan_service import ScanService

TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


@pytest.mark.asyncio
async def test_worker_processes_job_successfully():
    db = TestingSessionLocal()
    scan = Scan(
        id=generate_scan_id(),
        input_type="url",
        target="https://test-worker.com",
        raw_input="https://test-worker.com",
        status="queued",
    )
    db.add(scan)
    db.commit()

    worker = ScanWorker()

    # Mock popping this scan ID
    with patch("app.backend.services.worker.pop_scan_id", side_effect=[scan.id, None]):
        with patch("app.backend.services.worker.SessionLocal", return_value=db):
            with patch.object(worker.orchestrator, "execute_scan", new_callable=AsyncMock) as mock_exec:
                mock_exec.return_value = scan
                processed = await worker.process_one(timeout=1)
                assert processed is True
                mock_exec.assert_called_once_with(db, scan.id)


@pytest.mark.asyncio
async def test_worker_handles_failure_and_retries():
    db = TestingSessionLocal()
    scan = Scan(
        id=generate_scan_id(),
        input_type="url",
        target="https://failure-test.com",
        raw_input="https://failure-test.com",
        status="queued",
    )
    db.add(scan)
    db.commit()

    worker = ScanWorker()

    with patch("app.backend.services.worker.pop_scan_id", return_value=scan.id):
        with patch("app.backend.services.worker.SessionLocal", return_value=db):
            with patch.object(worker.orchestrator, "execute_scan", side_effect=Exception("Database lock failure")):
                processed = await worker.process_one(timeout=1)
                assert processed is False


def test_queue_redis_unavailable_fallback():
    with patch("redis.ConnectionPool.from_url", side_effect=Exception("Redis down")):
        with patch("app.backend.services.queue._redis_pool", None):
            res = enqueue_scan_id("CG-123")
            assert res is False

            pop_res = pop_scan_id(timeout=1)
            assert pop_res is None


@pytest.mark.asyncio
async def test_scan_service_redis_fallback_runs_inline():
    db = TestingSessionLocal()
    service = ScanService()

    with patch("app.backend.services.scan_service.enqueue_scan_id", return_value=False):
        with patch.object(service.orchestrator, "execute_scan", new_callable=AsyncMock) as mock_exec:
            mock_scan = Scan(
                id="CG-FALLBACK",
                input_type="url",
                target="https://fallback.com",
                raw_input="https://fallback.com",
                status="completed",
            )
            mock_exec.return_value = mock_scan
            result = await service.create_scan(db, "url", "https://fallback.com", run_sync=False)
            assert result.status == "completed"
            mock_exec.assert_called_once()
