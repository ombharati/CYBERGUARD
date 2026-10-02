"""Background Scan Processing Worker.

Pulls jobs from Redis, executes the multi-engine scan pipeline asynchronously,
and records results to PostgreSQL.
"""
import asyncio
import signal
import sys
import logging
from app.backend.core.config import settings
from app.backend.core.database import SessionLocal
from app.backend.services.queue import pop_scan_id, enqueue_scan_id, is_redis_available
from app.backend.services.orchestrator import ScanOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyberguard.worker")


class ScanWorker:
    def __init__(self):
        self.running = True
        self.orchestrator = ScanOrchestrator()

    def stop(self, *args):
        logger.info("Worker received shutdown signal. Stopping gracefully...")
        self.running = False

    async def process_one(self, timeout: int = 2) -> bool:
        """Fetch and process a single scan from the queue. Returns True if a job was processed."""
        scan_id = pop_scan_id(timeout=timeout)
        if not scan_id:
            return False

        logger.info("Worker picked up scan ID: %s", scan_id)
        db = SessionLocal()
        try:
            await self.orchestrator.execute_scan(db, scan_id)
            return True
        except Exception as exc:
            logger.error("Worker unhandled exception for scan %s: %s", scan_id, exc, exc_info=True)
            return False
        finally:
            db.close()

    async def run(self):
        """Run continuous worker loop."""
        logger.info("CYBERGUARD Scan Worker started. Listening on queue '%s'", settings.SCAN_QUEUE_NAME)
        if not is_redis_available():
            logger.warning("Redis is currently not available. Waiting for connection...")

        while self.running:
            try:
                processed = await self.process_one(timeout=2)
                if not processed:
                    await asyncio.sleep(0.5)
            except Exception as loop_exc:
                logger.error("Error in worker main loop: %s", loop_exc)
                await asyncio.sleep(2.0)

        logger.info("Worker terminated cleanly.")


def main():
    worker = ScanWorker()
    signal.signal(signal.SIGINT, worker.stop)
    signal.signal(signal.SIGTERM, worker.stop)
    asyncio.run(worker.run())


if __name__ == "__main__":
    main()
