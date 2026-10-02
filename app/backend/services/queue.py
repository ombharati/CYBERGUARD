"""Redis Queue Client and Job Enqueuing with Graceful Fallback."""
import logging
from typing import Optional
import redis
from app.backend.core.config import settings

logger = logging.getLogger(__name__)

_redis_pool = None


def get_redis_client() -> Optional[redis.Redis]:
    """Get a pooled Redis client connection."""
    global _redis_pool
    try:
        if _redis_pool is None:
            _redis_pool = redis.ConnectionPool.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=5.0,
                socket_connect_timeout=3.0,
            )
        return redis.Redis(connection_pool=_redis_pool)
    except Exception as exc:
        logger.warning("Could not initialize Redis pool: %s", exc)
        return None


def is_redis_available() -> bool:
    """Check if Redis server is reachable."""
    client = get_redis_client()
    if not client:
        return False
    try:
        return bool(client.ping())
    except Exception:
        return False


def enqueue_scan_id(scan_id: str) -> bool:
    """
    Push a scan ID into the background processing queue.
    Returns True if successfully queued, False if Redis is unavailable.
    """
    client = get_redis_client()
    if not client:
        return False
    try:
        client.lpush(settings.SCAN_QUEUE_NAME, scan_id)
        logger.info("Enqueued scan %s to Redis queue '%s'", scan_id, settings.SCAN_QUEUE_NAME)
        return True
    except Exception as exc:
        logger.warning("Failed to enqueue scan %s to Redis: %s", scan_id, exc)
        return False


def pop_scan_id(timeout: int = 2) -> Optional[str]:
    """
    Pop the next scan ID from the queue with blocking timeout.
    Returns None if queue is empty or Redis is unavailable.
    """
    client = get_redis_client()
    if not client:
        return None
    try:
        item = client.brpop(settings.SCAN_QUEUE_NAME, timeout=timeout)
        if item and len(item) == 2:
            return item[1]
        return None
    except redis.exceptions.TimeoutError:
        # Normal queue idle timeout
        return None
    except Exception as exc:
        logger.warning("Redis brpop error: %s", exc)
        return None
