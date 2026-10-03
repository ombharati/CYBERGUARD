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


def enqueue_scan_id(scan_id: str, queue_name: Optional[str] = None) -> bool:
    """
    Push a scan ID into the background processing queue.
    Returns True if successfully queued, False if Redis is unavailable.
    """
    client = get_redis_client()
    if not client:
        return False
    target_queue = queue_name or settings.SCAN_QUEUE_NAME
    try:
        client.lpush(target_queue, scan_id)
        logger.info("Enqueued scan %s to Redis queue '%s'", scan_id, target_queue)
        return True
    except Exception as exc:
        logger.warning("Failed to enqueue scan %s to Redis: %s", scan_id, exc)
        return False


def pop_scan_id(timeout: int = 2, queue_name: Optional[str] = None) -> Optional[str]:
    """
    Pop the next scan ID from the queue with blocking timeout.
    Returns None if queue is empty or Redis is unavailable.
    """
    client = get_redis_client()
    if not client:
        return None
    target_queue = queue_name or settings.SCAN_QUEUE_NAME
    try:
        item = client.brpop(target_queue, timeout=timeout)
        if item and len(item) == 2:
            return item[1]
        return None
    except redis.exceptions.TimeoutError:
        # Normal queue idle timeout
        return None
    except Exception as exc:
        logger.warning("Redis brpop error: %s", exc)
        return None
