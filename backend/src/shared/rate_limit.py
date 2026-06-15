"""Simple in-memory rate limiter for API endpoints."""
from __future__ import annotations
import time
import threading
from collections import defaultdict
from fastapi import Request, HTTPException

_lock = threading.Lock()
_buckets: dict[str, list[float]] = defaultdict(list)


class RateLimitExceeded(HTTPException):
    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            status_code=429,
            detail={"error": "rate_limited", "retry_after_seconds": retry_after_seconds},
            headers={"Retry-After": str(retry_after_seconds)},
        )


def rate_limit(key: str, max_requests: int, window_seconds: int) -> None:
    """Raise RateLimitExceeded if rate limit exceeded. Includes Retry-After."""
    now = time.time()
    cutoff = now - window_seconds
    with _lock:
        bucket = _buckets[key]
        _buckets[key] = [t for t in bucket if t > cutoff]
        if len(_buckets[key]) >= max_requests:
            oldest = min(_buckets[key])
            retry_after = max(1, int(oldest + window_seconds - now) + 1)
            raise RateLimitExceeded(retry_after_seconds=retry_after)
        _buckets[key].append(now)

def rate_limit_by_ip(request: Request, max_requests: int = 10, window_seconds: int = 60) -> None:
    """Rate limit by client IP."""
    ip = request.client.host if request.client else "unknown"
    rate_limit(f"ip:{ip}", max_requests, window_seconds)

def rate_limit_scan(request: Request, tool: str) -> None:
    """Rate limit scan initiation: 5 scans per tool per 5 minutes."""
    ip = request.client.host if request.client else "unknown"
    rate_limit(f"scan:{tool}:{ip}", 5, 300)


def rate_limit_by_runner(runner_id: str, max_requests: int, window_seconds: int) -> None:
    """Rate limit a runner-keyed endpoint. Raises 429 when exceeded."""
    rate_limit(f"runner:{runner_id}", max_requests, window_seconds)
