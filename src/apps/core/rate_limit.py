import time
from collections import defaultdict
from threading import Lock
from typing import Dict, Tuple

from fastapi import HTTPException, status

from src.apps.core.config import settings


class RateLimiter:
    """Simple in-memory fixed-window rate limiter."""

    def __init__(self) -> None:
        self._buckets: Dict[str, Tuple[int, float]] = {}
        self._lock = Lock()

    def check(self, key: str, max_requests: int, window_seconds: int) -> None:
        now = time.time()
        with self._lock:
            count, window_start = self._buckets.get(key, (0, now))

            if now - window_start >= window_seconds:
                count = 0
                window_start = now

            if count >= max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded. Please try again later.",
                )

            self._buckets[key] = (count + 1, window_start)


_rate_limiter = RateLimiter()


def auth_rate_limit(key: str) -> None:
    _rate_limiter.check(
        key=key,
        max_requests=settings.AUTH_RATE_LIMIT_REQUESTS,
        window_seconds=settings.AUTH_RATE_LIMIT_WINDOW,
    )


def general_rate_limit(key: str) -> None:
    _rate_limiter.check(
        key=key,
        max_requests=settings.RATE_LIMIT_REQUESTS,
        window_seconds=settings.RATE_LIMIT_WINDOW,
    )
