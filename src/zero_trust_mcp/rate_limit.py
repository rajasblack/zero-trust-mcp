from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(slots=True)
class TokenBucket:
    capacity: int
    refill_per_sec: float
    tokens: float
    last_ts: float

    def take(self, n: int = 1) -> tuple[bool, int]:
        now = time.time()
        elapsed = max(0.0, now - self.last_ts)
        self.last_ts = now

        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_sec)

        if self.tokens >= n:
            self.tokens -= n
            return True, int(self.tokens)

        return False, int(self.tokens)


class InMemoryRateLimiter:
    """
    Lightweight in-memory limiter. Good for single-process dev/demo.
    """

    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}

    def allow(self, key: str, limit_per_minute: int, burst: int) -> tuple[bool, dict[str, int]]:
        cap = max(1, burst if burst else limit_per_minute)
        refill_per_sec = max(0.1, limit_per_minute / 60.0)

        b = self._buckets.get(key)
        if b is None:
            b = TokenBucket(capacity=cap, refill_per_sec=refill_per_sec, tokens=float(cap), last_ts=time.time())
            self._buckets[key] = b

        ok, remaining = b.take(1)
        meta = {"limit": limit_per_minute, "burst": burst or cap, "remaining": max(0, remaining)}
        return ok, meta
