"""
Shared reliability layer: per-source rate limiting + retry with backoff.

Rate limiting: a simple async token bucket per source, so we never
send more requests than that API's free-tier limit allows — we queue
and wait instead of firing and getting a 429 back.

Retry: wraps transient failures (429, 5xx, timeouts) with exponential
backoff via tenacity. Non-transient errors (4xx other than 429) are
NOT retried — retrying a bad API key or malformed request just wastes
time and burns rate limit budget.
"""

import asyncio
import time

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception,
)

import config
from logger import get_logger

log = get_logger("reliability")

# Retry tuning is read from config at decoration time so tests can shrink
# these to near-zero (see tests/conftest.py) without touching prod code paths.
RETRY_ATTEMPTS = getattr(config, "RETRY_ATTEMPTS", 3)
RETRY_MIN_WAIT = getattr(config, "RETRY_MIN_WAIT", 1)
RETRY_MAX_WAIT = getattr(config, "RETRY_MAX_WAIT", 10)


class RateLimitExceeded(Exception):
    """Raised internally when a circuit is open — caught by callers."""


class TokenBucket:
    """Simple async token bucket: `capacity` tokens, refilled at `refill_rate`/sec."""

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.last_refill = time.monotonic()
        self._lock = None
        self._lock_loop = None

    def _get_lock(self) -> asyncio.Lock:
        # asyncio.Lock binds to whatever event loop is running when it's
        # first used. If this process calls asyncio.run() more than once
        # (e.g. a long-lived process invoking the enrichment pipeline
        # repeatedly, like a Splunk custom command), each run gets a new
        # loop — a lock created under an old loop would raise
        # "bound to a different event loop" on the next run. Recreating
        # it whenever the running loop changes avoids that.
        current_loop = asyncio.get_running_loop()
        if self._lock is None or self._lock_loop is not current_loop:
            self._lock = asyncio.Lock()
            self._lock_loop = current_loop
        return self._lock

    async def acquire(self):
        async with self._get_lock():
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / self.refill_rate
                log.debug("rate limit reached, waiting", extra={"wait_seconds": round(wait_time, 2)})
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class CircuitBreaker:
    """
    After `failure_threshold` consecutive failures, stop calling this
    source for `cooldown_seconds` — protects against hammering a
    source that's clearly down, and burning rate-limit budget on a
    service that isn't going to answer anyway.
    """

    def __init__(self, failure_threshold: int = 5, cooldown_seconds: float = 60):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.consecutive_failures = 0
        self.opened_at = None

    def is_open(self) -> bool:
        if self.opened_at is None:
            return False
        if time.monotonic() - self.opened_at > self.cooldown_seconds:
            # cooldown elapsed, allow a trial request through
            self.opened_at = None
            self.consecutive_failures = 0
            return False
        return True

    def record_success(self):
        self.consecutive_failures = 0
        self.opened_at = None

    def record_failure(self):
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold and self.opened_at is None:
            self.opened_at = time.monotonic()
            log.warning("circuit breaker opened", extra={"cooldown_seconds": self.cooldown_seconds})


# One bucket + breaker per source, sized to each API's published free-tier limit.
# Conservative on purpose — better to be a bit slower than to get rate-limited.
_BUCKETS = {
    "AbuseIPDB": TokenBucket(capacity=5, refill_rate=5 / 60),      # ~1000/day soft-paced
    "VirusTotal": TokenBucket(capacity=4, refill_rate=4 / 60),     # 4 req/min hard limit
    "Shodan": TokenBucket(capacity=1, refill_rate=1 / 1),          # 1 req/sec
    "OTX": TokenBucket(capacity=10, refill_rate=10 / 60),
}

_BREAKERS = {name: CircuitBreaker() for name in _BUCKETS}


def _reset_for_tests():
    """Resets all buckets/breakers to a clean, fast state. Called from
    test fixtures only. Widens capacity/refill so batch tests exercising
    many IOCs don't hit real multi-second rate-limit waits — the token
    bucket algorithm itself is covered separately by dedicated tests
    against standalone TokenBucket instances in test_reliability.py."""
    for name, bucket in _BUCKETS.items():
        bucket.capacity = 1000
        bucket.refill_rate = 1000
        bucket.tokens = 1000
        bucket.last_refill = time.monotonic()
        bucket._lock = None
        bucket._lock_loop = None
    for breaker in _BREAKERS.values():
        breaker.consecutive_failures = 0
        breaker.opened_at = None


def _is_transient(exc: BaseException) -> bool:
    if isinstance(exc, httpx.TimeoutException):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        return code == 429 or 500 <= code < 600
    return False


def with_reliability(source_name: str):
    """
    Decorator for a source's `check()` function. Applies:
    1. Circuit breaker check (fail fast if source is known-down)
    2. Rate limiting (wait for a token before calling)
    3. Retry with exponential backoff on transient failures
    """
    bucket = _BUCKETS.get(source_name)
    breaker = _BREAKERS.get(source_name)

    def decorator(func):
        @retry(
            stop=stop_after_attempt(RETRY_ATTEMPTS),
            wait=wait_exponential(multiplier=1, min=RETRY_MIN_WAIT, max=RETRY_MAX_WAIT),
            retry=retry_if_exception(_is_transient),
            reraise=True,
        )
        async def call_with_retry(*args, **kwargs):
            return await func(*args, **kwargs)

        async def wrapper(*args, **kwargs):
            if breaker and breaker.is_open():
                log.warning("skipping call, circuit open", extra={"source": source_name})
                return {
                    "source": source_name, "skipped": True,
                    "reason": "circuit breaker open (recent repeated failures)",
                }

            if bucket:
                await bucket.acquire()

            try:
                result = await call_with_retry(*args, **kwargs)
                if breaker:
                    breaker.record_success()
                return result
            except Exception as e:
                if breaker:
                    breaker.record_failure()
                log.error("source call failed after retries",
                          extra={"source": source_name, "error": str(e)})
                return {"source": source_name, "skipped": False, "error": str(e)}

        return wrapper
    return decorator
