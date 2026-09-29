import asyncio
import time

import httpx
import pytest

from reliability import TokenBucket, CircuitBreaker, with_reliability, _reset_for_tests


async def test_token_bucket_allows_burst_up_to_capacity():
    bucket = TokenBucket(capacity=3, refill_rate=1)
    start = time.monotonic()
    for _ in range(3):
        await bucket.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.1  # shouldn't wait at all within capacity


async def test_token_bucket_waits_when_exhausted():
    bucket = TokenBucket(capacity=1, refill_rate=10)  # refills fast for test speed
    await bucket.acquire()  # use the only token
    start = time.monotonic()
    await bucket.acquire()  # should wait ~0.1s for refill
    elapsed = time.monotonic() - start
    assert elapsed > 0.05


def test_circuit_breaker_opens_after_threshold():
    breaker = CircuitBreaker(failure_threshold=3, cooldown_seconds=60)
    assert breaker.is_open() is False

    for _ in range(3):
        breaker.record_failure()

    assert breaker.is_open() is True


def test_circuit_breaker_closes_on_success():
    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.is_open() is True

    breaker.record_success()
    assert breaker.is_open() is False


def test_circuit_breaker_allows_trial_after_cooldown():
    breaker = CircuitBreaker(failure_threshold=1, cooldown_seconds=0.05)
    breaker.record_failure()
    assert breaker.is_open() is True

    time.sleep(0.1)
    assert breaker.is_open() is False  # cooldown elapsed, trial allowed


async def test_with_reliability_retries_transient_failures(monkeypatch):
    _reset_for_tests()
    call_count = {"n": 0}

    @with_reliability("AbuseIPDB")
    async def flaky():
        call_count["n"] += 1
        if call_count["n"] < 2:
            request = httpx.Request("GET", "https://example.com")
            response = httpx.Response(503, request=request)
            raise httpx.HTTPStatusError("server error", request=request, response=response)
        return {"source": "AbuseIPDB", "skipped": False, "error": None, "malicious": False}

    result = await flaky()
    assert call_count["n"] == 2  # failed once, retried, succeeded
    assert result["error"] is None


async def test_with_reliability_gives_up_after_max_attempts():
    _reset_for_tests()

    @with_reliability("AbuseIPDB")
    async def always_fails():
        request = httpx.Request("GET", "https://example.com")
        response = httpx.Response(500, request=request)
        raise httpx.HTTPStatusError("server error", request=request, response=response)

    result = await always_fails()
    assert result["error"] is not None  # returns an error dict, doesn't raise


async def test_with_reliability_does_not_retry_non_transient_errors():
    _reset_for_tests()
    call_count = {"n": 0}

    @with_reliability("AbuseIPDB")
    async def bad_request():
        call_count["n"] += 1
        request = httpx.Request("GET", "https://example.com")
        response = httpx.Response(400, request=request)  # not transient
        raise httpx.HTTPStatusError("bad request", request=request, response=response)

    result = await bad_request()
    assert call_count["n"] == 1  # no retries for a 400
    assert result["error"] is not None
