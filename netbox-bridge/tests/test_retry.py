"""Tests for the retry helper.

Retry transient HTTP failures with exponential backoff. Permanent 4xx (other than 429) propagates
immediately. 429 honors Retry-After when present.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from netbox_bridge._retry import RetryConfig, with_retry


class _Boom(requests.HTTPError):
    def __init__(self, status: int, retry_after: str | None = None):
        response = MagicMock()
        response.status_code = status
        response.text = f"HTTP {status}"
        response.headers = {"Retry-After": retry_after} if retry_after else {}
        super().__init__(f"HTTP {status}", response=response)


@pytest.fixture
def fast_sleep(monkeypatch):
    """Skip real sleeps so tests stay snappy."""
    monkeypatch.setattr("netbox_bridge._retry.time.sleep", lambda _: None)


class TestSucceedsImmediately:
    def test_returns_value_on_first_call(self, fast_sleep):
        fn = MagicMock(return_value="ok")
        assert with_retry(fn, config=RetryConfig(max_attempts=4)) == "ok"
        assert fn.call_count == 1


class TestTransientFailures:
    def test_retries_on_500_then_succeeds(self, fast_sleep):
        fn = MagicMock(side_effect=[_Boom(500), _Boom(500), "ok"])
        assert with_retry(fn, config=RetryConfig(max_attempts=4)) == "ok"
        assert fn.call_count == 3

    def test_retries_on_connection_error(self, fast_sleep):
        fn = MagicMock(
            side_effect=[requests.ConnectionError("dns"), "ok"]
        )
        assert with_retry(fn, config=RetryConfig(max_attempts=4)) == "ok"
        assert fn.call_count == 2

    def test_retries_on_timeout(self, fast_sleep):
        fn = MagicMock(side_effect=[requests.Timeout("slow"), "ok"])
        assert with_retry(fn, config=RetryConfig(max_attempts=4)) == "ok"

    def test_gives_up_after_max_attempts(self, fast_sleep):
        fn = MagicMock(side_effect=_Boom(500))
        with pytest.raises(requests.HTTPError):
            with_retry(fn, config=RetryConfig(max_attempts=3))
        assert fn.call_count == 3


class TestPermanentFailures:
    def test_400_does_not_retry(self, fast_sleep):
        fn = MagicMock(side_effect=_Boom(400))
        with pytest.raises(requests.HTTPError):
            with_retry(fn, config=RetryConfig(max_attempts=4))
        assert fn.call_count == 1

    def test_401_does_not_retry(self, fast_sleep):
        fn = MagicMock(side_effect=_Boom(401))
        with pytest.raises(requests.HTTPError):
            with_retry(fn, config=RetryConfig(max_attempts=4))
        assert fn.call_count == 1

    def test_403_does_not_retry(self, fast_sleep):
        fn = MagicMock(side_effect=_Boom(403))
        with pytest.raises(requests.HTTPError):
            with_retry(fn, config=RetryConfig(max_attempts=4))
        assert fn.call_count == 1

    def test_404_does_not_retry(self, fast_sleep):
        fn = MagicMock(side_effect=_Boom(404))
        with pytest.raises(requests.HTTPError):
            with_retry(fn, config=RetryConfig(max_attempts=4))
        assert fn.call_count == 1


class TestThrottle:
    def test_429_retries(self, fast_sleep):
        fn = MagicMock(side_effect=[_Boom(429), _Boom(429), "ok"])
        assert with_retry(fn, config=RetryConfig(max_attempts=4)) == "ok"
        assert fn.call_count == 3

    def test_429_honors_retry_after_when_longer_than_backoff(self, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("netbox_bridge._retry.time.sleep", slept.append)
        fn = MagicMock(side_effect=[_Boom(429, retry_after="30"), "ok"])
        with_retry(
            fn,
            config=RetryConfig(max_attempts=4, base_delay=0.1, max_delay=60),
        )
        assert slept and slept[0] >= 30

    def test_429_caps_at_max_delay(self, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("netbox_bridge._retry.time.sleep", slept.append)
        fn = MagicMock(side_effect=[_Boom(429, retry_after="3600"), "ok"])
        with_retry(
            fn,
            config=RetryConfig(max_attempts=4, base_delay=0.1, max_delay=10),
        )
        assert slept[0] == 10


class TestBackoffBehavior:
    def test_delays_grow_exponentially(self, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("netbox_bridge._retry.time.sleep", slept.append)
        fn = MagicMock(side_effect=[_Boom(503), _Boom(503), _Boom(503), "ok"])
        with_retry(
            fn,
            config=RetryConfig(max_attempts=4, base_delay=1.0, jitter=0.0, max_delay=60),
        )
        # Each delay roughly doubles: 1.0, 2.0, 4.0
        assert slept == [1.0, 2.0, 4.0]

    def test_jitter_within_bounds(self, monkeypatch):
        slept: list[float] = []
        monkeypatch.setattr("netbox_bridge._retry.time.sleep", slept.append)
        fn = MagicMock(side_effect=[_Boom(503), "ok"])
        with_retry(
            fn,
            config=RetryConfig(max_attempts=4, base_delay=1.0, jitter=0.5, max_delay=60),
        )
        # base_delay (1.0) + jitter ∈ [0, 0.5)
        assert 1.0 <= slept[0] < 1.5


class TestNonHttpExceptionsPropagate:
    def test_value_error_does_not_retry(self, fast_sleep):
        fn = MagicMock(side_effect=ValueError("nope"))
        with pytest.raises(ValueError):
            with_retry(fn, config=RetryConfig(max_attempts=4))
        assert fn.call_count == 1
