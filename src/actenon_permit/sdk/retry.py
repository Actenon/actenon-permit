"""Retry guidance for the Actenon SDK.

The SDK does NOT retry automatically — retries must be explicit.
This module provides helpers and guidance for safe retries.

Safe retry rules:
  1. Always use the same ``idempotency_key`` for retries of the same
     logical action. The broker's idempotency cache will return the
     original response.
  2. Only retry on ``OutcomeUnknownError`` or ``RetryableError``.
     Do NOT retry on ``ExecutionRefusedError`` (the action was
     refused — retrying won't help).
  3. Use exponential backoff with jitter to avoid thundering herds.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import TypeVar

T = TypeVar("T")


def with_retry(
    fn: Callable[[], T],
    *,
    max_attempts: int = 3,
    base_delay_seconds: float = 1.0,
    max_delay_seconds: float = 30.0,
    is_retryable: Callable[[Exception], bool] | None = None,
) -> T:
    """Call ``fn()`` with exponential backoff + jitter.

    Retries only if ``is_retryable(exc)`` returns True. By default,
    retries on ``OutcomeUnknownError`` and ``RetryableError``.

    Example::

        from actenon_permit.sdk import with_retry, OutcomeUnknownError

        result = with_retry(
            lambda: intent.execute(),
            max_attempts=5,
            base_delay_seconds=2.0,
        )
    """
    from .exceptions import OutcomeUnknownError, RetryableError

    if is_retryable is None:
        def is_retryable(exc: Exception) -> bool:
            return isinstance(exc, (OutcomeUnknownError, RetryableError))

    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if not is_retryable(exc):
                raise
            if attempt >= max_attempts:
                raise
            delay = min(
                base_delay_seconds * (2 ** (attempt - 1)),
                max_delay_seconds,
            )
            jitter = random.uniform(0, delay * 0.1)
            time.sleep(delay + jitter)

    # Unreachable, but keeps the type checker happy.
    assert last_exc is not None
    raise last_exc


__all__ = ["with_retry"]
