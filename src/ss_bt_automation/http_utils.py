"""HTTP retries and helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

T = TypeVar("T")


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in (429, 500, 502, 503, 504)
    if isinstance(exc, (httpx.ConnectError, httpx.ReadTimeout, httpx.WriteTimeout)):
        return True
    return False


def with_http_retries(
    fn: Callable[..., T],
    *,
    max_attempts: int = 5,
) -> Callable[..., T]:
    """Wrap a callable that may raise httpx errors with exponential backoff."""

    @retry(
        reraise=True,
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        retry=retry_if_exception(_is_retryable),
    )
    def _inner(*args: Any, **kwargs: Any) -> T:
        return fn(*args, **kwargs)

    return _inner
