from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Callable

from .cache import JsonCache
from .models import PasswordResult


class PasswordApiError(RuntimeError):
    pass


def _request_range(prefix: str, endpoint: str, timeout: float) -> str:
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/{prefix}",
        headers={"User-Agent": "BreachCheck-lab/1.0", "Add-Padding": "true"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raise PasswordApiError("Password range API rate limit reached (HTTP 429). Try again later.") from exc
        raise PasswordApiError(f"Password range API returned HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise PasswordApiError(f"Password range API request failed: {exc.reason if hasattr(exc, 'reason') else exc}") from exc


def check_password(
    password: str,
    *,
    cache: JsonCache,
    endpoint: str = "https://api.pwnedpasswords.com/range",
    timeout: float = 10.0,
    retries: int = 3,
    request: Callable[[str, str, float], str] = _request_range,
) -> PasswordResult:
    if not password:
        raise ValueError("Password cannot be empty.")
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    cached = cache.get("password-range", prefix)
    if cached is None:
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            try:
                body = request(prefix, endpoint, timeout)
                break
            except PasswordApiError as exc:
                last_error = exc
                if attempt >= retries:
                    raise
                time.sleep(2**attempt)
        else:
            raise PasswordApiError(str(last_error))
        counts: dict[str, int] = {}
        for line in body.splitlines():
            if ":" not in line:
                continue
            returned_suffix, raw_count = line.strip().split(":", 1)
            try:
                counts[returned_suffix.strip().upper()] = int(raw_count.strip())
            except ValueError:
                continue
        cache.set("password-range", prefix, counts)
        is_cached = False
    else:
        counts = {str(key).upper(): int(value) for key, value in cached.items()}
        is_cached = True
    return PasswordResult(
        prefix=prefix,
        matches=counts.get(suffix, 0),
        checked_at=datetime.now(timezone.utc).isoformat(),
        cached=is_cached,
    )
