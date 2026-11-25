from __future__ import annotations

import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .cache import JsonCache
from .models import BreachRecord


class BreachApiError(RuntimeError):
    pass


def normalize_api_class(value: object) -> str:
    raw = str(value).strip().lower()
    aliases = {
        "passwords": "password",
        "password hashes": "password_hash",
        "password hints": "password",
        "credit cards": "financial",
        "bank account numbers": "financial",
        "financial information": "financial",
        "phone numbers": "phone",
        "physical addresses": "address",
        "email addresses": "email",
        "emails": "email",
        "usernames": "username",
    }
    return aliases.get(raw, raw)


class EmailBreachClient:
    def __init__(self, *, cache: JsonCache, api_key: str | None = None, endpoint: str = "https://haveibeenpwned.com/api/v3/breachedaccount", timeout: float = 15.0, retries: int = 3) -> None:
        self.cache = cache
        self.api_key = api_key or os.getenv("HIBP_API_KEY")
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.retries = retries

    def lookup(self, email: str) -> tuple[list[BreachRecord], bool]:
        if not self.api_key:
            raise BreachApiError("HIBP_API_KEY is not set. Set it in the environment or use --offline for local lab data.")
        normalized = email.strip().lower()
        cached = self.cache.get("email-breach", normalized)
        if cached is not None:
            return [BreachRecord(**item) for item in cached], True
        url = f"{self.endpoint}/{urllib.parse.quote(normalized, safe='')}?truncateResponse=false"
        request = urllib.request.Request(url, headers={"hibp-api-key": self.api_key, "user-agent": "BreachCheck-lab/1.0"})
        payload: Any
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = response.read().decode("utf-8")
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    payload = "[]"
                    break
                if exc.code == 429 and attempt < self.retries:
                    retry_after = exc.headers.get("Retry-After", "")
                    delay = float(retry_after) if retry_after.isdigit() else 2**attempt
                    time.sleep(min(delay, 30))
                    continue
                if exc.code in {401, 403}:
                    raise BreachApiError("Email breach API rejected the API key (HTTP %s)." % exc.code) from exc
                raise BreachApiError(f"Email breach API returned HTTP {exc.code}.") from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < self.retries:
                    time.sleep(2**attempt)
                    continue
                reason = exc.reason if hasattr(exc, "reason") else exc
                raise BreachApiError(f"Email breach API request failed: {reason}") from exc
        else:
            raise BreachApiError("Email breach API request failed after retries.")
        try:
            rows = __import__("json").loads(payload)
        except ValueError as exc:
            raise BreachApiError("Email breach API returned invalid JSON.") from exc
        if not isinstance(rows, list):
            raise BreachApiError("Email breach API returned an unexpected response.")
        records = [BreachRecord(name=str(row.get("Name", "Unknown breach")), date=str(row.get("BreachDate", "unknown")), classes=tuple(normalize_api_class(item) for item in row.get("DataClasses", [])), email=normalized, source="Email breach API") for row in rows if isinstance(row, dict)]
        self.cache.set("email-breach", normalized, [record.__dict__ for record in records])
        return records, False
