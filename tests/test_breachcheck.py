from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from breachcheck.breach_api import EmailBreachClient
from breachcheck.cache import JsonCache
from breachcheck.dataset import find_matches
from breachcheck.models import BreachRecord
from breachcheck.password_check import check_password
from breachcheck.scoring import merge_findings


class BreachCheckTests(unittest.TestCase):
    def test_local_dataset_normalizes_and_filters_email(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "data.csv"
            path.write_text("email,name,date,classes\nTEST@LAB.TEST,Demo,2025-01-01,email|phone\nother@lab.test,Other,2024-01-01,email\n", encoding="utf-8")
            matches = find_matches([path], "test@lab.test")
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].name, "Demo")

    def test_merge_deduplicates_and_unions_sources_and_classes(self) -> None:
        records = [
            BreachRecord("Demo", "2025-02-01", ("email", "password"), "a@lab.test", "Email breach API"),
            BreachRecord("Demo", "2025-01-01", ("email", "phone"), "a@lab.test", "Local dataset"),
        ]
        findings = merge_findings(records)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].date, "2025-01-01")
        self.assertEqual(set(findings[0].classes), {"email", "password", "phone"})
        self.assertEqual(findings[0].severity, "High")

    def test_password_request_contains_only_five_character_prefix(self) -> None:
        observed: list[str] = []

        def fake_request(prefix: str, endpoint: str, timeout: float) -> str:
            observed.append(prefix)
            return "AABBCCDDEEFF00112233445566778899:9\n"

        with tempfile.TemporaryDirectory() as folder:
            result = check_password("lab-only-password", cache=JsonCache(folder), request=fake_request)
        self.assertEqual(len(observed[0]), 5)
        self.assertEqual(result.prefix, observed[0])
        self.assertNotIn("lab-only-password", observed[0])

    def test_password_result_uses_cache_on_second_check(self) -> None:
        calls = 0

        def fake_request(prefix: str, endpoint: str, timeout: float) -> str:
            nonlocal calls
            calls += 1
            return "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:4\n"

        with tempfile.TemporaryDirectory() as folder:
            cache = JsonCache(folder)
            first = check_password("cache-test", cache=cache, request=fake_request)
            second = check_password("cache-test", cache=cache, request=fake_request)
        self.assertEqual(calls, 1)
        self.assertFalse(first.cached)
        self.assertTrue(second.cached)

    def test_email_client_retries_429_and_parses_response(self) -> None:
        client = EmailBreachClient(cache=JsonCache(tempfile.mkdtemp()), api_key="lab-key", retries=1)
        calls = 0

        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self): return b'[{"Name":"Demo","BreachDate":"2025-01-01","DataClasses":["Emails","Passwords"]}]'

        def fake_urlopen(request, timeout):
            nonlocal calls
            calls += 1
            if calls == 1:
                from urllib.error import HTTPError
                raise HTTPError(request.full_url, 429, "rate limit", {"Retry-After": "0"}, None)
            return Response()

        with patch("breachcheck.breach_api.urllib.request.urlopen", side_effect=fake_urlopen):
            records, cached = client.lookup("a@lab.test")
        self.assertEqual(calls, 2)
        self.assertFalse(cached)
        self.assertEqual(records[0].name, "Demo")
        self.assertEqual(records[0].source, "Email breach API")
        self.assertEqual(records[0].classes, ("email", "password"))


if __name__ == "__main__":
    unittest.main()
