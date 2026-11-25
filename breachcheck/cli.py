from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path

from .breach_api import BreachApiError, EmailBreachClient
from .cache import JsonCache
from .dataset import find_matches, normalize_email
from .models import ExposureReport, Finding
from .password_check import PasswordApiError, check_password
from .report import write_report
from .scoring import merge_findings


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="BreachCheck — privacy-preserving breach exposure checker")
    p.add_argument("--email", help="address to check")
    p.add_argument("--dataset", action="append", default=[], help="local CSV/JSON/JSONL dataset (repeatable)")
    p.add_argument("--cache-dir", default=".breachcheck-cache", help="directory for cached API responses")
    p.add_argument("--output", help="write the report to a file instead of stdout")
    p.add_argument("--format", choices=("text", "json", "csv"), default="text")
    p.add_argument("--check-password", action="store_true", help="prompt securely for a lab-only password")
    p.add_argument("--offline", action="store_true", help="skip external APIs and use only local datasets")
    p.add_argument("--batch", help="file containing one lab email address per line")
    p.add_argument("--delay", type=float, default=1.0, help="seconds between batch checks")
    p.add_argument("--previous-report", help="JSON report used to show only newly seen breaches")
    return p


def validate_email(email: str) -> str:
    normalized = normalize_email(email)
    if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
        raise ValueError("Enter a valid email address.")
    return normalized


def previous_names(path: str | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {str(item.get("name", "")).lower() for item in data.get("findings", []) if isinstance(item, dict)}


def run_one(email: str, args: argparse.Namespace, cache: JsonCache) -> ExposureReport:
    normalized = validate_email(email)
    records = []
    errors: list[str] = []
    sources: list[str] = []
    if args.offline:
        sources.append("Offline mode")
    else:
        try:
            api_records, cached = EmailBreachClient(cache=cache).lookup(normalized)
            records.extend(api_records)
            sources.append("Email breach API" + (" (cache)" if cached else ""))
        except BreachApiError as exc:
            errors.append(str(exc))
    if args.dataset:
        records.extend(find_matches(args.dataset, normalized))
        sources.append("Local datasets")
    report = ExposureReport(email=normalized, findings=merge_findings(records), sources=sources, errors=errors)
    if args.check_password and not args.batch:
        password = getpass.getpass("Lab-only password (input hidden; never use a real password): ")
        try:
            report.password_check = check_password(password, cache=cache)
        except (PasswordApiError, ValueError) as exc:
            report.errors.append(str(exc))
        finally:
            del password
    old = previous_names(args.previous_report)
    if args.previous_report:
        report.new_findings = [finding for finding in report.findings if finding.name.lower() not in old]
    return report


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if not args.email and not args.batch:
        parser().error("provide --email or --batch")
    if args.batch and args.check_password:
        parser().error("--check-password cannot be used with --batch")
    cache = JsonCache(args.cache_dir)
    emails = [args.email] if args.email else [line.strip() for line in Path(args.batch).read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
    for index, email in enumerate(emails):
        try:
            report = run_one(email, args, cache)
            write_report(report, args.output if len(emails) == 1 else None, args.format)
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            print(f"BreachCheck error: {exc}", file=sys.stderr)
            return 2
        if index < len(emails) - 1:
            time.sleep(max(0.0, args.delay))
    return 0
