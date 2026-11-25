from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import TextIO

from .models import ExposureReport


def render_text(report: ExposureReport) -> str:
    lines = [
        "BreachCheck — Per-address exposure report",
        "=" * 48,
        f"Address: {report.email}",
        f"Checked: {report.checked_at}",
        f"Sources: {', '.join(report.sources) if report.sources else 'None'}",
        "",
    ]
    if report.password_check:
        status = f"{report.password_check.matches} match(es)"
        cached = " (cached)" if report.password_check.cached else ""
        lines += [f"Password k-anonymity: prefix {report.password_check.prefix}, {status}{cached}", ""]
    if not report.findings:
        lines.append("No breach exposure found in the checked sources.")
    else:
        lines.append(f"Findings: {len(report.findings)}")
        for index, finding in enumerate(report.findings, 1):
            lines += [
                f"\n{index}. {finding.name} [{finding.severity}]",
                f"   Date: {finding.date}",
                f"   Data classes: {', '.join(finding.classes)}",
                f"   Sources: {', '.join(finding.sources)}",
                f"   Why: {finding.rationale}",
                f"   Action: {finding.action}",
            ]
    if report.new_findings is not None:
        lines += ["", f"New since previous report: {len(report.new_findings)}"]
    if report.errors:
        lines += ["", "Warnings:"] + [f"- {error}" for error in report.errors]
    lines += ["", "Lab-only: use only your own address or data you have written permission to check."]
    return "\n".join(lines) + "\n"


def write_report(report: ExposureReport, path: str | Path | None, fmt: str = "text", stream: TextIO = sys.stdout) -> None:
    if fmt == "text":
        content = render_text(report)
    elif fmt == "json":
        content = json.dumps(report.to_dict(), indent=2) + "\n"
    elif fmt == "csv":
        output = __import__("io").StringIO()
        writer = csv.DictWriter(output, fieldnames=["address", "name", "date", "classes", "sources", "severity", "rationale", "action"])
        writer.writeheader()
        for finding in report.findings:
            writer.writerow({"address": report.email, "name": finding.name, "date": finding.date, "classes": ";".join(finding.classes), "sources": ";".join(finding.sources), "severity": finding.severity, "rationale": finding.rationale, "action": finding.action})
        content = output.getvalue()
    else:
        raise ValueError(f"Unsupported report format: {fmt}")
    if path:
        Path(path).write_text(content, encoding="utf-8")
    else:
        stream.write(content)
