from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class BreachRecord:
    name: str
    date: str
    classes: tuple[str, ...]
    email: str
    source: str


@dataclass(frozen=True)
class Finding:
    name: str
    date: str
    classes: tuple[str, ...]
    sources: tuple[str, ...]
    severity: str
    rationale: str
    action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"classes": list(self.classes), "sources": list(self.sources)}


@dataclass
class PasswordResult:
    prefix: str
    matches: int
    checked_at: str
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExposureReport:
    email: str
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    password_check: PasswordResult | None = None
    errors: list[str] = field(default_factory=list)
    new_findings: list[Finding] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "report_type": "BreachCheck per-address exposure report",
            "disclaimer": "Lab-only output. Use only your own address or data you have written permission to check.",
            "address": self.email,
            "checked_at": self.checked_at,
            "sources": self.sources,
            "summary": {
                "findings": len(self.findings),
                "high": sum(item.severity == "High" for item in self.findings),
                "medium": sum(item.severity == "Medium" for item in self.findings),
                "low": sum(item.severity == "Low" for item in self.findings),
            },
            "findings": [item.to_dict() for item in self.findings],
            "errors": self.errors,
        }
        if self.password_check is not None:
            payload["password_check"] = self.password_check.to_dict()
        if self.new_findings is not None:
            payload["new_findings"] = [item.to_dict() for item in self.new_findings]
        return payload
