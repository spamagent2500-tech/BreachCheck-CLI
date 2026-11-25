from __future__ import annotations

from .models import BreachRecord, Finding


def score(classes: tuple[str, ...]) -> tuple[str, str, str]:
    exposed = set(classes)
    if "password" in exposed or "password_hash" in exposed or "financial" in exposed:
        if "password" in exposed or "password_hash" in exposed:
            return "High", "A password or password hash was exposed.", "Change the password anywhere it was reused and enable MFA."
        return "High", "Financial data was exposed.", "Review statements, contact the provider, and monitor account activity."
    if "phone" in exposed or "address" in exposed:
        return "Medium", "Phone or address data could support targeted phishing.", "Watch for targeted phishing, verify recovery details, and monitor the account."
    return "Low", "Email or profile identifiers were exposed without higher-risk classes.", "Watch for phishing and use a unique password with MFA on the account."


def merge_findings(records: list[BreachRecord]) -> list[Finding]:
    grouped: dict[str, list[BreachRecord]] = {}
    for record in records:
        grouped.setdefault(record.name.strip().lower(), []).append(record)
    findings: list[Finding] = []
    for group in grouped.values():
        classes = tuple(sorted({item for record in group for item in record.classes}))
        dates = [record.date for record in group if record.date and record.date != "unknown"]
        date = min(dates) if dates else "unknown"
        severity, rationale, action = score(classes)
        findings.append(Finding(
            name=group[0].name,
            date=date,
            classes=classes,
            sources=tuple(sorted({record.source for record in group})),
            severity=severity,
            rationale=rationale,
            action=action,
        ))
    order = {"High": 0, "Medium": 1, "Low": 2}
    return sorted(findings, key=lambda item: (order[item.severity], item.name.lower()))
