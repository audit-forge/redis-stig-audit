"""Wiz SCC / Google Security Command Center output formatter for redis-stig-audit."""
import json
from datetime import datetime, timezone


def build_wiz(results: list, target: dict, tool_name: str, version: str) -> dict:
    findings = []
    for r in results:
        findings.append({
            "findingId": r.check_id,
            "title": r.title,
            "status": r.status.value,
            "severity": r.severity.value,
            "description": r.description,
            "actual": r.actual,
            "expected": r.expected,
            "remediation": r.remediation,
            "category": r.category,
        })
    return {
        "tool": tool_name,
        "version": version,
        "target": target,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
    }


def write_wiz(path: str, results: list, target: dict, tool_name: str, version: str) -> None:
    doc = build_wiz(results, target, tool_name, version)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)


write = write_wiz
