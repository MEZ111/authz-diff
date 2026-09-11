#!/usr/bin/env python3
"""Detect authorization regressions between two OpenAPI specifications."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
SENSITIVE_HINTS = {"admin", "account", "billing", "payment", "user", "token", "auth", "secret", "internal"}
LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Regression:
    rule_id: str
    severity: str
    score: int
    method: str
    path: str
    message: str
    before: Any
    after: Any
    fingerprint: str


def load_spec(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        value = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("YAML input requires: python -m pip install PyYAML") from exc
        value = yaml.safe_load(text)
    if not isinstance(value, dict) or "paths" not in value:
        raise ValueError("expected an OpenAPI object with a paths field")
    return value


def operations(spec: dict) -> dict[tuple[str, str], dict]:
    result = {}
    for path, item in spec.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.lower() in HTTP_METHODS and isinstance(operation, dict):
                result[(str(path), method.upper())] = operation
    return result


def effective_security(spec: dict, operation: dict) -> list[dict]:
    value = operation["security"] if "security" in operation else spec.get("security", [])
    return value if isinstance(value, list) else []


def secured(requirements: list[dict]) -> bool:
    return bool(requirements) and all(isinstance(item, dict) and bool(item) for item in requirements)


def scopes(requirements: list[dict]) -> dict[str, set[str]]:
    merged: dict[str, set[str]] = {}
    for alternative in requirements:
        if not isinstance(alternative, dict):
            continue
        for scheme, values in alternative.items():
            merged.setdefault(str(scheme), set()).update(str(value) for value in (values or []))
    return merged


def make_regression(rule: str, severity: str, score: int, method: str, path: str,
                    message: str, before: Any, after: Any) -> Regression:
    identity = json.dumps([rule, method, path, before, after], sort_keys=True, default=list)
    return Regression(rule, severity, score, method, path, message, before, after,
                      hashlib.sha256(identity.encode()).hexdigest()[:12])


def compare(before: dict, after: dict) -> list[Regression]:
    findings: list[Regression] = []
    old_ops, new_ops = operations(before), operations(after)
    for key in sorted(old_ops.keys() & new_ops.keys()):
        path, method = key
        old_sec = effective_security(before, old_ops[key])
        new_sec = effective_security(after, new_ops[key])
        if secured(old_sec) and not secured(new_sec):
            findings.append(make_regression("AZD001", "critical", 100, method, path,
                "Operation changed from authenticated to anonymous", old_sec, new_sec))
            continue
        old_scopes, new_scopes = scopes(old_sec), scopes(new_sec)
        for scheme in sorted(old_scopes.keys() & new_scopes.keys()):
            removed = sorted(old_scopes[scheme] - new_scopes[scheme])
            if removed:
                findings.append(make_regression("AZD002", "high", 80, method, path,
                    f"Required scopes removed from {scheme}: {', '.join(removed)}",
                    sorted(old_scopes[scheme]), sorted(new_scopes[scheme])))
        removed_schemes = sorted(old_scopes.keys() - new_scopes.keys())
        if removed_schemes and secured(new_sec):
            findings.append(make_regression("AZD003", "high", 75, method, path,
                f"Security requirement removed: {', '.join(removed_schemes)}", old_sec, new_sec))
    for key in sorted(new_ops.keys() - old_ops.keys()):
        path, method = key
        security = effective_security(after, new_ops[key])
        if not secured(security):
            sensitive = any(hint in path.lower() for hint in SENSITIVE_HINTS)
            findings.append(make_regression("AZD004", "high" if sensitive else "medium",
                75 if sensitive else 55, method, path, "New operation is anonymous", None, security))
    old_schemes = set(before.get("components", {}).get("securitySchemes", {}))
    new_schemes = set(after.get("components", {}).get("securitySchemes", {}))
    for scheme in sorted(old_schemes - new_schemes):
        findings.append(make_regression("AZD005", "high", 85, "*", "components.securitySchemes",
            f"Security scheme definition removed: {scheme}", scheme, None))
    return sorted(findings, key=lambda f: (-f.score, f.path, f.method, f.rule_id))


def markdown(findings: list[Regression]) -> str:
    lines = ["# AuthZDiff", "", f"**Authorization regressions:** {len(findings)}", "",
             "| Score | Rule | Severity | Operation | Change |", "| ---: | --- | --- | --- | --- |"]
    for item in findings:
        message = item.message.replace("|", "\\|")
        lines.append(f"| {item.score} | {item.rule_id} | {item.severity} | `{item.method} {item.path}` | {message} |")
    lines += ["", "> Review signals against the API's intended access policy before release.", ""]
    return "\n".join(lines)


def sarif(findings: list[Regression], after_path: str) -> dict:
    rules = {
        "AZD001": "Authentication removed", "AZD002": "OAuth scope weakened",
        "AZD003": "Security requirement removed", "AZD004": "New anonymous operation",
        "AZD005": "Security scheme removed",
    }
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "AuthZDiff", "rules": [
            {"id": key, "shortDescription": {"text": value}} for key, value in rules.items()
        ]}},
        "results": [{"ruleId": item.rule_id, "level": "error" if LEVEL[item.severity] >= 3 else "warning",
                     "message": {"text": f"{item.method} {item.path}: {item.message}"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": after_path}}}],
                     "properties": asdict(item)} for item in findings],
    }]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--fail-level", choices=tuple(LEVEL), default="critical")
    args = parser.parse_args()
    findings = compare(load_spec(args.before), load_spec(args.after))
    if args.format == "sarif":
        payload: Any = sarif(findings, str(args.after))
        output = json.dumps(payload, indent=2)
    elif args.format == "json":
        output = json.dumps({"regressions": [asdict(f) for f in findings]}, indent=2)
    else:
        output = markdown(findings)
    args.output.write_text(output, encoding="utf-8") if args.output else print(output)
    threshold = LEVEL[args.fail_level]
    return 1 if any(LEVEL[item.severity] >= threshold for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
