#!/usr/bin/env python3
"""Detect authorization regressions between two OpenAPI specifications."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
SENSITIVE_HINTS = {"admin", "account", "billing", "payment", "user", "token", "auth", "secret", "internal"}
LEVEL = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
RULES = {
    "AZD001": "Authentication removed",
    "AZD002": "Required scopes weakened",
    "AZD003": "Required security scheme removed",
    "AZD004": "New anonymous operation",
    "AZD005": "Security scheme definition removed",
    "AZD006": "Weaker security alternative added",
    "AZD007": "Security scheme type changed",
}
Requirement = tuple[tuple[str, tuple[str, ...]], ...]

@dataclass(frozen=True)
class Regression:
    rule_id: str
    severity: str
    score: int
    confidence: str
    method: str
    path: str
    message: str
    rationale: str
    before: Any
    after: Any
    fingerprint: str

def _security_schemes(spec: dict[str, Any]) -> dict[str, Any]:
    components = spec.get("components", {})
    if components is None:
        return {}
    if not isinstance(components, dict):
        raise ValueError("components must be an object")
    schemes = components.get("securitySchemes", {})
    if schemes is None:
        return {}
    if not isinstance(schemes, dict):
        raise ValueError("components.securitySchemes must be an object")
    return schemes

def _validate_security(value: Any, schemes: dict[str, Any], where: str) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{where} must be an array")
    for index, requirement in enumerate(value):
        if not isinstance(requirement, dict):
            raise ValueError(f"{where}[{index}] must be an object")
        for name, scopes in requirement.items():
            if not isinstance(name, str) or not name:
                raise ValueError(f"{where}[{index}] contains an invalid security scheme name")
            if name not in schemes:
                raise ValueError(f"{where}[{index}] references undefined security scheme: {name}")
            if not isinstance(scopes, list) or not all(isinstance(scope, str) for scope in scopes):
                raise ValueError(f"{where}[{index}].{name} must be an array of strings")

def validate_spec(spec: dict[str, Any]) -> None:
    if not isinstance(spec, dict):
        raise ValueError("expected an OpenAPI object")
    version = spec.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise ValueError("expected an OpenAPI 3.x document")
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("expected an OpenAPI object with a paths object")
    schemes = _security_schemes(spec)
    for name, definition in schemes.items():
        if not isinstance(name, str) or not isinstance(definition, dict):
            raise ValueError("security scheme definitions must be objects")
        if not isinstance(definition.get("type"), str):
            raise ValueError(f"security scheme {name} needs a string type")
    if "security" in spec:
        _validate_security(spec["security"], schemes, "security")
    for path, item in paths.items():
        if not isinstance(path, str) or not isinstance(item, dict):
            raise ValueError("each paths entry must map a string path to an object")
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise ValueError(f"{method.upper()} {path} must be an object")
            if "security" in operation:
                _validate_security(operation["security"], schemes, f"{method.upper()} {path}.security")

def load_spec(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        value = json.loads(text)
    else:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("YAML input requires PyYAML") from exc
        value = yaml.safe_load(text)
    if not isinstance(value, dict):
        raise ValueError("expected an OpenAPI object")
    validate_spec(value)
    return value

def operations(spec: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    paths = spec.get("paths", {})
    assert isinstance(paths, dict)
    for path, item in paths.items():
        assert isinstance(path, str) and isinstance(item, dict)
        for method, operation in item.items():
            if method.lower() in HTTP_METHODS and isinstance(operation, dict):
                result[(path, method.upper())] = operation
    return result

def effective_security(spec: dict[str, Any], operation: dict[str, Any]) -> list[dict[str, list[str]]]:
    value = operation["security"] if "security" in operation else spec.get("security", [])
    assert isinstance(value, list)
    return value

def normalize_requirement(requirement: dict[str, list[str]]) -> Requirement:
    return tuple(sorted((scheme, tuple(sorted(set(values)))) for scheme, values in requirement.items()))

def normalize_security(requirements: list[dict[str, list[str]]]) -> tuple[Requirement, ...]:
    return tuple(sorted({normalize_requirement(requirement) for requirement in requirements}))

def secured(requirements: list[dict[str, list[str]]]) -> bool:
    return bool(requirements) and all(bool(requirement) for requirement in requirements)

def _requirement_map(requirement: Requirement) -> dict[str, set[str]]:
    return {scheme: set(values) for scheme, values in requirement}

def requirement_weaker_or_equal(candidate: Requirement, baseline: Requirement) -> bool:
    """Return whether candidate requires no more credentials/scopes than baseline."""
    if not candidate:
        return True
    candidate_map = _requirement_map(candidate)
    baseline_map = _requirement_map(baseline)
    if not set(candidate_map).issubset(baseline_map):
        return False
    return all(candidate_map[name].issubset(baseline_map[name]) for name in candidate_map)

def _strictly_weaker(candidate: Requirement, baseline: Requirement) -> bool:
    return candidate != baseline and requirement_weaker_or_equal(candidate, baseline)

def make_regression(rule: str, severity: str, score: int, confidence: str, method: str, path: str,
                    message: str, rationale: str, before: Any, after: Any) -> Regression:
    identity = json.dumps([rule, method, path, before, after], sort_keys=True, default=list)
    return Regression(rule, severity, score, confidence, method, path, message, rationale, before, after,
                      hashlib.sha256(identity.encode()).hexdigest()[:16])

def _compare_policy(findings: list[Regression], method: str, path: str,
                    old_sec: list[dict[str, list[str]]], new_sec: list[dict[str, list[str]]]) -> None:
    if secured(old_sec) and not secured(new_sec):
        findings.append(make_regression("AZD001", "critical", 100, "definite", method, path,
            "Operation changed from authenticated to anonymous",
            "The previous policy required credentials, while the candidate policy permits anonymous access.",
            old_sec, new_sec))
        return
    if not secured(old_sec) or not secured(new_sec):
        return
    old_normalized = normalize_security(old_sec)
    new_normalized = normalize_security(new_sec)
    old_set, new_set = set(old_normalized), set(new_normalized)
    for candidate in sorted(new_set - old_set):
        weaker_than = [baseline for baseline in old_normalized if _strictly_weaker(candidate, baseline)]
        if not weaker_than:
            continue
        baseline = min(weaker_than, key=lambda item: (len(item), item))
        baseline_map = _requirement_map(baseline)
        candidate_map = _requirement_map(candidate)
        old_preserved = baseline in new_set
        removed_schemes = sorted(set(baseline_map) - set(candidate_map))
        removed_scopes = {
            scheme: sorted(baseline_map[scheme] - candidate_map.get(scheme, set()))
            for scheme in sorted(set(baseline_map) & set(candidate_map))
            if baseline_map[scheme] - candidate_map.get(scheme, set())
        }
        if old_preserved:
            findings.append(make_regression("AZD006", "high", 85, "definite", method, path,
                "A weaker OR security alternative was added",
                "OpenAPI security array entries are alternatives (OR). Adding an easier alternative broadens access even when the old requirement remains.",
                baseline, candidate))
        elif removed_schemes:
            findings.append(make_regression("AZD003", "high", 80, "definite", method, path,
                f"Required security schemes removed: {', '.join(removed_schemes)}",
                "Schemes inside one Security Requirement are combined with AND; removing one makes that alternative easier to satisfy.",
                baseline, candidate))
        elif removed_scopes:
            detail = "; ".join(f"{scheme}: {', '.join(values)}" for scheme, values in removed_scopes.items())
            findings.append(make_regression("AZD002", "high", 80, "definite", method, path,
                f"Required scopes removed: {detail}",
                "Removing required scopes from the same authentication alternative makes the declared authorization policy less restrictive.",
                baseline, candidate))

def compare(before: dict[str, Any], after: dict[str, Any]) -> list[Regression]:
    validate_spec(before)
    validate_spec(after)
    findings: list[Regression] = []
    old_ops, new_ops = operations(before), operations(after)
    for key in sorted(old_ops.keys() & new_ops.keys()):
        path, method = key
        _compare_policy(findings, method, path, effective_security(before, old_ops[key]),
                        effective_security(after, new_ops[key]))
    for key in sorted(new_ops.keys() - old_ops.keys()):
        path, method = key
        security = effective_security(after, new_ops[key])
        if not secured(security):
            sensitive = any(hint in path.lower() for hint in SENSITIVE_HINTS)
            findings.append(make_regression("AZD004", "high" if sensitive else "medium",
                75 if sensitive else 55, "definite", method, path, "New operation is anonymous",
                "The new operation has no effective authentication requirement. Path sensitivity only influences severity, not detection.",
                None, security))
    old_schemes = _security_schemes(before)
    new_schemes = _security_schemes(after)
    for scheme in sorted(set(old_schemes) - set(new_schemes)):
        findings.append(make_regression("AZD005", "high", 90, "definite", "*", "components.securitySchemes",
            f"Security scheme definition removed: {scheme}",
            "Operations may still reference this scheme indirectly or downstream tooling may stop enforcing the intended contract.",
            old_schemes[scheme], None))
    for scheme in sorted(set(old_schemes) & set(new_schemes)):
        old_type = old_schemes[scheme].get("type")
        new_type = new_schemes[scheme].get("type")
        if old_type != new_type:
            findings.append(make_regression("AZD007", "medium", 60, "review", "*", "components.securitySchemes",
                f"Security scheme type changed for {scheme}: {old_type} -> {new_type}",
                "Changing authentication mechanism type can alter enforcement semantics and deserves explicit review, but direction of weakness is not inferred.",
                old_schemes[scheme], new_schemes[scheme]))
    unique = {finding.fingerprint: finding for finding in findings}
    return sorted(unique.values(), key=lambda finding: (-finding.score, finding.path, finding.method, finding.rule_id))

def markdown(findings: list[Regression]) -> str:
    lines = ["# AuthZDiff", "", f"**Authorization regressions:** {len(findings)}", "",
             "| Score | Rule | Severity | Confidence | Operation | Change |",
             "| ---: | --- | --- | --- | --- | --- |"]
    for item in findings:
        message = item.message.replace("|", "\\|")
        lines.append(f"| {item.score} | {item.rule_id} | {item.severity} | {item.confidence} | `{item.method} {item.path}` | {message} |")
    lines += ["", "> Contract regression signals require review against implementation and intended policy.", ""]
    return "\n".join(lines)

def sarif(findings: list[Regression], after_path: str) -> dict[str, Any]:
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "AuthZDiff", "informationUri": "https://github.com/MEZ111/authz-diff",
            "rules": [{"id": key, "shortDescription": {"text": value}} for key, value in RULES.items()]}},
        "results": [{"ruleId": item.rule_id,
                     "level": "error" if LEVEL[item.severity] >= LEVEL["high"] else "warning",
                     "message": {"text": f"{item.method} {item.path}: {item.message}. {item.rationale}"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": after_path}},
                                    "logicalLocations": [{"fullyQualifiedName": f"{item.method} {item.path}"}]}],
                     "partialFingerprints": {"authzDiffFingerprint/v1": item.fingerprint},
                     "properties": asdict(item)} for item in findings]}]}

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--fail-level", choices=tuple(LEVEL), default="high")
    args = parser.parse_args()
    try:
        findings = compare(load_spec(args.before), load_spec(args.after))
        if args.format == "sarif":
            payload: Any = sarif(findings, str(args.after))
            output = json.dumps(payload, indent=2)
        elif args.format == "json":
            output = json.dumps({"regressions": [asdict(finding) for finding in findings]}, indent=2)
        else:
            output = markdown(findings)
        args.output.write_text(output, encoding="utf-8") if args.output else print(output)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"authz-diff: error: {exc}", file=sys.stderr)
        return 2
    threshold = LEVEL[args.fail_level]
    return 1 if any(LEVEL[item.severity] >= threshold for item in findings) else 0

if __name__ == "__main__":
    raise SystemExit(main())
