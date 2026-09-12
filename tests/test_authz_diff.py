import json
import tempfile
import unittest
from pathlib import Path

from authz_diff import (
    compare,
    load_spec,
    normalize_requirement,
    requirement_weaker_or_equal,
    sarif,
    validate_spec,
)


def spec(paths, security=None, schemes=None, version="3.0.3"):
    value = {
        "openapi": version,
        "paths": paths,
        "components": {
            "securitySchemes": schemes
            or {
                "oauth": {"type": "oauth2"},
                "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            }
        },
    }
    if security is not None:
        value["security"] = security
    return value


class AuthZDiffTests(unittest.TestCase):
    def test_detects_authentication_removal(self):
        before = spec({"/accounts": {"get": {}}}, [{"oauth": ["read"]}])
        after = spec({"/accounts": {"get": {"security": []}}}, [{"oauth": ["read"]}])
        finding = compare(before, after)[0]
        self.assertEqual(finding.rule_id, "AZD001")
        self.assertEqual(finding.severity, "critical")

    def test_empty_requirement_is_anonymous(self):
        before = spec({"/accounts": {"get": {"security": [{"oauth": ["read"]}]}}})
        after = spec({"/accounts": {"get": {"security": [{"oauth": ["read"]}, {}]}}})
        self.assertEqual(compare(before, after)[0].rule_id, "AZD001")

    def test_detects_scope_weakening(self):
        before = spec({"/billing": {"post": {"security": [{"oauth": ["write", "admin"]}]}}})
        after = spec({"/billing": {"post": {"security": [{"oauth": ["write"]}]}}})
        finding = compare(before, after)[0]
        self.assertEqual(finding.rule_id, "AZD002")
        self.assertIn("admin", finding.message)

    def test_detects_removed_and_scheme(self):
        before = spec({"/billing": {"post": {"security": [{"oauth": ["write"], "apiKey": []}]}}})
        after = spec({"/billing": {"post": {"security": [{"oauth": ["write"]}]}}})
        self.assertEqual(compare(before, after)[0].rule_id, "AZD003")

    def test_detects_weaker_or_alternative_added(self):
        strong = {"oauth": ["read", "admin"]}
        weak = {"oauth": ["read"]}
        before = spec({"/admin": {"get": {"security": [strong]}}})
        after = spec({"/admin": {"get": {"security": [strong, weak]}}})
        self.assertEqual(compare(before, after)[0].rule_id, "AZD006")

    def test_removing_weaker_or_alternative_is_not_regression(self):
        weak = {"oauth": ["read"]}
        strong = {"oauth": ["read", "admin"]}
        before = spec({"/admin": {"get": {"security": [weak, strong]}}})
        after = spec({"/admin": {"get": {"security": [strong]}}})
        self.assertEqual(compare(before, after), [])

    def test_different_scope_names_are_not_assumed_hierarchical(self):
        before = spec({"/admin": {"get": {"security": [{"oauth": ["admin"]}]}}})
        after = spec({"/admin": {"get": {"security": [{"oauth": ["read"]}]}}})
        self.assertEqual(compare(before, after), [])

    def test_requirement_comparison_respects_and_semantics(self):
        baseline = normalize_requirement({"oauth": ["read", "admin"], "apiKey": []})
        candidate = normalize_requirement({"oauth": ["read"]})
        self.assertTrue(requirement_weaker_or_equal(candidate, baseline))
        self.assertFalse(requirement_weaker_or_equal(baseline, candidate))

    def test_prioritizes_new_sensitive_anonymous_route(self):
        before = spec({})
        after = spec({"/admin/export": {"get": {"security": []}}})
        finding = compare(before, after)[0]
        self.assertEqual(finding.rule_id, "AZD004")
        self.assertEqual(finding.severity, "high")

    def test_new_public_non_sensitive_route_is_medium(self):
        finding = compare(spec({}), spec({"/health": {"get": {"security": []}}}))[0]
        self.assertEqual(finding.severity, "medium")

    def test_global_security_inheritance(self):
        before = spec({"/reports": {"get": {}}}, [{"oauth": ["read", "admin"]}])
        after = spec({"/reports": {"get": {}}}, [{"oauth": ["read"]}])
        self.assertEqual(compare(before, after)[0].rule_id, "AZD002")

    def test_operation_override_beats_global_security(self):
        document = spec({"/status": {"get": {"security": []}}}, [{"oauth": ["read"]}])
        self.assertEqual(compare(document, document), [])

    def test_ignores_unchanged_security(self):
        document = spec({"/status": {"get": {"security": [{"oauth": ["read"]}]}}})
        self.assertEqual(compare(document, document), [])

    def test_security_alternative_order_is_irrelevant(self):
        left = {"oauth": ["read"]}
        right = {"apiKey": []}
        before = spec({"/x": {"get": {"security": [left, right]}}})
        after = spec({"/x": {"get": {"security": [right, left]}}})
        self.assertEqual(compare(before, after), [])

    def test_detects_removed_security_scheme_definition(self):
        before = spec({}, schemes={"oauth": {"type": "oauth2"}, "legacy": {"type": "http"}})
        after = spec({}, schemes={"oauth": {"type": "oauth2"}})
        self.assertEqual(compare(before, after)[0].rule_id, "AZD005")

    def test_detects_security_scheme_type_change_as_review(self):
        before = spec({}, schemes={"oauth": {"type": "oauth2"}})
        after = spec({}, schemes={"oauth": {"type": "http"}})
        finding = compare(before, after)[0]
        self.assertEqual(finding.rule_id, "AZD007")
        self.assertEqual(finding.confidence, "review")

    def test_rejects_undefined_security_scheme(self):
        broken = spec({"/x": {"get": {"security": [{"missing": []}]}}})
        with self.assertRaisesRegex(ValueError, "undefined security scheme"):
            validate_spec(broken)

    def test_rejects_non_array_scopes(self):
        broken = spec({"/x": {"get": {"security": [{"oauth": "read"}]}}})
        with self.assertRaisesRegex(ValueError, "array of strings"):
            validate_spec(broken)

    def test_accepts_openapi_31(self):
        validate_spec(spec({}, version="3.1.1"))

    def test_rejects_openapi_2(self):
        with self.assertRaisesRegex(ValueError, "OpenAPI 3.x"):
            validate_spec(spec({}, version="2.0"))

    def test_loads_yaml(self):
        content = """openapi: 3.0.3
paths: {}
components:
  securitySchemes:
    oauth:
      type: oauth2
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "api.yaml"
            path.write_text(content, encoding="utf-8")
            self.assertEqual(load_spec(path)["openapi"], "3.0.3")

    def test_sarif_has_stable_fingerprint_and_logical_location(self):
        before = spec({"/admin": {"get": {"security": [{"oauth": ["read"]}]}}})
        after = spec({"/admin": {"get": {"security": []}}})
        result = sarif(compare(before, after), "after.json")["runs"][0]["results"][0]
        self.assertIn("authzDiffFingerprint/v1", result["partialFingerprints"])
        self.assertEqual(result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"], "GET /admin")

    def test_json_serialization_keeps_explainability_fields(self):
        before = spec({"/admin": {"get": {"security": [{"oauth": ["read"]}]}}})
        after = spec({"/admin": {"get": {"security": []}}})
        encoded = json.dumps(compare(before, after)[0].__dict__)
        self.assertIn("rationale", encoded)
        self.assertIn("confidence", encoded)


if __name__ == "__main__":
    unittest.main()
