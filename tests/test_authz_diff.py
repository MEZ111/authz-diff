import unittest

from authz_diff import compare


def spec(paths, security=None, schemes=None):
    value = {"openapi": "3.0.3", "paths": paths,
             "components": {"securitySchemes": schemes or {"oauth": {"type": "oauth2"}}}}
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

    def test_detects_scope_weakening(self):
        before = spec({"/billing": {"post": {"security": [{"oauth": ["write", "admin"]}]}}})
        after = spec({"/billing": {"post": {"security": [{"oauth": ["write"]}]}}})
        self.assertEqual(compare(before, after)[0].rule_id, "AZD002")

    def test_prioritizes_new_sensitive_anonymous_route(self):
        before = spec({})
        after = spec({"/admin/export": {"get": {"security": []}}})
        finding = compare(before, after)[0]
        self.assertEqual(finding.rule_id, "AZD004")
        self.assertEqual(finding.severity, "high")

    def test_ignores_unchanged_security(self):
        document = spec({"/status": {"get": {"security": [{"oauth": ["read"]}]}}})
        self.assertEqual(compare(document, document), [])


if __name__ == "__main__":
    unittest.main()
