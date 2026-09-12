import unittest

from authz_diff import compare


SCHEMES = {
    "oauth": {"type": "oauth2"},
    "apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
}


def document(paths=None, security=None, schemes=None):
    value = {
        "openapi": "3.0.3",
        "paths": paths or {},
        "components": {"securitySchemes": schemes if schemes is not None else SCHEMES},
    }
    if security is not None:
        value["security"] = security
    return value


def operation(security):
    return {"/resource": {"get": {"security": security}}}


def rules(before, after):
    return sorted(finding.rule_id for finding in compare(before, after))


class AuthorizationCorpusTests(unittest.TestCase):
    def test_twenty_known_policy_transitions(self):
        oauth_read = [{"oauth": ["read"]}]
        oauth_admin = [{"oauth": ["read", "admin"]}]
        oauth_write = [{"oauth": ["write"]}]
        api_key = [{"apiKey": []}]
        cases = [
            ("authentication removed", document(operation(oauth_read)), document(operation([])), ["AZD001"]),
            ("anonymous alternative added", document(operation(oauth_read)), document(operation([{"oauth": ["read"]}, {}])), ["AZD001"]),
            ("scope removed", document(operation(oauth_admin)), document(operation(oauth_read)), ["AZD002"]),
            ("and scheme removed", document(operation([{"oauth": ["read"], "apiKey": []}])), document(operation(oauth_read)), ["AZD003"]),
            ("weaker or added", document(operation(oauth_admin)), document(operation([{"oauth": ["read", "admin"]}, {"oauth": ["read"]}])), ["AZD006"]),
            ("weaker or removed", document(operation([{"oauth": ["read"]}, {"oauth": ["read", "admin"]}])), document(operation(oauth_admin)), []),
            ("scope added", document(operation(oauth_read)), document(operation(oauth_admin)), []),
            ("and scheme added", document(operation(oauth_read)), document(operation([{"oauth": ["read"], "apiKey": []}])), []),
            ("alternative order only", document(operation([{"oauth": ["read"]}, {"apiKey": []}])), document(operation([{"apiKey": []}, {"oauth": ["read"]}])), []),
            ("opaque scope replacement", document(operation([{"oauth": ["admin"]}])), document(operation([{"oauth": ["read"]}])), []),
            ("unchanged write policy", document(operation(oauth_write)), document(operation(oauth_write)), []),
            ("oauth replaced by api key", document(operation(oauth_read)), document(operation(api_key)), []),
            ("new public sensitive operation", document(), document({"/admin/export": {"get": {"security": []}}}), ["AZD004"]),
            ("new public ordinary operation", document(), document({"/health": {"get": {"security": []}}}), ["AZD004"]),
            ("new secured operation", document(), document({"/private": {"get": {"security": oauth_read}}}), []),
            ("global scope weakened", document({"/resource": {"get": {}}}, oauth_admin), document({"/resource": {"get": {}}}, oauth_read), ["AZD002"]),
            ("public override survives global change", document({"/resource": {"get": {"security": []}}}, oauth_read), document({"/resource": {"get": {"security": []}}}, oauth_admin), []),
            ("scheme definition removed", document(schemes={"oauth": {"type": "oauth2"}, "legacy": {"type": "http"}}), document(schemes={"oauth": {"type": "oauth2"}}), ["AZD005"]),
            ("scheme type changed", document(schemes={"oauth": {"type": "oauth2"}}), document(schemes={"oauth": {"type": "http"}}), ["AZD007"]),
            ("two simultaneous regressions", document({"/a": {"get": {"security": oauth_admin}}, "/b": {"post": {"security": oauth_write}}}), document({"/a": {"get": {"security": oauth_read}}, "/b": {"post": {"security": []}}}), ["AZD001", "AZD002"]),
        ]
        self.assertEqual(len(cases), 20)
        for name, before, after, expected in cases:
            with self.subTest(name=name):
                self.assertEqual(rules(before, after), sorted(expected))


if __name__ == "__main__":
    unittest.main()
