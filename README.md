# AuthZDiff

Semantic authorization regression detection for OpenAPI. AuthZDiff compares two
API contracts and fails a release when authentication, security schemes, or
required OAuth scopes become weaker.

## Why this exists

Text diffs show that an OpenAPI file changed. They do not explain that a billing
route became anonymous or that an `admin` scope disappeared. AuthZDiff resolves
effective operation security, including inherited global requirements, then
reports the security meaning of the change.

## Detectors

| Rule | Regression | Default severity |
| --- | --- | --- |
| AZD001 | authenticated operation becomes anonymous | critical |
| AZD002 | required OAuth scopes are removed | high |
| AZD003 | a security requirement is removed | high |
| AZD004 | a new operation is anonymous | medium/high by path sensitivity |
| AZD005 | a security-scheme definition is removed | high |

## Install and run

```bash
git clone https://github.com/MEZ111/authz-diff.git
cd authz-diff
python3 -m pip install .
authz-diff examples/before.json examples/after.json --format markdown
```

Use it as a release gate or emit SARIF:

```bash
authz-diff base.yaml candidate.yaml --fail-level high
authz-diff base.json candidate.json --format sarif -o authz.sarif
```

## Design boundaries

AuthZDiff interprets OpenAPI security declarations. It cannot prove that an
implementation enforces the contract, and intentional public endpoints still
need policy review. YAML support uses `PyYAML`; JSON analysis is otherwise
straightforward and deterministic.

## Verification

```bash
PYTHONPATH=src python3 -m unittest -v tests/test_authz_diff.py
```

Tests cover authentication removal, OAuth scope weakening, new sensitive public
routes, and unchanged policies.

## License

MIT
