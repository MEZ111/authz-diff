# AuthZDiff

Semantic authorization-regression detection for OpenAPI 3.x. AuthZDiff compares two API contracts and reports when the candidate contract becomes easier to satisfy: authentication disappears, required schemes/scopes are removed, or a weaker OR alternative is introduced.

## Why this exists

Text diffs show that an OpenAPI file changed. They do not explain that a billing route became anonymous, that `admin` stopped being required, or that a second easier authentication alternative now bypasses the original one. AuthZDiff resolves global and operation-level security and compares the **security meaning** of the change.

## OpenAPI semantics handled

OpenAPI Security Requirements have two important rules:

- entries in the `security` array are **OR alternatives**;
- schemes inside one requirement object are combined with **AND**.

AuthZDiff preserves that structure instead of flattening alternatives. It treats scope names as opaque labels and never invents a hierarchy such as `admin > read` unless the weakening is structurally visible as removed required scopes.

## Detectors

| Rule | Regression | Severity |
| --- | --- | --- |
| AZD001 | authenticated operation becomes anonymous | critical |
| AZD002 | required scopes are removed from an alternative | high |
| AZD003 | a required AND security scheme is removed | high |
| AZD004 | a new operation is anonymous | medium/high by path sensitivity |
| AZD005 | a security-scheme definition is removed | high |
| AZD006 | a weaker OR security alternative is added | high |
| AZD007 | a security-scheme type changes | medium / review |

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

`high` is the default fail level.

## Exit-code contract

- `0`: analysis completed and no finding met the configured fail level;
- `1`: one or more findings met the fail level;
- `2`: invalid input, unreadable files, or another analysis error.

This makes CI failure meaning explicit instead of relying on tracebacks.

## Explainability and SARIF

Every finding includes the before/after policy fragment, a rationale, confidence, deterministic fingerprint, and operation identity. SARIF output includes a stable partial fingerprint and logical location so code-scanning systems can correlate a finding across runs even though OpenAPI source-line mapping is not yet implemented.

## Design boundaries

AuthZDiff interprets the **declared OpenAPI contract**. It cannot prove that an implementation enforces the contract. It does not infer semantic relationships between differently named OAuth scopes. Remote `$ref` resolution and implementation-side authorization testing are intentionally out of scope for v0.2.

New anonymous-route severity uses a path-name sensitivity heuristic; detection itself does not depend on that heuristic.

## Verification

```bash
python3 -m pip install ".[dev]"
ruff check src tests
mypy src
PYTHONPATH=src python3 -m unittest -v tests/test_authz_diff.py
python3 -m build
pip-audit
```

CI runs on Python 3.10, 3.11, 3.12, and 3.13 with pinned GitHub Action commits.

See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for comparison semantics and [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT
