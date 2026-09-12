# Validation corpus

AuthZDiff v0.2 includes an executable 20-case authorization-transition corpus in `tests/test_corpus.py`, in addition to focused unit tests.

The corpus covers authentication removal, explicit anonymous alternatives, OAuth scope removal, AND-scheme removal, weaker OR alternatives, strengthening changes that must not alert, new public operations, global inheritance, operation overrides, security-scheme removal/type change, opaque scope replacement, and simultaneous regressions.

The expected rule IDs are asserted on every CI run across Python 3.10–3.13. This corpus validates contract-diff semantics only; it is not a benchmark of runtime API enforcement or vulnerability-detection recall against live systems.

When a new detector is added, add at least one positive case and one non-regression/strengthening case so the corpus guards against both false negatives and obvious false positives.
