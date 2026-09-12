# Security comparison model

AuthZDiff is intentionally conservative and structural.

## What counts as weaker

For one Security Requirement, candidate `C` is structurally weaker than baseline `B` when:

1. every scheme required by `C` is also required by `B`; and
2. for each retained scheme, every scope required by `C` was required by `B`.

Therefore removing an AND scheme or removing a required scope is weaker. Adding a new weaker requirement to the `security` array is also weaker because array elements are OR alternatives.

## What is not inferred

AuthZDiff does not infer that one opaque scope label is stronger than another. Replacing `admin` with `read` is therefore reported only if another structural signal exists; teams that need scope hierarchies should add a policy layer rather than relying on naming conventions.

## Confidence

`definite` means the contract structure itself demonstrates broader access. `review` means the contract changed in a security-relevant way but the tool cannot determine direction without external policy context.

## False positives and false negatives

Intentional public endpoints can produce findings. Conversely, implementation-only authorization bugs, undocumented routes, runtime policy engines, remote `$ref` content, and semantic scope hierarchies can escape contract-only analysis.
