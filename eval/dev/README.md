# Development cases (simulated)

Twelve simulated cases, written for development. None is a real GitHub run: repository, run, job and commit identifiers, package names and log lines are all invented.

| Folder | Contents | Who may read it |
| --- | --- | --- |
| `bundles/` | v0 input bundles (contracts/bundle-v0.md). Identifiers are neutral and do not name the diagnosis | the product and tests |
| `sidecars/` | expected comparison results: decision, reason rows, observations with citations, and limitations. Written from contracts/comparison-v0.md along with the cases; not reviewed independently | evaluators and tests only |

A sidecar must never enter the product, a model's context or retrieval. Its `evaluator_only` member makes the bundle validator reject it as input (`evaluator_field`). The labels and scenario notes are in the sidecars, so the input bundles stay label-free.

These cases are for development and are public, so they cannot serve as a held-out evaluation set.

Run the checks, or print one comparison result, from the repository root. `GOTOOLCHAIN=local` stops Go from downloading a different toolchain:

```sh
(cd collector && GOTOOLCHAIN=local go test ./...)
(cd collector && GOTOOLCHAIN=local go run ./cmd/aftergreen-compare ../eval/dev/bundles/dev-01.json)
```
