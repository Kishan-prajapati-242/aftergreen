# contracts

Offline contracts for evidence bundles and comparison results. Nothing here touches the network, GitHub, a model or a hosted service.

| Path | Contents |
| --- | --- |
| `bundle-v0.md` | Bundle contract v0: simulated evidence. Normative rules for limits, strict JSON, objects, line mapping, digest, error codes and pointers |
| `bundle-v1.md` | Bundle contract v1: one failed job collected from a public repository. It shares v0's profile and adds collection, redaction and download claims |
| `comparison-v0.md` | Comparison result contract v0, computed from a v0 bundle. v1 bundles are refused by name |
| `cases/`, `cases-v1/` | Test bundles and a `manifest.json` per version, which states every case's expected result |
| `go/` | Go module `aftergreen/contracts`: package `bundle` (`Validate`, `ValidateV1`, `DigestV1`) and the `aftergreen-validate` command. Standard library only |
| `ts/` | TypeScript validators (`bundle.ts`, `bundle-v1.ts`) and `validate.ts`, for the built-in type stripping of Node 22.18 or later. No npm dependencies |

## Run the tests

From the repository root:

```sh
(cd contracts/go && GOTOOLCHAIN=local go test ./...)
node --test contracts/ts/bundle.test.ts contracts/ts/bundle-v1.test.ts contracts/ts/validate.test.ts
```

`GOTOOLCHAIN=local` stops Go from downloading a different toolchain; `go.mod` requires Go 1.27.3. For each version, both suites read the same manifest. For each case they must produce:

- the expected result: accept or reject;
- on rejection, the expected error code and JSON Pointer;
- on acceptance, the expected digest.

Both suites also fail if any error code has no case. A further check gives every accepted v1 case to the v0 validator, and every accepted v0 case to the v1 validator, and expects each to be rejected.

Check one file from the command line. Both commands print the same single JSON line, with no content from the file except a printable-ASCII pointer. The syntax is:

```text
aftergreen-validate -schema v0|v1 FILE
node contracts/ts/validate.ts -schema v0|v1 FILE
```

For example, from the repository root:

```sh
(cd contracts/go && GOTOOLCHAIN=local go run ./cmd/aftergreen-validate -schema v1 ../cases-v1/valid-producer-fixture.json)
node contracts/ts/validate.ts -schema v1 contracts/cases-v1/valid-producer-fixture.json
```

## Case manifest

Each case has an `id`, an optional `note`, an `input` and an `expect`.

An `input` takes one of these forms:

- `file`: a case file, used unchanged.
- `base`: a case file, then optional edits:
  - `replace`: a list of `{find, with | with_hex | with_repeat}`. Every `find` must occur exactly once, and edits are applied in order.
  - `pad_to_bytes`: appends ASCII spaces until the input reaches that size.
- `raw` or `raw_hex`: literal input text, or bytes given as hex.

Large inputs, such as the 128 KiB boundary cases, are generated during the test instead of being stored.

`expect` is one of:

- `{"result": "accept", "evidence_sha256": ...}`
- `{"result": "reject", "code": ..., "pointer": ...}`. An absent `pointer` means the empty string.

The v0 manifest's `canonical_vectors` checks the digest encoding (bundle-v0.md section 7) against byte strings written out in the manifest, whose digests were checked with `shasum -a 256`.

## About the case data

None of the case bundles was collected from GitHub.

- **v0 bundles** are simulations of a stale-lockfile `npm ci` failure, written for these tests.
  - The repository, workflow, run, job and commit IDs are invented. Do not look them up.
  - Omitted ranges stand for lines that were never written; they exist to exercise the format.
  - The package names are fictional (`@simulated/...`), and the lockfile is simplified.
- **v1 bundles:**
  - `valid-collected-job-log.json` is synthetic data written for these tests. It is in the `collected_public` shape only to exercise that evidence class. Its `case_id` is `synthetic-collected-shape`, and `example-org/example-repo` and every ID in it are invented.
  - `valid-simulated-log-missing.json` is written for these tests and labelled `simulated`.
  - `valid-producer-fixture.json` is the output of the Go producer (`collector/logbundle`) for the invented fixture log and mocked API responses in `collector/github/bundle_test.go`.
    - It is labelled `simulated`, and that test fails if the producer's output changes.
    - Its `authentication` is `gh_cli` because the test puts a stand-in credential source in place of the GitHub CLI. No real login was used.
- **Identifiers** such as `case_id`, the repository name and the package name are neutral on purpose: an identifier must not give away the diagnosis.
