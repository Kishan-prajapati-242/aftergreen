# Aftergreen

Aftergreen is planned as an evidence workbench for failed GitHub Actions runs. Its question: what changed since the last comparable passing run, and which of those changes could explain the failure? A changed line is something to investigate, not proof of a cause.

## Status

Early. What exists today:

- **Evidence bundle contracts.**
  - [v0](contracts/bundle-v0.md) holds simulated data only.
  - [v1](contracts/bundle-v1.md) holds one failed job collected from a public repository.
  - Each has a Go validator and a dependency-free TypeScript validator. The two agree on every shared case.
- **A deterministic comparison** ([contract](contracts/comparison-v0.md)) of a failed run and an explicitly supplied baseline in a v0 bundle. It refuses v1 by name until v1 compatibility is designed.
- **A bounded, read-only collector** for one failed job of a public GitHub Actions push run ([details](docs/collector.md)). It writes a sanitized v1 bundle.
- **Twelve simulated development cases** ([eval/dev](eval/dev/README.md)) with expected comparison results.

Not built yet: selecting a baseline run, collecting workflow and dependency files, retrieval, model analysis, the web application and any hosted service.

## Requirements

- Go 1.27.3. The modules name it, and `GOTOOLCHAIN=local` stops Go from downloading another toolchain.
- Node 22.18 or later, for the TypeScript validator. It uses Node's built-in type stripping, on by default from 22.18, and has no npm dependencies.
- Optional: the GitHub CLI, logged in to github.com, for `-auth gh`.

## Usage

Run the commands below from the repository root. Each `sh` block can be pasted as it is.

Collecting a run reaches GitHub, so it is shown as syntax. `RUN_URL` is `https://github.com/OWNER/REPO/actions/runs/RUN_ID`, optionally followed by `/attempts/N`. `FILE` must be a path that does not exist yet, in a directory that does. Use an absolute path outside the repository, because the command runs inside `collector/`:

```text
(cd collector && GOTOOLCHAIN=local go run ./cmd/aftergreen-collect [-auth none|gh] [-job JOB_ID] -out FILE RUN_URL)
(cd collector && GOTOOLCHAIN=local go run ./cmd/aftergreen-probe [-auth none|gh] [-job JOB_ID] RUN_URL)
```

- **`-auth`:** without `-auth gh`, everything is unauthenticated. With it, the GitHub CLI's login is sent only on the job-log request. In the one repository tried, the job-log endpoint answered 403 without a credential.
- **`-job JOB_ID`:** needed when several jobs failed.
- **Report only:** `aftergreen-probe` prints metadata and writes no bundle.

Check a bundle with both validators. This example checks the producer fixture stored in the repository; for your own bundle, give its absolute path instead:

```sh
(cd contracts/go && GOTOOLCHAIN=local go run ./cmd/aftergreen-validate -schema v1 ../cases-v1/valid-producer-fixture.json)
node contracts/ts/validate.ts -schema v1 contracts/cases-v1/valid-producer-fixture.json
```

Compare a simulated v0 bundle:

```sh
(cd collector && GOTOOLCHAIN=local go run ./cmd/aftergreen-compare ../eval/dev/bundles/dev-01.json)
```

## Tests

```sh
(cd collector && GOTOOLCHAIN=local go test ./...)
(cd contracts/go && GOTOOLCHAIN=local go test ./...)
node --test contracts/ts/bundle.test.ts contracts/ts/bundle-v1.test.ts contracts/ts/validate.test.ts
```

The tests are offline. Collector tests use local mock servers and invented fixtures.

## Limitations

- **Redaction is rule-based.** It cannot guarantee that a bundle holds no secret. It finds known shapes and withholds lines conservatively:
  - GitHub, npm and Slack tokens, AWS access key IDs and JWTs;
  - private keys and `Authorization` values;
  - URL query strings, where signed URLs carry their signatures;
  - credentials in URLs, values assigned to names such as `password` or `token`, and e-mail addresses.

  It misses secrets with no recognizable shape.
- **Line selection is keyword-based** and may miss the lines that explain a failure. Logs over 2 MiB are cut.
- **Checkout is not established.** The run's head commit is recorded as run metadata, never as what the job checked out. Matrix values and runner details stay unresolved.
- **Producer claims.** A bundle's statements are the producer's claims. Nothing in a bundle proves that it came from GitHub.
- **Live use so far:** one failed job in one public repository, three times. Other repositories have not been tried.
  - 2026-11-08: `aftergreen-probe` without a credential. The job-log endpoint answered 403.
  - 2026-11-10: `aftergreen-probe -auth gh`, with an earlier version that sent the login on every API request, not only the job-log request. The log was downloaded, counted and discarded.
  - 2026-11-11 UTC: `aftergreen-collect -auth gh`. It wrote a bundle that both validators accept. Whether the selected lines show why the job failed was not checked.

See [docs/collector.md](docs/collector.md) for the network policy, the credential boundary and the redaction rules.

## Layout

| Path | Contents |
| --- | --- |
| `contracts/` | Bundle contracts v0 and v1, comparison contract v0, shared test cases, Go and TypeScript validators ([README](contracts/README.md)) |
| `collector/github` | GitHub client: probe, and collection into a bundle |
| `collector/logbundle` | Log numbering, cleaning, redaction and selection into bundle v1 |
| `collector/compare` | Comparison of v0 bundles |
| `collector/cmd/` | `aftergreen-probe`, `aftergreen-collect`, `aftergreen-compare` |
| `eval/dev/` | Simulated development cases and their expected results |
