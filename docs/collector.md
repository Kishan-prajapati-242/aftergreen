# Collector

`collector/` is a Go module, standard library only. It reads one failed job of one public GitHub Actions push run and either reports what it found (`aftergreen-probe`) or writes an evidence bundle v1 ([contract](../contracts/bundle-v1.md)) of that job (`aftergreen-collect`). Requests are read-only `GET`s.

## Commands

Syntax, as run from `collector/` (add `GOTOOLCHAIN=local` before `go`, as in the README, so that Go does not download another toolchain). Square brackets mark optional flags, and `|` separates the choices:

```text
go run ./cmd/aftergreen-probe   [-auth none|gh] [-job JOB_ID] https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]
go run ./cmd/aftergreen-collect [-auth none|gh] [-job JOB_ID] -out FILE https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]
go run ./cmd/aftergreen-audit   [-auth none|gh] [-job JOB_ID] [-saved BUNDLE] https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]
```

- **`aftergreen-probe`** prints a JSON report of run, attempt, job and log metadata. It downloads the log, counts and hashes it, and discards it.
- **`aftergreen-collect`** builds a bundle from the log, held in memory, and writes the bundle to `FILE`.
  - `FILE` must not exist, and its directory must. It is created with mode 0600.
  - Stdout gets a JSON summary: counts, digests and the collection report. It never holds log text, a signed URL or a credential.
  - Exit status: 0 for a bundle with a complete job log; 3 for a bundle whose job log is missing or incomplete; 1 when nothing was written; 2 for invalid arguments, before any request.
  - Keep bundles outside version control. A bundle is sanitized, but see [Limitations](#limitations).
- **`aftergreen-audit`** makes the same collection, keeps the log in memory, writes nothing, and prints a [selection audit](#selection-audit).

Check a bundle with either validator. Both print the same single JSON line. These examples run from the repository root and check the producer fixture stored there. For your own bundle, give its absolute path instead:

```sh
(cd contracts/go && GOTOOLCHAIN=local go run ./cmd/aftergreen-validate -schema v1 ../cases-v1/valid-producer-fixture.json)
node contracts/ts/validate.ts -schema v1 contracts/cases-v1/valid-producer-fixture.json
```

## What a collection does

1. Validate the run reference (owner, repository, run, attempt, job). Invalid input makes no request and is not echoed.
2. Refuse to run if `GODEBUG` turns on Go's HTTP/2 debug logging, which would print request headers and URLs.
3. `GET /rate_limit`, then the run and the selected attempt. All of these requests are unauthenticated.
   - Both run responses must state `"private": false`. Otherwise the collection stops and reports none of that response's content.
   - The attempt must be a completed `push` attempt with conclusion `failure`.
4. List the attempt's jobs from the attempt-specific route: 100 per page, at most 3 pages. Select the single failed job, or the one named by `-job`.
5. **Only now, with `-auth gh`,** obtain the GitHub CLI's stored github.com login (see [Credential](#credential)).
6. `GET /repos/{owner}/{repo}/actions/jobs/{job_id}/logs`. This is the only request that may carry the credential.
7. Follow its 302 only if the destination passes the [host policy](#network-policy). The download is unauthenticated and is limited to 2 MiB.
8. `aftergreen-collect` only: build, validate and check the bundle ([From log to bundle](#from-log-to-bundle)), then write it.

The collection stops at the first error, limit or ambiguity, such as several failed jobs without `-job`. It never retries.

### Limits

| Limit | Value |
| --- | --- |
| Requests per collection, the download included | 30 |
| Time per request, body included | 15 s |
| Time for the whole collection | 90 s |
| One API response body | 1 MiB |
| Log download | 2 MiB |
| All response bodies together | 8 MiB |

- **Log over the limit:** only its first 2 MiB are read, and it is marked `prefix`.
- **End not verifiable:** an HTTP/1 body with neither Content-Length nor chunked encoding ends when the connection closes, so a cut connection would look complete. It is marked `partial`, never `complete`.
- **Rate limits:** before the run request, the collection stops (`rate_limit_low`) if fewer unauthenticated core requests remain than it could need: 6, or 5 with `-auth gh`. It stops at a reported rate limit, and once a response reports 0 requests remaining, no further API request is sent.

### Network policy

- **API requests** go only to `https://api.github.com`, on routes built from the validated reference. No URL the user supplies is fetched.
- **The redirect** is followed once, without Go's `http.Client` redirect handling. Its destination must be:
  - HTTPS on the default port, with no user information;
  - exactly `productionresultssa<N>.blob.core.windows.net`, with N in 0–19, 30–49 or 100–199.

  That list is a snapshot of GitHub's `GET /meta` from 2026-11-08. It is not widened to make a collection succeed. Wildcards such as `*.blob.core.windows.net` are not trusted.
- **Connections:** every connection must reach a public address on port 443, checked at connect time. Proxy settings are ignored, no cookies are sent, and keep-alive is off.
- **Never recorded:** the signed redirect URL. Only its host is.
- **Error details** are fixed text. GitHub's message is read in memory only to classify the response.

## Credential

`-auth gh` uses the github.com login that the GitHub CLI has stored.

- **How:** after step 4, the collector runs `gh auth token --hostname github.com` as a child process, never through a shell.
  - Stdin is empty, stdout is capped at 4 KiB, and stderr is discarded.
  - `GH_TOKEN`, `GITHUB_TOKEN`, `GH_ENTERPRISE_TOKEN` and `GITHUB_ENTERPRISE_TOKEN` are removed from gh's environment.
  - The collector never installs gh or starts a login. If no login is usable, it stops before the job-log request with `credential_unavailable`.
- **When:** only after the repository is shown to be public, the run, attempt and job identities match, and one failed job is selected. Invalid, private or mismatched input never runs gh.
- **Where:** only on the job-log `GET` to `api.github.com`. Before attaching the credential, the code checks the request's host, path and empty query. It is never sent on a metadata request or the log download.
- **Fail-closed checks:** in each case, the check looks for any 12-character piece of the token, in any letter case.
  - A redirect URL that contains a piece is not followed.
  - A report that would contain one is withheld.
  - A bundle that would contain one is discarded.
- **Not known to the collector:** the token's type and scopes. Only `GET` requests are sent, but a gh login may carry write scopes.

## From log to bundle

Package `collector/logbundle` turns the received bytes into the job-log source of a bundle. The raw log and the signed URL are never written, printed or put in an error.

1. **Number the lines first.** Split on LF. A CR directly before an LF is dropped, and a final LF starts no line. Every later step keeps the line's number.
2. **Clean each line.**
   - Malformed UTF-8 becomes U+FFFD, one per run of bad bytes.
   - A byte-order mark on line 1 is dropped.
   - ECMA-48 escape sequences are removed: CSI, OSC, DCS, SOS, PM, APC, and two-byte or intermediate ESC sequences, in 7-bit and C1 forms. An unterminated sequence runs to the end of its line.
   - Then every remaining control character except tab is removed.
3. **Redact with rule set `aftergreen.redaction.1`.** A replacement keeps the line and writes `[REDACTED:<rule>]` in place of the match.
   - **Inline rules, in order:**
     - `private-key`: a one-line `BEGIN … PRIVATE KEY` block;
     - `github-token`: `gh[pousr]_…` and `github_pat_…`;
     - `authorization`: the credential after `Authorization`, a separator (`:`, `=`, `=>` or `:=`) and a scheme, or after `Bearer `;
     - `url-userinfo`: `scheme://user:password@`;
     - `url-query`: the whole query string of an `http(s)` URL, where signed URLs carry their signatures;
     - `aws-key-id`, `slack-token`, `npm-token`, `jwt`;
     - `assignment`: the value after `:`, `=`, `=>` or `:=` following a name that contains password, passwd, pwd, secret, token, api key, access key, private key or client secret.
       - A value with no letter or digit, such as GitHub's `***` mask, is left alone.
       - When another such assignment starts inside the value and ends after it, as in `token: password: x`, the replacement runs on to its end;
     - `email`.
   - **Private-key blocks:** lines from a `BEGIN … PRIVATE KEY` marker with no END after it, through the next END line (or to the end of the log), are withheld whole as `redacted`.
   - **Other readings of a line:** removing a malformed escape sequence can also remove the start of `password=` or of a key marker, and a string logged with backslash escapes (`{\"password\":\"x\"}`) hides its quotes from the rules. Each line is therefore also read with the escape sequences' printable bytes kept, and with `\"` read as `"`.
     - Key markers are searched in the escape-kept reading as well.
     - If any reading differs from the cleaned text and matches any inline rule, the whole line is withheld as `redacted`.
4. **Select lines.**
   - **Candidates:**
     - failure lines: `##[error]`, and `Process completed with exit code` with a non-zero code;
     - other error signals: `npm ERR!`, `npm error`, `Error:`, `ERROR`, `FAIL`, `failed`, `AssertionError`, Python tracebacks, `panic:`, timeouts;
     - 3 lines of context around each;
     - the first 5 and last 20 lines.
   - **Order:** candidates are admitted in that order, later lines first within each group, up to 500 lines and the 128 KiB bundle limit.
   - **Never included:**
     - a line over 2,048 bytes after cleaning, which is then neither redacted nor scanned for signals, or over 2,048 bytes after redaction (`line_too_long` if selected);
     - a withheld line (`redacted`);
     - a candidate over budget (`line_limit`).
   - Every other line is `outside_selected_span`, unless a step span (below) includes it. Every line from 1 to `line_count` is either included or in an omitted range with its reason.
   - **Range limit:** a bundle may hold at most 501 omitted ranges, and every omitted line keeps its exact reason.
     - Many isolated failures, each with its context cut by the budget, can need more ranges than that.
     - In that case, blocks of included lines that lie between `line_limit` lines are left out, least important first. Their lines become `line_limit`, and each block left out merges two ranges into one. The summary's `dropped_to_fit_ranges` counts the lines.
     - The collector tries line budgets from 110,000 bytes down in steps of 1,024 while positive (ending at 432), then 0. It keeps the first selection that fits both the range limit and the 131,072-byte size limit.
     - If none fits, `aftergreen-collect` writes no bundle and reports the omitted-range limit (`logbundle.ErrRangeLimit`). That happens only when even a selection with no included line needs more than 501 ranges. For example, more than about 250 withheld private-key blocks, each followed by an ordinary line, or more than about 500 over-long lines among the selected lines. The budgets are at most 1,024 bytes apart, so a narrow fitting window between two of them can be missed.
     - Metadata that bundle v1 cannot hold, such as a job name over 256 bytes or an unknown log extent, is checked before any line is selected and reported as a metadata problem.
   - **Step spans:** the inspector cites a step header only when the header and every line through the observation are included. Once a selection fits, each included failure line, latest first, gets its step span if the whole span fits. The span runs from the nearest step header at or before the failure line (a line starting with `##[group]Run` and a space, after an optional timestamp) through the failure line.
     - Only failure lines get spans. Another error signal gets a step header cited only when the lines from its header happen to be included, for example inside a failure line's span.
     - A span is added whole or not at all. It is not added when no step header comes before the failure line, or when one of its lines is withheld or over 2,048 bytes. It is also not added when the lines it would add do not fit in the 500 lines or the line budget, or could take the bundle over 131,072 bytes. That size check is conservative: it does not count the bytes the span saves in omitted ranges. Nor is any span added when lines were left out to fit the range limit. The step then stays undetermined.
     - When not every span fits, later failure lines get theirs first, as elsewhere in the selection. An earlier failure line's step may then stay undetermined, although the earlier failure may be the one that matters.
     - Spans come after every other selected line. Every line a span adds was `outside_selected_span`. Adding a span adds no omitted range and changes no other line's reason. The lines of a span that is not added keep their reasons. So an `outside_selected_span` line may be one that more room would have included.
     - The nearest step header can be an inner step of a composite action, or a header-shaped line that any process printed. It says which such line comes last before the failure line, not which step printed it.
     - A header that a span adds is also an inspector observation. In a log with about 200 observations, it can push a later observation out of the 200 the inspector lists, which the inspection reports as `observations_truncated`.
5. **Fill in the bundle.**
   - **Copied, not inferred:** run, attempt and job metadata, as the API stated them.
   - **`head_sha`** is run metadata, not a checkout claim.
   - **Unresolved or unknown:** checkout and matrix are `unresolved` (`workflow_not_collected`), and runner `os` and `arch` are `unknown`. Runner `labels` are the labels the job requested, as the API listed them, not a description of the machine.
   - **Missing:** the workflow file, manifest and lockfile are `not_collected`.
   - **Collection details:** `received_bytes`, `received_sha256` and `extent` describe the download as the collector measured it. `authentication` says how the job-log API request was made; the download itself never carries a credential.
6. **Check, then write.** The bundle is checked with the v1 validator and for credential pieces, then written. If required metadata does not fit the contract, for example a workflow path outside `.github/workflows/` or a branch name the contract does not allow, no bundle is built and the reason is reported.

## Selection audit

`aftergreen-audit` counts what the line selection does with lines that match known failure patterns. It uses the fixed patterns of the [inspection contract](../contracts/inspection-v0.md) (section 3): GitHub Actions error annotations, npm, Go and pytest failure lines, Python tracebacks, Go panics, `…Error:` lines, timeouts, "N failed" counts, non-zero exit lines and step headers.

- **What it counts.** For each pattern:
  - `lines`: how many lines of the whole log held in memory match, on their cleaned text before redaction, so the total does not depend on the selection. A match that exists only after redaction (a placeholder next to the text that follows it) is not counted, although the inspector, which reads the bundle text, would report it;
  - `included`: how many of those the selection includes with the match still in the bundle text, which the inspector reads;
  - `hidden_by_inline_redaction`: how many are included, but inline redaction removed the match;
  - `omitted`: how many it omits, by omission reason.

  `lines` is the sum of the other three. There are two line-number lists, of included lines and of omitted lines with their reasons. Each holds the first 20 line numbers in line order. One flag, `lists_truncated`, says whether either list was cut.
- **What it does not print.** No log text, signed URL or credential, and no name or path from the run: only pattern names, counts, line numbers, hosts, statuses and hashes.
- **What the numbers mean.** Every pattern except step headers is also one of the current producer's selection signals (see the signals above). A step header is included only as a signal itself, as context of a signal, as one of the first 5 or last 20 lines, or at the start of a step span. A matching line of the other patterns is omitted only:
  - by the line, byte or range budget (`line_limit`);
  - by its length: `line_too_long`, or `outside_selected_span` for an over-long line that is not within 3 lines of another signal or among the first 5 or last 20 lines, because an over-long line is never a signal itself;
  - by redaction: `redacted`, or `outside_selected_span` when inline redaction removed the signal.

  The counts show what those cost, not how well the signals were chosen. They measure coverage of these known patterns only. They are not diagnosis accuracy, and not recall of all relevant evidence: a failure can be explained by lines no pattern matches. No percentage is given.
- **A saved bundle.** With `-saved`, the audit also covers that bundle's selection.
  - The saved bundle must be a bundle of the job collected: `RUN_URL` must end in its `/attempts/N`, `-job` must give its job, and the repository and run must match. That is checked before any request, and anything else exits with status 2.
  - The comparison is made only when the bytes just collected are the bytes the bundle was built from: its `received_bytes`, `received_sha256` and `line_count`.
  - The saved selection was made by the producer that wrote the bundle, whose signals may differ from the current producer's, so the signal statement above may not hold for it. Its `hidden_by_inline_redaction` counts included lines whose saved text no longer matches, whatever changed it. Its audit carries its own scope sentence saying so.
  - Otherwise `saved_bundle` has `compared: false` and a reason:
    - `collection_stopped`: no failed job was selected, or the report was withheld;
    - `log_not_obtained`: no log bytes were obtained, or, without the credential, the log was not requested;
    - `log_differs`: other bytes;
    - `saved_log_missing`: the saved bundle has no job log;
    - `saved_bundle_invalid`.
- **The requests.** They are the requests of one `aftergreen-collect` run, under the same limits and host policy, with the credential (with `-auth gh`) on the job-log request only.
- **Exit status:** 0 for an audit (and, with `-saved`, a comparison); 3 when a saved bundle was given but not compared; 1 when no audit was produced; 2 for invalid arguments, before any request. Under `go run`, an exit status other than 0 is reported as 1, with Go printing `exit status N`. Build the command to see its own exit status.

## Limitations

- **Redaction is rule-based.**
  - It finds what its rules match and nothing else. A secret with no recognizable shape or context, such as a bare password, a base64 blob or a split string, passes through. It does not stop a log written on purpose to evade it.
  - GitHub masks registered secrets as `***` before the log is stored. That covers only secrets registered with GitHub.
  - Treat a bundle as sanitized, not as secret-free.
- **Withholding is conservative.** A coloured line, or a line with `\"`, that matches any rule is dropped whole. The `url-query` and `email` rules also hit harmless URLs and addresses. The summary counts omitted lines by reason. A withheld line also keeps its step's span out.
- **Step spans include ordinary lines.** A span can add up to 475 lines that match no signal, including the failing step's printed script and its `env:` and `with:` values. Redaction treats them like any other line. So a bundle can now hold more values that the rules do not recognize, such as a webhook URL with the secret in its path, or a password passed as a command-line flag.
- **Selection is keyword-based.** The lines that explain a failure may not be selected. Step headers are not selection signals. A step header can be cited for a failure line only when its whole step span fits. A long step, a withheld or over-long line in the step, or a crowded log leaves the step undetermined. When a header is cited, it is only the nearest earlier header-shaped line, which does not prove that this step printed the line.
- **Cut logs.** A log over 2 MiB loses its end. In a `prefix` or `partial` log, the last line may be cut short.
- **Visibility is read once.** The repository is shown public by the unauthenticated run and attempt responses. The job-log request comes seconds later, and a change of visibility in between would not be noticed.
- **Narrow scope.** One failed job of one public push run. No baseline run is selected, and no workflow file, manifest or lockfile is fetched.
- **Producer claims.** A bundle states what the producer says it collected. Nothing in it proves that it came from GitHub.
- **Tested mostly offline.** Except as recorded in the [README](../README.md), the collector has been exercised only against local mock servers and invented fixtures.

## Tests

From the repository root:

```sh
(cd collector && GOTOOLCHAIN=local go test ./...)
```

All tests are offline. They use local TLS mock servers, a refusing test transport and a fake credential source. No test reaches GitHub or runs the real gh.

- `logbundle`:
  - newline, cleaning and redaction tables, using sentinels assembled at run time;
  - private-key blocks, long lines and byte and line limits;
  - a deterministic run of 1,500 random logs built from awkward fragments.
  - step spans: 28 synthetic logs with hand-derived selections and cited step headers, checked through the inspector and its verifier. Also comparisons with spans turned off (only `outside_selected_span` lines may become included), 200 random logs, range pressure, exact limit checks, and the two trade-offs above (an observation pushed out of the inspector's list, and an unrecognized value in an included env block).
  - Negative controls: shifted line numbers, a missing omission, redaction turned off, and v1 output given to the v0 validator.
- `github`:
  - the whole path from mocked API to validated bundle, compared with [a golden bundle](../contracts/cases-v1/valid-producer-fixture.json);
  - credential placement, including negative controls for a credential on a metadata request or the download.
