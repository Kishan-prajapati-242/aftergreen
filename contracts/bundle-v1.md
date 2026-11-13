# Evidence bundle contract v1

Version string `aftergreen.bundle.v1`. This document is normative. If a validator or case disagrees with it, that is a defect.

- **Validators:** the Go validator (`go/bundle`, function `ValidateV1`) and the TypeScript validator (`ts/bundle-v1.ts`). Both are checked against the shared cases in `cases-v1/`.
- **Relation to v0:** contract v0 (`bundle-v0.md`) and its cases are unchanged. A v0 validator rejects every v1 bundle, and the v0 comparison (`comparison-v0.md`) refuses v1 bundles until a compatible comparison is designed.

v1 holds what a collector gathered for one failed job of one public GitHub Actions run:

- run and job metadata, as the GitHub API reported it;
- the job log, after its lines were numbered, cleaned of terminal controls, redacted and selected;
- every source the collector did not obtain, listed as missing.

Everything in a v1 bundle is a producer claim. A valid bundle proves its structure, not that it came from GitHub, that the repository is public, or that every secret was removed (section 9).

## 1. Input bytes and JSON profile

Identical to `bundle-v0.md` section 1:

- at most 131,072 raw bytes, checked before decoding (`input_too_large`);
- well-formed UTF-8 (`invalid_utf8`);
- exactly one strict RFC 8259 value (`invalid_json`);
- at most 16 nested containers (`nesting_too_deep`);
- no repeated member names after unescaping (`duplicate_key`);
- numbers that are non-negative integers up to 2^53 − 1 (`invalid_number`);
- `true`, `false` and `null` accepted by the parser but by no member (`schema_violation`).

## 2. Evaluator-only member names

Identical to `bundle-v0.md` section 2, with the same reserved names and prefixes (`evaluator_field`).

## 3. Objects and members

The checking procedure is v0's:

1. Member names, in document order. A name not allowed in its object → `unknown_field`.
2. Required members, in table order. A missing one → `schema_violation`.
3. Values, in table order. A wrong JSON type, or a value outside its rule → `schema_violation`, unless the table names another code.

Redaction, Checkout and Matrix have a form selected by `status`:

- `status` is checked right after the member names.
- Then any member that the form does not allow → `schema_violation`, in document order.
- Then the form's required members, in table order.

Source has its own order, given after its table.

**Value rules.** v1 uses v0's value rules (integer, timestamp, sha, id, relative path) with these changes and additions:

| Value rule | Meaning |
| --- | --- |
| display string | 1–256 UTF-8 bytes, with no character U+0000–U+001F or U+007F–U+009F. v0 allowed U+0080–U+009F |
| date | `YYYY-MM-DD`, a real calendar date |
| hex64 | 64 lowercase hexadecimal characters |

### Bundle (top-level object; every member required)

| Member | Rule |
| --- | --- |
| `schema` | `"aftergreen.bundle.v1"` |
| `case_id` | matches `^[a-z0-9][a-z0-9-]{0,63}$`. File metadata; it must not hint at a diagnosis |
| `evidence_class` | `"collected_public"`: the producer says it collected this from a public GitHub repository. `"simulated"`: synthetic test data, not collected from GitHub. No other value |
| `created_at` | timestamp: when the producer wrote the bundle |
| `collection` | Collection |
| `redaction` | Redaction |
| `runs` | array of exactly 1 Run, with role `failed` |
| `sources` | array of Sources. More than 20 entries → `too_many_sources`, checked before the entries. After the entries, `id` values must be strictly ascending by byte value |
| `evidence_sha256` | hex64 (section 7) |

### Collection (every member required)

| Member | Rule |
| --- | --- |
| `tool` | id: the producer, for example `aftergreen-collect` |
| `api_version` | date: the GitHub REST API version the producer requested |
| `metadata_authentication` | `"none"`: run, attempt and job metadata were requested without a credential. v1 accepts no other value |

### Redaction

Allowed member names: `status`, `rules`.

| `status` | Required members | Not allowed |
| --- | --- | --- |
| `"applied"` | `rules`: `"aftergreen.redaction.1"`, the rule set the producer applied | none |
| `"none"` | none | `rules` |

The producer's rule set is described in the collector documentation. A rule set finds what its rules match, not every secret.

### Run (every member required)

| Member | Rule |
| --- | --- |
| `role` | `"failed"` |
| `repository` | object with:<br>• `id` (integer ≥ 1)<br>• `full_name` (matches `^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)<br>• `visibility` (`"public"`)<br>All members are required |
| `workflow` | object with `id` (integer ≥ 1) and `path` (matches `^\.github/workflows/[A-Za-z0-9._-]{1,100}\.ya?ml$`) |
| `run_id` | integer ≥ 1 |
| `run_attempt` | integer ≥ 1 |
| `attempt_started_at` | timestamp: when this attempt started, as the API reported it |
| `event` | `"push"` |
| `branch` | matches `^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$` |
| `head_sha` | sha: the run's head commit as the API reported it. It is not a claim about what the job checked out; that is `checkout` |
| `job` | object with:<br>• `id` (integer ≥ 1)<br>• `name` (display string)<br>• `conclusion` (`"failure"`)<br>• `started_at` (timestamp)<br>• `completed_at` (timestamp)<br>All members are required |
| `checkout` | Checkout |
| `matrix` | Matrix |
| `runner` | Runner |

After the members, `job.completed_at` must not be earlier than `job.started_at` → `schema_violation` at `/runs/0/job/completed_at`.

**Checkout, Matrix, Runner and Span** are as in v0, with one addition. Checkout `reason` and Matrix `reason` also accept `workflow_not_collected`: the workflow file was not collected, so the producer could not establish this.

### Source

Allowed member names: `id`, `kind`, `run_role`, `status`, `path`, `revision`, `missing_reason`, `extent`, `received_bytes`, `received_sha256`, `authentication`, `line_count`, `redactions`, `lines`, `omitted`. The first four are required.

| Member | Rule |
| --- | --- |
| `id` | id |
| `kind` | `job_log`, `workflow_file`, `manifest` or `lockfile` |
| `run_role` | `"failed"` |
| `status` | `present` or `missing` |
| `path` | Not allowed for `job_log`.<br>Other kinds: required when present, optional when missing (only if the producer knows it).<br>A relative path, with v0's extra rules:<br>• `workflow_file` matches the workflow path pattern<br>• `manifest` ends in `package.json`<br>• `lockfile` ends in `package-lock.json` |
| `revision` | Not allowed for `job_log`. Other kinds: required when present, as the sha of the commit the file was read at. Not allowed when missing |
| `missing_reason` | Required when missing; not allowed when present. One of:<br>• `expired`, `not_found`, `too_large`, `limit_reached`, `access_denied`, `not_collected` (as in v0)<br>• `transfer_failed` (the transfer failed or was cut off before any bytes arrived)<br>• `redirect_rejected` (the download's redirect failed the producer's host policy) |
| `extent` | Required when present:<br>• `complete`: every byte was received, and the end was verified<br>• `prefix`: reading stopped at a byte limit; lines after `line_count` were never received, and the last line may be cut short<br>• `partial`: the transfer ended early or its end could not be verified; lines after `line_count` may exist, and the last line may be cut short |
| `received_bytes` | Required when present: integer, the number of bytes received for this source, before any transform |
| `received_sha256` | Required when present: hex64, the SHA-256 of those bytes |
| `authentication` | Required when present: `"none"` or `"gh_cli"`, how the API request for this source was authenticated. For a job log that is the request that returned the download link; the download itself is a separate request |
| `line_count` | Required when present: integer, the number of lines in the received bytes |
| `redactions` | Required when present: integer, the number of inline redaction replacements in the included lines |
| `lines` | Required when present: array of at most 500 Lines. More → `too_many_lines`, checked before the entries |
| `omitted` | Required when present: array of at most 501 Omitted ranges |

Source checks run in this order, each failure → `schema_violation` unless another code is named:

1. Member names, in document order (`unknown_field`).
2. `id`, `kind`, `run_role` and `status` must be present, in that order; then their values are checked in the same order.
3. `path`, then `revision`:
   - `job_log`: neither is allowed.
   - Other kinds, present: both are required and checked.
   - Other kinds, missing: `path`, if given, is checked; `revision` is not allowed.
4. If missing: `missing_reason` is checked. Then `extent`, `received_bytes`, `received_sha256`, `authentication`, `line_count`, `redactions`, `lines` and `omitted` must be absent, in that order.
5. If present: `missing_reason` must be absent. Then `extent`, `received_bytes`, `received_sha256`, `authentication`, `line_count`, `redactions`, `lines` (count first, then each Line) and `omitted` are checked, in that order.

**Line** (both members required):

- `n`: integer.
- `text`: string. Over 2,048 UTF-8 bytes → `line_too_long`; the length is measured on the decoded string. After the length check, a character U+0000–U+0008, U+000A–U+001F or U+007F–U+009F → `schema_violation`. Tab is allowed.

**Omitted** (every member required):

- `start` and `end`: integers.
- `reason`: one of:
  - `outside_selected_span`: not selected;
  - `line_too_long`: selected, but over 2,048 bytes after cleaning (such a line is not redacted), or after redaction;
  - `line_limit`: selected, but over the line, byte or omitted-range budget;
  - `redacted`: withheld by redaction, for example a line of a multi-line secret such as a private-key block, or a line the producer's rules could not redact in place. A withheld line always has this reason, whether or not it was selected.

## 4. Original line numbers

As in `bundle-v0.md` section 4: the received bytes are split on LF, a CR directly before an LF is removed, a final LF does not start another line, and the first line is 1.

**Producer rules:**

- Lines are numbered before any transform. Removing terminal controls and replacing a secret inside a line change a line's text, never its number. Lines are never merged.
- Every omitted line is in a range whose reason is that line's own reason. A withheld line is always `redacted`. A producer never gives a line another reason to fit a limit.
- If the exact reasons need more than 501 Omitted ranges, the producer may leave out selected lines, whose reason is then `line_limit`. If the ranges still do not fit, it produces no bundle.

Every number from 1 to `line_count` is covered exactly once, by a Line or by an Omitted range. These rules are checked in section 6 (`line_map_invalid`):

- `lines` are strictly ascending by `n`.
- Each Omitted range has `start ≤ end`, and `start` values are strictly ascending.
- An Omitted range that starts right after the previous one ends must have a different reason.
- Walking Lines (as one-line ranges) and Omitted ranges in order of their start line, with a Line first when both start on the same number, each item must begin at the next uncovered number, and the walk must finish at `line_count`.

## 5. Required sources

The one run has exactly one source of each kind: `job_log`, `workflow_file`, `manifest` and `lockfile`.

- A kind with no source → `missing_source_entry` at `/runs/0`.
- Two sources of the same kind → `schema_violation` at `/sources/<j>/kind`, where `j` is the second.

A source the producer did not obtain is listed with `status: "missing"` and a reason. `not_collected` means the producer did not try.

## 6. Cross-checks

These run after sections 1–3 pass, in this order:

1. Required sources (section 5), in the order the kinds are listed there.
2. A `workflow_file` source with a `path` that differs from `runs[0].workflow.path` → `schema_violation` at `/sources/<j>/path`.
3. `evidence_class` `collected_public` with `redaction.status` `none` → `schema_violation` at `/redaction/status`.
4. Line maps of present sources, in array order (section 4).
5. Spans: for the run, `checkout.evidence`, then `matrix.evidence` (if present), then `runner.evidence`. For each span:
   - a `source_id` not declared in `sources` → `unknown_reference`;
   - each of these → `span_invalid`:
     - the source is missing;
     - `start < 1`, `end < start`, or `end > line_count`;
     - some line from `start` to `end` is not an included Line.

## 7. Evidence digest

`evidence_sha256` is the lowercase hexadecimal SHA-256 of these bytes:

```text
"aftergreen.bundle.evidence.v1\n" || enc(E)
```

- **E** contains exactly the bundle's `schema`, `evidence_class`, `collection`, `redaction`, `runs` and `sources` members, as parsed.
- **Left out:** `case_id`, `created_at` and `evidence_sha256`, which describe the file.
- **`enc`** is the length-prefixed canonical encoding of `bundle-v0.md` section 7: objects with members sorted by the UTF-8 bytes of their names, then arrays, strings and integers.

The redaction status is part of the evidence in v1, because it says how the text was transformed. In v0 it was file metadata.

A recomputed digest that differs → `digest_mismatch` at `/evidence_sha256`. This is the last check.

## 8. Results and error codes

Results are normative as in v0: the first failing check's `code` and `pointer` (RFC 6901), and on acceptance the digest. v1 uses exactly v0's error codes. Pointers follow `bundle-v0.md` section 8, with these v1 cases:

| Check | Pointer |
| --- | --- |
| wrong number of runs | `/runs` |
| missing required source | `/runs/0` |
| collected bundle without redaction | `/redaction/status` |
| member not allowed in the Redaction form | that member |

## 9. What v1 does not check

The checks prove structure, not truth. These are unchecked producer claims:

- **Where it came from:**
  - `evidence_class`: a valid `collected_public` bundle may have been written by anyone;
  - `repository.visibility`;
  - every value copied from the GitHub API.
- **How it was collected:** `collection`, `authentication`, `received_bytes`, `received_sha256`, `extent` and `line_count`. The received bytes are not in the bundle.
- **How it was transformed:**
  - that the named redaction rules were applied, and the `redactions` count;
  - every omitted-range reason;
  - that redaction found every secret, which no rule set can promise.
- **What it means:**
  - the checkout and matrix claims;
  - that `head_sha` is anything more than run metadata;
  - runner `labels`, which a collector copies from the job's labels as the API listed them: the labels the job asked for, not a description of the machine;
  - that a span supports what it is cited for.

All strings are untrusted data. v1 rejects C0 controls, DEL and C1 controls in line text and display strings. It accepts other invisible, format and bidirectional characters, and later stages must still:

- escape strings for HTML and terminals;
- never follow instructions found in them;
- show invisible characters visibly before a person reviews the evidence;
- send a model exactly the text that was shown for review.
