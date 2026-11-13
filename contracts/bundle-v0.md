# Evidence bundle contract v0

Version string `aftergreen.bundle.v0`. Status: implemented by the Go validator in `go/` and the TypeScript validator in `ts/`, both checked against the shared cases in `cases/`. This document is normative. If a validator or case disagrees with it, that is a defect.

The contract covers only what a collector writes: Bundle, Run and Source. Diffs, comparisons, corpus hits, generated reports and traces are not part of it.

Nothing in v0 collects from GitHub, selects baselines, removes ANSI sequences or redacts secrets. v0 bundles are hand-written simulations. In a simulated bundle, repository, workflow, run, job and commit identifiers are invented and must not be looked up on GitHub.

## 1. Input bytes and JSON profile

1. The input is the raw byte sequence received (a file or a request body). More than 131,072 bytes (128 KiB) → `input_too_large`. This is checked before anything is decoded.
2. The bytes must be well-formed UTF-8: no overlong forms, no encoded surrogates, nothing above U+10FFFF → `invalid_utf8`.
3. The bytes must hold exactly one JSON value (RFC 8259), optionally surrounded by space, tab, LF or CR → `invalid_json`. Also rejected as `invalid_json`:
   - a byte order mark
   - comments, trailing commas or single quotes
   - an unescaped control character inside a string, or an unknown escape
   - a leading zero on a number without a minus sign, such as `01`
   - data after the value
4. Containers nest at most 16 deep, counting the top-level value as depth 1. Opening a 17th nested object or array → `nesting_too_deep`.
5. An object must not repeat a member name. Names are compared after unescaping, so `"a"` and `"\u0061"` are the same → `duplicate_key`.
6. A `\u` escape for a low surrogate, or a high surrogate not immediately followed by a `\u` low-surrogate escape → `invalid_utf8`.
7. A number must be `0`, or a digit 1–9 followed by digits, with a value of at most 9,007,199,254,740,991 (2^53 − 1). A grammatically valid JSON number that breaks this rule → `invalid_number`. That covers a minus sign, a fraction, an exponent, and anything larger. The parser reads the longest RFC 8259 number token and judges it as soon as the token ends, before reading the next character. So `-01` is `invalid_number` (the token is `-0`), while `01` is `invalid_json` (the token `0` is valid and the `1` after it is unexpected).
8. `true`, `false` and `null` parse as JSON, but no v0 member accepts them → `schema_violation`.

Rules 1 and 2 apply to the whole input before parsing starts. Malformed UTF-8 anywhere is therefore `invalid_utf8`, even when a syntax error comes earlier. Parsing then reads left to right and stops at the first error.

## 2. Evaluator-only member names

Evaluation answers live in separate sidecar files and must never be part of an input bundle.

After parsing, and before any other rule, every member name in every object is checked. The scan is depth-first and in document order, so the first reserved name in the document is the one reported.

A name is reserved if it is one of:

- `acceptable_hypotheses`, `answer`, `answers`, `baseline_applicability`, `diagnosis`, `expected`
- `fix`, `gold`, `ground_truth`, `injected_fault`, `repair`, `root_cause`
- `supporting_spans`, `unsupported_claims`, `verified_outcome`, `verified_repair`

A name is also reserved if it starts with `expected_`, `gold_`, `eval_` or `evaluator_`.

A reserved name → `evaluator_field`. No v0 member uses one.

Only member names are scanned; values are not. Every object already rejects names it does not list, so this scan changes the reported code, not whether a bundle is accepted. Answers can still hide in values. Fixture identifiers must therefore not hint at the diagnosis, and `case_id` and other file metadata must never be shown to a model.

## 3. Objects and members

An object accepts only the members listed for it. Checks run in this order:

1. Member names, in document order. A name not allowed in that object → `unknown_field`.
2. Required members, in table order. A missing one → `schema_violation`.
3. Values, in table order. A wrong JSON type, or a value outside its rule → `schema_violation`, unless the table names another code.

Checkout and Matrix, whose form depends on `status`, add steps after member names:

- `status` is checked next.
- Then any member that the selected form does not allow → `schema_violation`, in document order.
- Then the form's required members, in table order.

Source depends on both `kind` and `status`, and has its own order, given after its table.

| Value rule | Meaning |
| --- | --- |
| integer | a JSON number as in section 1 rule 7, in the stated range |
| timestamp | `YYYY-MM-DDTHH:MM:SSZ` in UTC: a real calendar date, hour 00–23, minute and second 00–59 |
| sha | 40 lowercase hexadecimal characters |
| id | matches `^[a-z0-9][a-z0-9._-]{0,63}$` |
| display string | 1–256 UTF-8 bytes, with no character U+0000–U+001F or U+007F |
| relative path | 1–256 bytes of `/`-separated segments drawn from `[A-Za-z0-9._-]`. Empty, `.` and `..` segments are not allowed |

### Bundle (top-level object; every member required)

| Member | Rule |
| --- | --- |
| `schema` | `"aftergreen.bundle.v0"` |
| `case_id` | matches `^[a-z0-9][a-z0-9-]{0,63}$` |
| `evidence_class` | `"simulated"`. v0 accepts no other value. Classes for collected and user-edited bundles arrive with the code that produces them |
| `created_at` | timestamp: when the producer wrote the bundle |
| `redaction` | `"none"`. No redaction exists yet, and v0 accepts no other value |
| `runs` | array of 1–2 Runs. After the items are checked: `runs[0].role` must be `failed`, and `runs[1].role`, if present, must be `baseline` |
| `sources` | array of Sources. More than 20 entries → `too_many_sources`, checked before the entries. After the entries: `id` values must be strictly ascending by byte value |
| `evidence_sha256` | 64 lowercase hexadecimal characters (section 7) |

### Run (one selected job of one run attempt; every member required)

| Member | Rule |
| --- | --- |
| `role` | `"failed"` or `"baseline"` |
| `repository` | object with `id` (integer ≥ 1) and `full_name` (matches `^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`) |
| `workflow` | object with `id` (integer ≥ 1) and `path` (matches `^\.github/workflows/[A-Za-z0-9._-]{1,100}\.ya?ml$`) |
| `run_id` | integer ≥ 1 |
| `run_attempt` | integer ≥ 1 |
| `attempt_started_at` | timestamp: start of this attempt, not of a later attempt |
| `event` | `"push"` |
| `branch` | matches `^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$` |
| `head_sha` | sha |
| `job` | object with:<br>• `id` (integer ≥ 1)<br>• `name` (display string)<br>• `conclusion` (`"failure"` or `"success"`)<br>• `started_at` (timestamp)<br>• `completed_at` (timestamp) |
| `checkout` | Checkout |
| `matrix` | Matrix |
| `runner` | Runner |

After the members, two consistency checks run, both → `schema_violation`:

- A `failed` run's `job.conclusion` must be `failure`, and a `baseline` run's must be `success`.
- `job.completed_at` must not be earlier than `job.started_at`.

### Checkout

Allowed member names: `status`, `sha`, `reason`, `evidence`. The value of `status` selects the form:

| `status` | Required members | Not allowed |
| --- | --- | --- |
| `"resolved"` | `sha` (sha), `evidence` (1–4 Spans) | `reason` |
| `"unresolved"` | `reason`, `evidence` (0–4 Spans) | `sha` |

`reason` is one of `dynamic_ref`, `multiple_checkouts`, `log_missing`, `reusable_workflow`, `output_unverifiable`, `no_checkout_step`.

### Matrix

Allowed member names: `status`, `values`, `reason`, `evidence`.

| `status` | Required members | Not allowed |
| --- | --- | --- |
| `"none"` (not a matrix job) | none | `values`, `reason`, `evidence` |
| `"resolved"` | `values`, `evidence` (0–4 Spans) | `reason` |
| `"unresolved"` | `reason`, `evidence` (0–4 Spans) | `values` |

`values` holds 1–8 objects, each with:

- `key`: matches `^[A-Za-z0-9_-]{1,64}$`
- `value`: display string

Keys must be strictly ascending, checked after the items.

`reason` is one of `custom_job_name`, `log_missing`, `ambiguous`.

### Runner (every member required)

| Member | Rule |
| --- | --- |
| `os` | `Linux`, `Windows`, `macOS` or `unknown` |
| `arch` | `X64`, `ARM64`, `X86`, `ARM` or `unknown` |
| `labels` | array of 0–10 strings, each matching `^[A-Za-z0-9._-]{1,64}$` |
| `evidence` | 0–4 Spans |

### Span (every member required)

| Member | Rule |
| --- | --- |
| `source_id` | id |
| `start` | integer |
| `end` | integer |

How a span resolves is checked in section 6.

### Source

Allowed member names: `id`, `kind`, `run_role`, `status`, `path`, `revision`, `missing_reason`, `extent`, `line_count`, `lines`, `omitted`. The first four are required.

| Member | Rule |
| --- | --- |
| `id` | id |
| `kind` | `job_log`, `workflow_file`, `manifest` or `lockfile` |
| `run_role` | `failed` or `baseline`: the run whose job used this source |
| `status` | `present` or `missing` |
| `path` | Not allowed for `job_log`. Required for other kinds, as a relative path:<br>• `workflow_file`: must also match the workflow path pattern<br>• `manifest`: last segment must be `package.json`<br>• `lockfile`: last segment must be `package-lock.json` |
| `revision` | Not allowed for `job_log`. For other kinds: required, the sha of the commit the file was read at |
| `missing_reason` | Required when `missing`; one of `expired`, `not_found`, `too_large`, `limit_reached`, `access_denied`, `not_collected`. Not allowed when `present` |
| `extent` | Required when `present`:<br>• `complete`: the whole source was read<br>• `prefix`: reading stopped at a byte limit, and lines after `line_count` were never read |
| `line_count` | Required when `present`: integer, the number of lines read |
| `lines` | Required when `present`: array of at most 500 Lines. More → `too_many_lines`, checked before the entries |
| `omitted` | Required when `present`: array of at most 501 Omitted ranges |

Source checks run in this order, each failure → `schema_violation` unless another code is named:

1. Member names, in document order (`unknown_field`).
2. `id`, `kind`, `run_role` and `status` must be present, in that order; then their values are checked in the same order.
3. `path`, then `revision`: not allowed for `job_log`, required and checked for other kinds.
4. If `missing`: `missing_reason` is checked, then `extent`, `line_count`, `lines` and `omitted` must be absent, in that order.
5. If `present`: `missing_reason` must be absent; then `extent`, `line_count`, `lines` (count first, then each Line) and `omitted` are checked, in that order.

Line (both members required):

- `n`: integer.
- `text`: string. Over 2,048 UTF-8 bytes → `line_too_long`. The length is measured on the decoded string, not on its JSON escapes.
- After the length check, `text` containing U+0000–U+0008, U+000A–U+001F or U+007F → `schema_violation`. Tab is allowed.

Omitted (every member required):

- `start` and `end`: integers.
- `reason`: one of `outside_selected_span`, `line_too_long`, `line_limit`. The reason `redacted` is reserved for a version that has redaction. v0 rejects it, because no v0 bundle can have been redacted.

## 4. Original line numbers

Original line numbers count the lines of the text the producer obtained: a downloaded job log, or a file at `revision`.

- The text is split on LF, and a CR directly before an LF is removed.
- A final LF does not start another line.
- The first line is 1.
- `line_count` is the number of lines obtained. `"a\nb\n"` and `"a\nb"` each have 2 lines; empty text has 0.

A Line keeps its original number `n`. Sanitized line `n` is therefore always original line `n`. A transform may change a line's text but never its number.

Every number from 1 to `line_count` is covered exactly once, either by a Line or by an Omitted range. A transform that removes several lines becomes an Omitted range; lines are never merged. A future redaction of a private-key block would use reason `redacted`, which v0 does not accept yet. No such transform exists in M1.

These rules are checked in section 6; a violation → `line_map_invalid`:

- `lines` are strictly ascending by `n`. Each Omitted range has `start ≤ end`, and `start` values are strictly ascending.
- If an Omitted range starts on the line right after the previous range ends, the two must have different reasons.
- Walk Lines (as one-line ranges) and Omitted ranges together, ordered by start line. When a Line and a range start on the same number, the Line comes first. Starting from 1, each item must begin exactly at the next uncovered number, and the walk must finish at `line_count`.

## 5. Required sources

Every run has exactly one source of each kind: `job_log`, `workflow_file`, `manifest` and `lockfile`. A source that could not be obtained is still listed, with `status: "missing"` and a `missing_reason`. A partial bundle therefore stays valid instead of depending on something it does not contain.

- A kind with no source for a run → `missing_source_entry`.
- Two sources of the same kind for one run → `schema_violation`.

## 6. Cross-checks

These run after sections 1–3 pass, in this order:

1. Two runs with different `repository.id` or `repository.full_name` → `schema_violation`.
2. A baseline whose `job.completed_at` is not strictly earlier than the failed run's `attempt_started_at` → `schema_violation`. A baseline must have finished before the failure began, so it cannot contain a later repair.
3. A source whose `run_role` names a run that is not present → `unknown_reference`.
4. Required sources (section 5). Runs are taken in array order, and kinds in the order listed in section 5.
5. For each run in array order, its `workflow_file` source `path` differs from `run.workflow.path` → `schema_violation`.
6. Line maps of present sources, in array order (section 4).
7. Spans. For each run in order, the span lists are checked as `checkout.evidence`, then `matrix.evidence` (if present), then `runner.evidence`. For each span:
   - A `source_id` not declared in `sources` → `unknown_reference`.
   - Each of the following → `span_invalid`:
     - the source is `missing`
     - the source has a different `run_role` from the run
     - `start < 1`, or `end < start`, or `end > line_count`
     - some line from `start` to `end` is not an included Line

## 7. Evidence digest

`evidence_sha256` is the lowercase hexadecimal SHA-256 of these bytes:

```text
"aftergreen.bundle.evidence.v0\n" || enc(E)
```

E is an object containing exactly the bundle's `schema`, `evidence_class`, `runs` and `sources` members, as parsed. Four members are left out: `case_id`, `created_at`, `redaction` and `evidence_sha256`. They describe the file rather than the evidence, so the same evidence written twice has the same digest.

`enc` is a length-prefixed canonical encoding of a parsed value:

| Value | Encoding |
| --- | --- |
| object | `d`, then for each member in ascending order of the UTF-8 bytes of its name: `enc(name)`, `enc(value)`; then `e` |
| array | `l`, then `enc` of each element in order, then `e` |
| string | `s`, the number of UTF-8 bytes in decimal, `:`, then those bytes |
| integer | `i`, the decimal digits, then `e` |

Strings are encoded after unescaping. JSON whitespace, member order and the choice of escapes therefore do not change the digest. Booleans and null never reach `enc`, because section 3 rejects them first.

Example: `{"b":[1,"é"],"a":"x"}` encodes as `ds1:as1:xs1:bli1es2:` followed by the bytes `C3 A9`, then `ee`. The shared cases contain this vector and its SHA-256.

A recomputed digest that differs from `evidence_sha256` → `digest_mismatch`. This is the last check.

The digest identifies content. It proves neither GitHub origin nor truth, and anyone who edits a bundle can recompute it.

## 8. Results and error codes

A validator reports the first failing check and nothing after it. The normative parts of a result are:

- the error `code`
- the `pointer`
- on acceptance, the digest

Error messages are informational and may differ between implementations.

`pointer` is an RFC 6901 JSON Pointer (`~` written as `~0`, `/` as `~1`) to the value whose check failed:

- an unknown or reserved member, or a member not allowed in its form: that member
- a missing member: the place it would occupy
- an array count rule: the array
- an order rule: the first out-of-order element's key, for example `/sources/7/id`
- run consistency checks: `/runs/<i>/job/conclusion` or `/runs/<i>/job/completed_at`
- byte and parse errors, and a top-level value that is not an object: the empty string

Cross-check pointers:

| Check | Pointer |
| --- | --- |
| repositories differ | `/runs/1/repository` |
| baseline did not finish before the failed attempt started | `/runs/1/job/completed_at` |
| unknown `run_role` | `/sources/<i>/run_role` |
| missing required source | `/runs/<r>` |
| duplicate required source | `/sources/<j>/kind`, where `j` is the second such source |
| workflow path differs | `/sources/<j>/path` |
| `lines` order | `/sources/<i>/lines/<k>/n` |
| range `start > end` | `/sources/<i>/omitted/<k>/end` |
| range `start` order | `/sources/<i>/omitted/<k>/start` |
| adjacent ranges with the same reason | `/sources/<i>/omitted/<k>/reason`, the second range |
| walk item not at the next number | that item's `/n` or `/start` |
| walk does not finish at `line_count` | `/sources/<i>/line_count` |
| span source problems | `.../evidence/<k>/source_id` |
| span `start < 1` | `.../evidence/<k>/start` |
| span `end` out of range | `.../evidence/<k>/end` |
| span covers a line that is not included | `.../evidence/<k>` |
| digest differs | `/evidence_sha256` |

| Phase | Code | Meaning |
| --- | --- | --- |
| bytes | `input_too_large` | more than 131,072 raw bytes |
| bytes or parse | `invalid_utf8` | malformed UTF-8, or an escape for an unpaired surrogate |
| parse | `invalid_json` | not exactly one JSON value in the strict profile |
| parse | `nesting_too_deep` | more than 16 nested containers |
| parse | `duplicate_key` | a member name repeated within one object |
| parse | `invalid_number` | a number that is not a non-negative integer ≤ 2^53 − 1 |
| evaluator scan | `evaluator_field` | a reserved evaluator-only member name, anywhere in the document |
| structure | `unknown_field` | a member not allowed in its object |
| structure | `schema_violation` | a missing member, wrong type, value outside its rule, or failed consistency rule |
| structure | `too_many_sources` | more than 20 sources |
| structure | `too_many_lines` | more than 500 Lines in one source |
| structure | `line_too_long` | a line text over 2,048 UTF-8 bytes |
| cross-check | `unknown_reference` | a span or source names an undeclared source or run |
| cross-check | `missing_source_entry` | a run lacks one of its four required sources |
| cross-check | `line_map_invalid` | Lines and Omitted ranges do not cover 1..`line_count` exactly once |
| cross-check | `span_invalid` | a span does not resolve to included lines of a present source of the same run |
| digest | `digest_mismatch` | the recomputed digest differs |

## 9. What v0 does not check

The raw 128 KiB limit is the only cumulative byte limit. There is no separate total for line text.

Validation proves structure, not truth. v0 does not verify these producer claims:

- `evidence_class`, `missing_reason`, `extent` and omitted-range reasons
- a `resolved` checkout's `sha`: its spans must exist, but nothing checks that those lines show that SHA
- that any span supports what it is cited for
- that file revisions match the checkout SHA, and that a baseline is comparable (Gate 2 rules)

All strings are untrusted data. That includes line text, display strings, and member names repeated in error pointers and messages. v0 rejects only C0 controls and DEL. It accepts C1 controls, zero-width and other format characters, tag characters (U+E0000–U+E007F), bidirectional controls, and U+2028 and U+2029. Later stages must:

- escape strings for HTML and terminals
- never follow instructions found in them
- show invisible and line-separator characters visibly, or strip them, before a person reviews the evidence
- send a model exactly the text that was shown for review
