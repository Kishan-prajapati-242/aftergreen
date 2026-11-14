# Inspection result contract v0

Version string `aftergreen.inspection.v0`. This contract is normative. It is implemented by the Go package `collector/inspect` and the command `aftergreen-inspect`, and checked against the expected results in `cases-inspection-v0/`.

An inspection is computed offline from one bundle accepted by `bundle-v1.md`. It is a separate document: it is never written into the bundle, and it is independent of the v0 comparison (`comparison-v0.md`). Computing it involves no network, no model and no GitHub.

- **Mechanical only.** An observation says that a fixed pattern (section 3) matched an included line. A marker is not an explanation, and nothing in an inspection states or ranks a cause.
- **No copied text.** No text from the bundle appears in an inspection. Every string value is a name defined here, a source `id`, or the evidence digest.
- **Untrusted text.** Line text is matched as data. Bundle v1 already rejects control characters in line text; any other character, including invisible and bidirectional ones, is matched as it is and never output.

## 1. Input

- The input must be bytes that bundle v1 validation accepts, digest included. Other input produces no result.
- The inspected source is the one source with `kind` `job_log`.

## 2. Result

| Field | Content |
| --- | --- |
| `schema` | `"aftergreen.inspection.v0"` |
| `bundle_schema` | `"aftergreen.bundle.v1"` |
| `bundle_evidence_sha256` | the bundle's evidence digest |
| `evidence_class` | copied from the bundle |
| `job_log` | the job log's facts (below) |
| `observations` | at most 200 Observations, ordered as in section 3 |
| `counts` | Counts, over all included lines |
| `limitations` | Limitations, in the order of section 5 |

**`job_log`** has `source_id` and `status`. When the status is `missing`, it also has `missing_reason`. When it is `present`, it also has `extent`, `line_count`, `included_lines` (the number of included lines), `omitted_lines` (an object giving the number of omitted lines for each of the four omission reasons, every reason present, 0 if none), `omitted_ranges` (the number of omitted ranges) and `inline_redactions` (the bundle's `redactions`).

**An Observation** has:

- `kind`: `error_marker`, `nonzero_exit` or `step_header`;
- `marker`: for `error_marker` only, one of the names in section 3;
- `exit_code`: for `nonzero_exit` only, an integer;
- `citation`: `{source_id, start, end}` with `start` = `end` = the line number, which is always an included line of the job log;
- `step_header`: for `error_marker` and `nonzero_exit` only, and only when section 4 establishes it, the citation of a `step_header` line.

**Counts** is `{error_marker, nonzero_exit, step_header, observations}`. `error_marker` is an object with every marker name of section 3 as a key and the number of included lines it matched. `observations` is the number of observations before the limit of 200.

## 3. Patterns

Each included line is matched on its **body**: the line text, with one leading GitHub Actions timestamp removed when the text starts with one. A timestamp is `YYYY-MM-DDTHH:MM:SS`, optionally followed by `.` and 1–9 digits, then `Z` and one space (regular expression `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z `). Matching is case-sensitive. A "digit" is an ASCII digit `0`–`9`. "After indentation" means after any leading spaces and tabs. A "word character" is an ASCII letter, digit or `_`.

The text matched is the bundle's text, after the producer's redaction. A redaction placeholder is matched as ordinary text, and a redaction can remove part of a line and, with it, a marker. Nothing in an inspection can see what redaction removed.

**`error_marker`**, in this order:

| `marker` | The body |
| --- | --- |
| `gha_error` | contains `##[error]` |
| `npm_error` | starts with `npm ERR!`, or starts with `npm error` followed by a space or the end of the body |
| `go_test_fail` | after indentation, starts with `--- FAIL: `; or, without removing indentation, is `FAIL` or starts with `FAIL` followed by a space or a tab |
| `pytest_failed` | starts with `FAILED ` |
| `python_traceback` | after indentation, starts with `Traceback (most recent call last):` |
| `go_panic` | starts with `panic: ` |
| `error_line` | after indentation, starts with zero or more ASCII letters followed by `Error: `, as in `Error: ` or `TypeError: ` |
| `timeout` | contains `TimeoutError`, `Timed out` or `timed out` with no word character directly before or after it |
| `failed_count` | contains a run of digits that does not start with `0`, then ` failed`, with no word character directly before the number or after `failed`. So `0 failed` and `03 failed` do not match |

**`nonzero_exit`**: the body contains `Process completed with exit code ` followed by 1–10 digits that do not start with `0` and are not followed by another digit. `exit_code` is the first such number in the body. (`exit code 0` is not an observation.)

**`step_header`**: the body starts with `##[group]Run `. The GitHub Actions runner prints such a line at the start of many steps, and also for a step inside a composite action, so a step header does not say which top-level step it is.

One line can give several observations, for example `##[error]Process completed with exit code 1.` gives `error_marker` `gha_error` and `nonzero_exit`. Observations are ordered by line number, then `error_marker` (in marker order), `nonzero_exit`, `step_header`. Only the first 200 are listed.

## 4. Step attribution

For an `error_marker` or `nonzero_exit` observation at line `n`, `step_header` cites line `h` when all of these hold:

- line `h` is a step header, and `h ≤ n`;
- every line from `h` to `n` is included;
- no other step header lies between `h` and `n`.

Otherwise `step_header` is absent, and a `step_undetermined` limitation names line `n` (section 5) with reason:

- `lines_omitted_before`: an omitted line lies between line `n` and the nearest step header before it, or, when no step header is included before line `n`, anywhere before line `n`. An omitted line can hold a step header;
- `no_step_header_before`: every line before line `n` is included and none is a step header.

An established `step_header` says which step header line comes last before the observation, nothing more. It does not establish that this step printed the line:

- output that follows a step without a header of this shape is credited to the header before it;
- any process can print a line of this shape, for example with the `::group::` workflow command.

## 5. Limitations

Each Limitation has a `code` and the fields shown. Within each code, entries are ordered by `source_id`, then line.

| `code` | Fields | Meaning |
| --- | --- | --- |
| `log_missing` | `source_id`, `missing_reason` | the job log is missing; there are no observations |
| `log_incomplete` | `source_id`, `extent` | `prefix`: lines after `line_count` were never received; `partial`: they may exist. Either way the last line may be cut short |
| `line_may_be_cut` | `source_id`, `line` | the extent is not `complete`, and a listed `error_marker` or `nonzero_exit` observation cites the last line (`line` = `line_count`). That line may be cut short, so the full line could match differently or give another `exit_code` (a cut `137` reads `13`) |
| `source_missing` | `source_id`, `kind`, `missing_reason` | every other missing source |
| `lines_omitted` | `source_id`, `reason`, `count`, `ranges` | for each omission reason with at least one line, in the order `outside_selected_span`, `line_too_long`, `line_limit`, `redacted`. Patterns cannot match omitted lines |
| `context_omitted` | `source_id`, `line`, `side` | a line with an `error_marker` or `nonzero_exit` observation whose line before (`before`), after (`after`) or both (`both`) is omitted. Lines outside `1..line_count` do not count |
| `step_undetermined` | `source_id`, `line`, `reason` | section 4 |
| `checkout_unresolved` | `reason` | from the bundle's checkout |
| `matrix_unresolved` | `reason` | from the bundle's matrix |
| `no_markers` | `source_id` | the job log is present, and no included line gives an `error_marker` or `nonzero_exit` observation. That says nothing about lines that were omitted or about patterns not in section 3 |
| `observations_truncated` | `total`, `listed` | more than 200 observations; `line_may_be_cut`, `context_omitted` and `step_undetermined` cover only the listed ones |

`context_omitted` and `step_undetermined` have one entry per line, however many observations the line has.

## 6. Verification

A result document is first read strictly (`ParseResult`). Anything else is `result_invalid`, and nothing more is checked. The rules:

- at most 1 MiB, nested at most 32 levels deep;
- exactly one JSON value, with only whitespace after it;
- no member name twice in one object;
- member names exactly as in section 2 (case matters), and no other member; `counts.error_marker` has exactly the marker names of section 3, and `job_log.omitted_lines` exactly the four omission reasons;
- `observations` and `limitations` are arrays, never `null`;
- numbers are integers in plain decimal;
- the document reads back to the same members and values, so a field that does not apply is absent, never `null` or empty.

`Verify(bundle, result)` then checks the result against its bundle without trusting it, using its own reading of sections 3–5. It reports a problem for:

- a bundle that bundle v1 validation rejects (`bundle_invalid`), or no result (`result_missing`);
- any field of section 2 other than `observations` that differs from what the bundle gives (`header_mismatch`, `counts_mismatch`, `limitations_mismatch`);
- each observation:
  - an unknown `kind` or `marker`, or a field the kind does not allow (`invalid_observation`);
  - a citation of another source, or with `start` ≠ `end`, or outside `1..line_count` (`citation_invalid`);
  - a citation of an omitted line (`citation_not_included`);
  - a cited line that does not match the claimed pattern or exit code (`pattern_mismatch`);
  - a `step_header` that section 4 does not establish, or an absent one that it does (`step_header_mismatch`);
  - an observation that repeats or breaks the order (`order_invalid`);
- a matching line, among those the listed observations should cover, with no observation (`observation_missing`).
