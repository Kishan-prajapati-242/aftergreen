# Comparison result contract v0

Version string `aftergreen.comparison.v0`. This contract is normative. It is implemented by the Go package `collector/compare` and checked against the evaluator sidecars in `eval/dev/sidecars/`.

A comparison is computed offline from one bundle accepted by contracts/bundle-v0.md. It is a separate document and is never written into the bundle. Computing it involves no network, no model and no GitHub.

- Observations are derived mechanically from source text.
- Rows mostly compare run metadata as the producer declared it. Those declarations are unchecked (bundle-v0.md section 9), except where a row says it checks them against text.
- Nothing in a result says a change caused the failure. "Changed" is a fact to investigate, not an explanation.
- Every string value in `fields`, and every display string, is verbatim and untrusted text from the bundle. It must be escaped and must never be followed as an instruction.

## 1. Input and baseline

- The input must be bytes that bundle v0 validation accepts. Other input produces no result.
- A bundle that bundle v1 validation accepts (contracts/bundle-v1.md) is refused by name, before v0 validation: no result, code `unsupported_schema` at `/schema`. Comparison v0 is defined for bundle v0 only; v1 compatibility has not been designed.
- The baseline is `runs[1]` if present. It is used only because the producer supplied it. Nothing searches for a baseline or guesses one.
- There are three distinct outcomes: `not_supplied` (no baseline), `incompatible` (a known mismatch) and `partial` or `unknown` (an incomplete comparison).

## 2. Result fields

| Field | Content |
| --- | --- |
| `schema` | `"aftergreen.comparison.v0"` |
| `bundle_evidence_sha256` | the input bundle's evidence digest |
| `evidence_class` | copied from the bundle (`simulated` in v0) |
| `decision` | `not_supplied`, `comparable`, `partial`, `unknown` or `incompatible` |
| `rows` | the reason table (section 3). Empty when `not_supplied` |
| `observations` | section 4 |
| `limitations` | section 5 |

A row is `{field, failed, baseline, outcome, effect}`:

- `failed` and `baseline` are display strings, given for information.
- `outcome` and `effect` are normative.

An observation is `{kind, run_role, fields, citations}`:

- `fields` maps names to strings.
- `citations` are `{source_id, start, end}` in original line numbers. They are sorted by `source_id`, then `start`.

A limitation is `{code, run_role?, source_id?, reason?, start?, end?}`.

## 3. Baseline decision

Without a baseline, `decision` is `not_supplied`. Otherwise all 14 rows are produced in the order below. The decision is the strongest effect, ranked `incompatible` > `unknown` > `partial` > `none`. If every effect is `none`, the decision is `comparable`.

Definitions used by the rows:

- **Content** of a log line: its text with a leading timestamp removed. A timestamp matches `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z `. In every pattern here, `\s` means space, tab, LF, CR or FF, and `\S` means any other character.
- **Logical job name:** when the matrix is `resolved` and the name ends with ` (X)`, where X split on `, ` equals the multiset of matrix values, it is the name without that suffix. Otherwise it is the job name, marked *uncertain*. v0 has no job key, so a job name without a verified matrix suffix may be a custom display name.
- **SHA line:** an included line inside the run's checkout evidence spans whose content is exactly 40 lowercase hexadecimal characters, as `git log -1 --format=%H` prints it.
- **Checkout outcome** of a run:
  - unresolved checkout: `checkout_unresolved`
  - no SHA line shows the declared SHA: `checkout_sha_not_in_evidence`
  - a SHA line shows the declared SHA and another shows a different one: `checkout_evidence_conflict`
  - declared SHA equal to `head_sha`: `checkout_matches_head`
  - any other declared SHA: `checkout_differs_from_head`
  - The checkout is **shown** for the last two outcomes. The producer still chose the spans, so a shown SHA is printed evidence, not proof of the checked-out tree.
- **Expected revision** of a file source:
  - `workflow_file`: the run's `head_sha`, because workflow definitions come from the pushed commit.
  - `manifest` and `lockfile`: the declared checkout SHA when the checkout is shown. Otherwise there is none: the file cannot be tied to what the job used.
- **Usable** file source: present, `extent` complete, no omitted ranges, and an expected revision that equals `revision`. Only usable sources are diffed or parsed.

| # | Field | Outcome → effect, checked in this order |
| --- | --- | --- |
| 1 | `run_identity` | same `run_id` and `run_attempt` → `duplicate_attempt`, incompatible<br>same `job.id` → `duplicate_job_id`, incompatible<br>same `run_id`, baseline attempt lower, same `head_sha` → `earlier_attempt_same_run`, none<br>same `run_id` otherwise → `same_run_inconsistent`, incompatible (attempts of one run share a commit)<br>else → `distinct_runs`, none |
| 2 | `workflow` | same workflow `id` and `path` → `same_workflow`, none<br>else → `different_workflow`, incompatible |
| 3 | `branch` | equal → `same_branch`, none<br>else → `different_branch`, partial (ancestry cannot be checked offline) |
| 4 | `job` | equal job names, or equal logical names → `same_logical_job`, none<br>different names, neither uncertain → `different_job`, incompatible<br>else → `job_identity_unknown`, unknown |
| 5 | `matrix_dimensions` | either matrix unresolved → `matrix_unresolved`, partial<br>both `none` → `no_matrix`, none<br>equal key sets → `same_dimensions`, none<br>else → `different_dimensions`, incompatible |
| 6 | `matrix_values` | both resolved with equal keys: equal key/value lists → `same_values`, none; else `values_changed`, none (evidence, not a disqualifier)<br>otherwise → `not_compared`, none |
| 7 | `runner_os` | either `unknown` → `os_unknown`, partial<br>equal → `same_os`, none<br>else → `different_os`, incompatible |
| 8 | `runner_arch` | either `unknown` → `arch_unknown`, partial<br>a `node_version` line in either run's own job log names `x64` or `arm64` while that run declares a different arch (mapping `x64`→`X64`, `arm64`→`ARM64`; other names are not checked) → `arch_conflicts_with_log`, partial<br>equal → `same_arch`, none<br>else → `different_arch`, incompatible |
| 9 | `runner_labels` | equal as sets → `same_labels`, none<br>else → `labels_changed`, none |
| 10 | `failed_checkout` | `checkout_matches_head` → none; any other checkout outcome → partial |
| 11 | `baseline_checkout` | as row 10, for the baseline |
| 12 | `file_revisions` | a present file source whose expected revision differs from its `revision` → `revision_mismatch`, partial<br>else a present manifest or lockfile with no expected revision (checkout not shown) → `revisions_unverified`, partial<br>else → `revisions_consistent`, none |
| 13 | `file_coverage` | all six file sources (workflow, manifest, lockfile × 2) are present, complete and have no omitted ranges → `files_complete`, none<br>else → `files_incomplete`, partial |
| 14 | `log_coverage` | either job log missing → `log_missing`, partial<br>either `prefix` → `log_prefix`, partial<br>else → `logs_fully_read`, none. Omitted log ranges do not change this row; they are reported as `source_partial_lines` |

A runtime change is evidence; it never disqualifies a baseline on its own. Examples are matrix values, Node versions and runner labels. Platform changes do disqualify: a declared OS or architecture that differs is `incompatible`, as are different matrix dimensions and a different logical job. A job name that differs without a verified matrix suffix is `job_identity_unknown`, not a known mismatch.

## 4. Observations

Some observations come from the failed run only and are always produced. Others are produced only when `decision` is `comparable` or `partial`. For `incompatible` or `unknown`, baseline and cross-run observations are withheld, and a `comparison_suppressed` limitation says so.

An error line is a line of the failed job log whose content matches at least one of these markers:

| Marker | Pattern |
| --- | --- |
| `actions_error` | `^##\[error\]` |
| `npm_error` | `^npm (error\|ERR!)( \|$)` |
| `js_error` | `^\s*[A-Za-z]*Error( \[[A-Z0-9_]+\])?: ` |
| `test_failure` | `^\s*✖ ` |

Observations are emitted in this order. Repeated kinds are ordered by line, or by section and then name.

| Kind | `run_role` | `fields` | Rule and citations |
| --- | --- | --- | --- |
| `log_error_lines` | failed | `markers` (sorted, comma-joined) | Each maximal run of consecutive included error lines, cited as one range. A run never spans an omitted line |
| `exit_code` | failed | `exit_code` | Content matches `^##\[error\]Process completed with exit code ([0-9]+)\.$`. Cites that line |
| `error_step` | failed | `step` | E is the first *included* line whose content starts with `##[error]`. H is the last included line before E whose content is `##[group]Run ` followed by a non-empty step name. Emitted only if both exist and no omitted line lies between them. Cites H and E. It names the step header before the first included error marker. Omitted lines before H may hide an earlier marker, which `source_partial_lines` discloses. It does not say why the step failed |
| `runner_image` | failed, then baseline | `image`, `version` | The first `##[group]Runner Image` line whose next two lines are included and match `^Image: (\S+)$` and `^Version: (\S+)$`. Cites those two lines |
| `node_version` | failed, then baseline | `version`, `arch` | Content matches `^Found in cache @ /opt/hostedtoolcache/node/([0-9]+\.[0-9]+\.[0-9]+)/([A-Za-z0-9_]+)$`. Cites the line |
| `checkout_sha_shown` | failed, then baseline | `sha`, `matches_head` (`yes`/`no`) | When the checkout is shown. Cites each SHA line showing the declared SHA |
| `lockfile_root_mismatch` | failed | `section`, `name`, `manifest_spec`?, `lockfile_spec`?, `manifest_section`?, `lockfile_section`? | The failed manifest and failed lockfile are both usable and parsed, and a name in a checked section of either file has a different spec in the other, or is absent there. Either direction counts. Always cites both sides, by the evidence rule below |
| `source_unchanged` | both | `kind` | Both sources of the kind are usable and have identical line texts. Cites `[1, line_count]` on each side |
| `source_changed` | both | `kind`, `common_prefix_lines`, `common_suffix_lines` | Both usable and different. The changed regions are baseline `[p+1, nb−s]` and failed `[p+1, nf−s]`; an empty region is not cited. Outside them the files are identical |
| `dependency_changed` | both | `section`, `name`, `baseline_spec`?, `failed_spec`?, `baseline_section`?, `failed_section`? | Both manifests usable and parsed, and the spec was added, removed or changed. Cites as `lockfile_root_mismatch` |

The order of emission:

1. Failed run: `log_error_lines`, `exit_code`, `error_step`, `runner_image`, `node_version`, `checkout_sha_shown`, `lockfile_root_mismatch`.
2. Baseline: `runner_image`, `node_version`, `checkout_sha_shown`.
3. Cross-run: `source_*` for `workflow_file`, then `manifest`, then `lockfile`; then `dependency_changed`.

Fields marked `?` are omitted when that side has no entry.

**Semantic parsing** applies only to usable manifests and lockfiles. The text is the included lines joined with LF. A source is parsed only when an observation needs it:

- the failed manifest and lockfile, when both are usable, for `lockfile_root_mismatch`;
- both manifests, when compared and both usable, for `dependency_changed`.

A member name repeated within one object anywhere in the file is a parse failure (`duplicate_key`). So is a dependency name or spec that decodes to a character U+0000–U+001F or U+007F–U+009F (`control_character`). Sources with 0 lines are not diffed.

- **Manifest:** a JSON object. Each section among `dependencies`, `devDependencies` and `optionalDependencies` that is present must be an object of string values.
- **Lockfile:** a JSON object. `lockfileVersion` must be 2 or 3, and `packages[""]` must be an object whose sections follow the manifest rules. The checked sections are the same three.
- **Locating lines:**
  - An entry line is the line of the member name.
  - A section block runs from the line of the section's name to the line of its closing brace.
  - The containing object of a manifest is its top-level object, from the line of its opening brace to the line of its closing brace.
  - The containing object of a lockfile is the `packages[""]` root package object, from the line of its member name `""` to the line of its closing brace.
- **Two-sided evidence rule** for `lockfile_root_mismatch` and `dependency_changed`: each side gets exactly one citation.
  - If the side has the entry: its entry line.
  - If the entry is absent but the side has the section: that side's section block.
  - If the side has no such section at all: that side's whole containing object, which is the complete object needed to inspect the absence. The observation then also carries that side's `*_section` field (`manifest_section`, `lockfile_section`, `baseline_section` or `failed_section`) with the value `absent`. The claim is that the object has no such section; the same name may still appear in it under a different section.
  - So every such observation cites both files. Citations are sorted as usual.

`source_changed` follows a different rule. When the change is a pure insertion or deletion, one side's region is empty and is not cited. `common_prefix_lines` locates the change on that side.

If parsing fails, no semantic observation is made for that source, and a `not_parsed` limitation is recorded.

## 5. Limitations

A limitation records evidence that is missing, omitted, partly read or unresolved, and that prevents a conclusion. They are listed in this order:

1. `no_baseline`, or `comparison_suppressed` (reason `incompatible` or `unknown`).
2. For each run in order:
   - `checkout_unresolved` (reason: the bundle's reason), `checkout_sha_not_in_evidence` or `checkout_evidence_conflict`
   - `matrix_unresolved` (reason: the bundle's reason)
   - `runner_unknown` (reason `os`, `arch` or `os_arch`)
   - `runner_arch_conflict` (row 8's log check failed for this run)
3. For each source in bundle order:
   - `source_missing` (reason: `missing_reason`)
   - otherwise, if present:
     - `source_prefix`
     - `source_partial_lines`, for any kind with omitted ranges. Observations cover included lines only
     - for file kinds: `revision_mismatch` (reason `head_sha` or `checkout_sha`, whichever was expected), or `revision_unverified` (a manifest or lockfile with no expected revision)
4. `error_step_undetermined`, when the failed job log is present but no `error_step` was emitted:
   - reason `no_error_marker` or `no_step_header`
   - or reason `omitted_lines_between`, with `start` = H and `end` = E
5. `not_parsed`, in source order. Reasons:
   - `invalid_json`
   - `not_an_object`
   - `bad_section`
   - `duplicate_key`
   - `control_character`
   - `unsupported_lockfile`

## 6. Verification

`Verify(bundle, result)` checks that a result is exactly the bundle's comparison in every normative value. An example is a result written by another tool. It reports problems in the following order. Each observation gets at most one problem, the first that applies:

1. Bundle and result:
   - no result at all (null) → `result_missing`, checked first and reported alone
   - the bundle is an accepted bundle v1 → `unsupported_schema`, reported alone
   - the bundle is rejected → `bundle_invalid`
   - the result's `bundle_evidence_sha256` differs from the bundle → `bundle_mismatch`
   - `schema`, `evidence_class`, `decision`, the rows' `field`, `outcome` and `effect` (not the display strings), or `limitations` differ from what the bundle gives → `summary_mismatch`
2. Each observation, in order:
   - an unknown `kind` → `unknown_kind`
   - a `run_role` not allowed for that kind → `invalid_run_role`
   - each citation:
     - an undeclared source → `citation_unknown_source`
     - a missing source → `citation_missing_source`
     - a source from another run → `citation_wrong_run` (`both` allows either run)
     - lines outside `1..line_count`, or `start > end` → `citation_out_of_range`
     - any omitted line inside the range → `citation_includes_omitted`
   - an observation that the bundle does not produce exactly, by kind, role, fields and citations → `unsupported_observation`
   - a repeat of an earlier observation → `duplicate_observation`
3. Whole list:
   - each observation the bundle produces but the result lacks → `observation_missing`
   - if nothing else failed but the order differs from section 4 → `observation_order`

A valid citation proves only that the cited lines exist and are included. Support is checked separately, and only for the mechanical kinds above.

## 7. Not covered in v0

- Diffs of files outside the bundle: application source, configuration held in repository settings, and artifacts produced by other jobs.
- Ancestry between the two commits.
- Step conditions and skipped steps.
- Any interpretation of exit codes.
- Any claim that one observation explains another.
