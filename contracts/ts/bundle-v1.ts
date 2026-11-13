// Evidence bundle contract v1 validator (contracts/bundle-v1.md). It shares
// v0's byte limits, strict JSON profile, evaluator-name scan, object
// procedure, line map, span rules and canonical encoding (./bundle.ts); this
// module holds what differs. No dependencies; runs on the type stripping of Node 22.18 or later.

import {
  CHECKOUT_REASONS,
  ContractError,
  JOB_MEMBERS,
  LINE_MEMBERS,
  MATRIX_REASONS,
  MAX_INPUT_BYTES,
  MAX_LINE_BYTES,
  MAX_LINES_PER_SOURCE,
  MAX_OMITTED_PER_SOURCE,
  MAX_SOURCES,
  MISSING_REASONS,
  OMITTED_MEMBERS,
  Obj,
  RE_BRANCH,
  RE_CASE_ID,
  RE_DIGEST,
  RE_ID,
  RE_REPO_NAME,
  RE_SHA,
  RE_WORKFLOW_PATH,
  REQUIRED_KINDS,
  RUN_MEMBERS,
  WORKFLOW_MEMBERS,
  checkCheckout,
  checkLineMap,
  checkMatrix,
  checkRunner,
  checkSpan,
  decodeUtf8,
  evidenceDigestFor,
  findEvaluatorField,
  lastSegment,
  object,
  parseStrict,
  schemaErr,
  utf8Length,
  validRelativePath,
  validTimestamp,
} from "./bundle.ts";
import type { JsonValue, RunDoc, SourceDoc, SpanDoc, ValidationResult } from "./bundle.ts";

export const SCHEMA_VERSION_V1 = "aftergreen.bundle.v1";
export const REDACTION_RULES_V1 = "aftergreen.redaction.1";
const DIGEST_TAG_V1 = "aftergreen.bundle.evidence.v1\n";

const EVIDENCE_MEMBERS_V1 = new Set(["schema", "evidence_class", "collection", "redaction", "runs", "sources"]);
const BUNDLE_MEMBERS_V1 = ["schema", "case_id", "evidence_class", "created_at", "collection", "redaction", "runs", "sources", "evidence_sha256"];
const COLLECTION_MEMBERS_V1 = ["tool", "api_version", "metadata_authentication"];
const REPOSITORY_MEMBERS_V1 = ["id", "full_name", "visibility"];
const SOURCE_MEMBERS_V1 = ["id", "kind", "run_role", "status", "path", "revision", "missing_reason", "extent",
  "received_bytes", "received_sha256", "authentication", "line_count", "redactions", "lines", "omitted"];
const PRESENT_ONLY_V1 = ["extent", "received_bytes", "received_sha256", "authentication", "line_count", "redactions", "lines", "omitted"];
const CHECKOUT_REASONS_V1 = [...CHECKOUT_REASONS, "workflow_not_collected"];
const MATRIX_REASONS_V1 = [...MATRIX_REASONS, "workflow_not_collected"];
const MISSING_REASONS_V1 = [...MISSING_REASONS, "transfer_failed", "redirect_rejected"];
const OMITTED_REASONS_V1 = ["outside_selected_span", "line_too_long", "line_limit", "redacted"];

type SourceDocV1 = SourceDoc & { pathGiven: boolean };
type BundleDocV1 = { run: RunDoc; sources: SourceDocV1[]; evidenceClass: string; redactionStatus: string; digest: string };

/** Validates raw bytes against contract v1 and reports the first failing check. */
export async function validateBundleV1(raw: Uint8Array): Promise<ValidationResult> {
  let root: JsonValue;
  let bundle: BundleDocV1;
  try {
    if (raw.length > MAX_INPUT_BYTES) {
      throw new ContractError("input_too_large", "", `input is ${raw.length} bytes; the limit is ${MAX_INPUT_BYTES}`);
    }
    root = parseStrict(decodeUtf8(raw));
    findEvaluatorField(root, "");
    bundle = checkBundleV1(root);
    crossCheckV1(bundle);
  } catch (e) {
    if (e instanceof ContractError) return { ok: false, code: e.code, pointer: e.pointer, detail: e.message };
    throw e;
  }
  const digest = await evidenceDigestFor(root, DIGEST_TAG_V1, EVIDENCE_MEMBERS_V1);
  if (digest !== bundle.digest) {
    return { ok: false, code: "digest_mismatch", pointer: "/evidence_sha256", detail: `recomputed evidence digest is ${digest}` };
  }
  return { ok: true, evidenceSha256: digest };
}

/** U+0000-U+001F, U+007F or U+0080-U+009F; tab is allowed when allowTab is set. */
function hasControlV1(s: string, allowTab: boolean): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x7f || (c >= 0x80 && c <= 0x9f) || (c < 0x20 && !(allowTab && c === 0x09))) return true;
  }
  return false;
}

function displayV1(o: Obj, name: string): string {
  const s = o.str(name);
  const n = utf8Length(s);
  if (n < 1 || n > 256 || hasControlV1(s, false)) throw schemaErr(o.at(name), "must be 1-256 UTF-8 bytes without control characters");
  return s;
}

function date(o: Obj, name: string): string {
  const s = o.str(name);
  if (s.length !== 10 || !validTimestamp(`${s}T00:00:00Z`)) throw schemaErr(o.at(name), `${JSON.stringify(s)} is not a valid YYYY-MM-DD date`);
  return s;
}

function checkBundleV1(root: JsonValue): BundleDocV1 {
  const o = object(root, "", BUNDLE_MEMBERS_V1, BUNDLE_MEMBERS_V1);
  o.enum("schema", SCHEMA_VERSION_V1);
  o.match("case_id", RE_CASE_ID);
  const evidenceClass = o.enum("evidence_class", "collected_public", "simulated");
  o.timestamp("created_at");
  const col = o.child("collection", COLLECTION_MEMBERS_V1, COLLECTION_MEMBERS_V1);
  col.match("tool", RE_ID);
  date(col, "api_version");
  col.enum("metadata_authentication", "none");
  const redactionStatus = checkRedaction(o);

  const runValues = o.array("runs");
  if (runValues.length !== 1) throw schemaErr(o.at("runs"), `expected exactly 1 run, found ${runValues.length}`);
  const run = checkRunV1(runValues[0], `${o.at("runs")}/0`);

  const sourceValues = o.array("sources");
  if (sourceValues.length > MAX_SOURCES) {
    throw new ContractError("too_many_sources", o.at("sources"), `${sourceValues.length} sources; the limit is ${MAX_SOURCES}`);
  }
  const sources = sourceValues.map((v, i) => checkSourceV1(v, `${o.at("sources")}/${i}`));
  for (let i = 1; i < sources.length; i++) {
    if (sources[i - 1].id >= sources[i].id) throw schemaErr(`${sources[i].ptr}/id`, "source ids must be strictly ascending");
  }
  const digest = o.match("evidence_sha256", RE_DIGEST);
  return { run, sources, evidenceClass, redactionStatus, digest };
}

function checkRedaction(bundle: Obj): string {
  const o = bundle.child("redaction", ["status", "rules"], ["status"]);
  const status = o.enum("status", "applied", "none");
  if (status === "none") {
    o.onlyForm("status");
    return status;
  }
  o.onlyForm("status", "rules");
  o.require("rules");
  o.enum("rules", REDACTION_RULES_V1);
  return status;
}

function checkRunV1(v: JsonValue, ptr: string): RunDoc {
  const o = object(v, ptr, RUN_MEMBERS, RUN_MEMBERS);
  const role = o.enum("role", "failed");
  const repo = o.child("repository", REPOSITORY_MEMBERS_V1, REPOSITORY_MEMBERS_V1);
  const repoId = repo.integer("id", 1);
  const repoName = repo.match("full_name", RE_REPO_NAME);
  repo.enum("visibility", "public");
  const wf = o.child("workflow", WORKFLOW_MEMBERS, WORKFLOW_MEMBERS);
  wf.integer("id", 1);
  const workflowPath = wf.match("path", RE_WORKFLOW_PATH);
  o.integer("run_id", 1);
  o.integer("run_attempt", 1);
  const attemptStarted = o.timestamp("attempt_started_at");
  o.enum("event", "push");
  o.match("branch", RE_BRANCH);
  o.match("head_sha", RE_SHA);
  const job = o.child("job", JOB_MEMBERS, JOB_MEMBERS);
  job.integer("id", 1);
  displayV1(job, "name");
  job.enum("conclusion", "failure");
  const started = job.timestamp("started_at");
  const completed = job.timestamp("completed_at");

  const spanLists: SpanDoc[][] = [checkCheckout(o, CHECKOUT_REASONS_V1)];
  const matrix = checkMatrix(o, MATRIX_REASONS_V1, displayV1);
  if (matrix !== null) spanLists.push(matrix);
  spanLists.push(checkRunner(o));

  if (completed < started) throw schemaErr(job.at("completed_at"), "completed_at is earlier than started_at");
  return { ptr, role, repoId, repoName, workflowPath, attemptStarted, jobCompleted: completed, spanLists };
}

function checkSourceV1(v: JsonValue, ptr: string): SourceDocV1 {
  const o = object(v, ptr, SOURCE_MEMBERS_V1, ["id", "kind", "run_role", "status"]);
  const s: SourceDocV1 = { ptr, id: "", kind: "", runRole: "", present: false, path: "", lineCount: 0, lines: [], omitted: [], pathGiven: false };
  s.id = o.match("id", RE_ID);
  s.kind = o.enum("kind", ...REQUIRED_KINDS);
  s.runRole = o.enum("run_role", "failed");
  s.present = o.enum("status", "present", "missing") === "present";

  if (s.kind === "job_log") {
    for (const name of ["path", "revision"]) {
      if (o.has(name)) throw schemaErr(o.at(name), `${name} is not allowed for a job_log source`);
    }
  } else {
    if (s.present || o.has("path")) {
      s.path = o.str("path");
      s.pathGiven = true;
      let ok = validRelativePath(s.path);
      if (s.kind === "workflow_file") ok = ok && RE_WORKFLOW_PATH.test(s.path);
      else if (s.kind === "manifest") ok = ok && lastSegment(s.path) === "package.json";
      else if (s.kind === "lockfile") ok = ok && lastSegment(s.path) === "package-lock.json";
      if (!ok) throw schemaErr(o.at("path"), `${JSON.stringify(s.path)} is not a valid ${s.kind} path`);
    }
    if (s.present) o.match("revision", RE_SHA);
    else if (o.has("revision")) throw schemaErr(o.at("revision"), "revision is not allowed for a missing source");
  }

  if (!s.present) {
    o.enum("missing_reason", ...MISSING_REASONS_V1);
    for (const name of PRESENT_ONLY_V1) {
      if (o.has(name)) throw schemaErr(o.at(name), `${name} is not allowed for a missing source`);
    }
    return s;
  }

  if (o.has("missing_reason")) throw schemaErr(o.at("missing_reason"), "missing_reason is not allowed for a present source");
  o.enum("extent", "complete", "prefix", "partial");
  o.integer("received_bytes", 0);
  o.match("received_sha256", RE_DIGEST);
  o.enum("authentication", "none", "gh_cli");
  s.lineCount = o.integer("line_count", 0);
  o.integer("redactions", 0);
  const lines = o.array("lines");
  if (lines.length > MAX_LINES_PER_SOURCE) {
    throw new ContractError("too_many_lines", o.at("lines"), `${lines.length} lines; the limit is ${MAX_LINES_PER_SOURCE}`);
  }
  lines.forEach((lv, i) => {
    const ln = object(lv, `${o.at("lines")}/${i}`, LINE_MEMBERS, LINE_MEMBERS);
    const n = ln.integer("n", 0);
    const text = ln.str("text");
    const bytes = utf8Length(text);
    if (bytes > MAX_LINE_BYTES) {
      throw new ContractError("line_too_long", ln.at("text"), `line text is ${bytes} UTF-8 bytes; the limit is ${MAX_LINE_BYTES}`);
    }
    if (hasControlV1(text, true)) throw schemaErr(ln.at("text"), "line text contains a control character other than tab");
    s.lines.push(n);
  });
  const omitted = o.array("omitted");
  if (omitted.length > MAX_OMITTED_PER_SOURCE) {
    throw schemaErr(o.at("omitted"), `${omitted.length} omitted ranges; the limit is ${MAX_OMITTED_PER_SOURCE}`);
  }
  omitted.forEach((ov, i) => {
    const om = object(ov, `${o.at("omitted")}/${i}`, OMITTED_MEMBERS, OMITTED_MEMBERS);
    const start = om.integer("start", 0);
    const end = om.integer("end", 0);
    const reason = om.enum("reason", ...OMITTED_REASONS_V1);
    s.omitted.push({ start, end, reason });
  });
  return s;
}

function crossCheckV1(b: BundleDocV1): void {
  for (const kind of REQUIRED_KINDS) {
    const found = b.sources.filter((s) => s.kind === kind);
    if (found.length === 0) {
      throw new ContractError("missing_source_entry", b.run.ptr, `the run has no ${kind} source; list it with status missing if it was not obtained`);
    }
    if (found.length > 1) throw schemaErr(`${found[1].ptr}/kind`, `the run has more than one ${kind} source`);
  }
  for (const s of b.sources) {
    if (s.kind === "workflow_file" && s.pathGiven && s.path !== b.run.workflowPath) {
      throw schemaErr(`${s.ptr}/path`, `workflow file path differs from the run's workflow path ${JSON.stringify(b.run.workflowPath)}`);
    }
  }
  if (b.evidenceClass === "collected_public" && b.redactionStatus !== "applied") {
    throw schemaErr("/redaction/status", "a collected_public bundle must have redaction applied");
  }
  for (const s of b.sources) {
    if (s.present) checkLineMap(s);
  }
  const byId = new Map<string, SourceDoc>(b.sources.map((s) => [s.id, s]));
  for (const list of b.run.spanLists) {
    for (const sp of list) checkSpan(sp, b.run, byId);
  }
}
