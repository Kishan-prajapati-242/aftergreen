// Aftergreen evidence bundle contract v0: validator and evidence digest.
//
// Normative rules: contracts/bundle-v0.md. Shared cases: contracts/cases.
// The Go validator in contracts/go must agree on every case.
//
// Only erasable TypeScript syntax is used, so the built-in type stripping of
// Node 22.18 or later runs this file directly. Only web-standard APIs are used
// (TextDecoder, TextEncoder, crypto.subtle). No type checker is run; the
// conformance cases are the verification.

export const SCHEMA_VERSION = "aftergreen.bundle.v0";
export const MAX_INPUT_BYTES = 131072; // 128 KiB of raw input
export const MAX_DEPTH = 16;
export const MAX_SOURCES = 20;
export const MAX_LINES_PER_SOURCE = 500;
export const MAX_OMITTED_PER_SOURCE = 501;
export const MAX_LINE_BYTES = 2048;
const MAX_SAFE_INTEGER = 9007199254740991n;
const DIGEST_TAG = "aftergreen.bundle.evidence.v0\n";

// Error codes, in validation-phase order (section 8).
export const ERROR_CODES = [
  "input_too_large",
  "invalid_utf8",
  "invalid_json",
  "nesting_too_deep",
  "duplicate_key",
  "invalid_number",
  "evaluator_field",
  "unknown_field",
  "schema_violation",
  "too_many_sources",
  "too_many_lines",
  "line_too_long",
  "unknown_reference",
  "missing_source_entry",
  "line_map_invalid",
  "span_invalid",
  "digest_mismatch",
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

// code, pointer and evidenceSha256 are normative; detail is informational.
export type ValidationResult =
  | { ok: true; evidenceSha256: string }
  | { ok: false; code: ErrorCode; pointer: string; detail: string };

export type JsonMember = { name: string; value: JsonValue };
export type JsonValue =
  | { kind: "object"; members: JsonMember[] }
  | { kind: "array"; items: JsonValue[] }
  | { kind: "string"; value: string }
  | { kind: "number"; literal: string }
  | { kind: "boolean"; value: boolean }
  | { kind: "null" };

export class ContractError extends Error {
  readonly code: ErrorCode;
  readonly pointer: string;
  constructor(code: ErrorCode, pointer: string, detail: string) {
    super(detail);
    this.code = code;
    this.pointer = pointer;
  }
}

export const schemaErr = (pointer: string, detail: string) => new ContractError("schema_violation", pointer, detail);

const escapePointer = (s: string) => s.replaceAll("~", "~0").replaceAll("/", "~1");

/** Validates raw bundle bytes and reports the first failing check. */
export async function validateBundle(raw: Uint8Array): Promise<ValidationResult> {
  let root: JsonValue;
  let bundle: BundleDoc;
  try {
    if (raw.length > MAX_INPUT_BYTES) {
      throw new ContractError("input_too_large", "", `input is ${raw.length} bytes; the limit is ${MAX_INPUT_BYTES}`);
    }
    root = parseStrict(decodeUtf8(raw));
    findEvaluatorField(root, "");
    bundle = checkBundle(root);
    crossCheck(bundle);
  } catch (e) {
    if (e instanceof ContractError) return { ok: false, code: e.code, pointer: e.pointer, detail: e.message };
    throw e;
  }
  const digest = await evidenceDigest(root);
  if (digest !== bundle.digest) {
    return { ok: false, code: "digest_mismatch", pointer: "/evidence_sha256", detail: `recomputed evidence digest is ${digest}` };
  }
  return { ok: true, evidenceSha256: digest };
}

// --- Section 1: bytes and the strict JSON profile --------------------------

const utf8Decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export function decodeUtf8(raw: Uint8Array): string {
  try {
    return utf8Decoder.decode(raw);
  } catch {
    throw new ContractError("invalid_utf8", "", "input is not well-formed UTF-8");
  }
}

/** Parses exactly one JSON value from already-decoded text. */
export function parseStrict(src: string): JsonValue {
  let pos = 0;
  let depth = 0;
  const syntax = (msg: string) => new ContractError("invalid_json", "", `${msg} at offset ${pos}`);
  const peek = () => (pos < src.length ? src.charCodeAt(pos) : -1);
  const isDigit = (c: number) => c >= 0x30 && c <= 0x39;
  const skipSpace = () => {
    while (pos < src.length) {
      const c = src.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) pos++;
      else return;
    }
  };
  const enter = () => {
    depth++;
    if (depth > MAX_DEPTH) throw new ContractError("nesting_too_deep", "", `more than ${MAX_DEPTH} nested containers at offset ${pos}`);
  };

  const hex4 = (): number => {
    if (pos + 4 > src.length) throw syntax("truncated \\u escape");
    let r = 0;
    for (let i = 0; i < 4; i++) {
      const c = src.charCodeAt(pos + i);
      let d: number;
      if (c >= 0x30 && c <= 0x39) d = c - 0x30;
      else if (c >= 0x61 && c <= 0x66) d = c - 0x61 + 10;
      else if (c >= 0x41 && c <= 0x46) d = c - 0x41 + 10;
      else throw syntax("invalid \\u escape");
      r = (r << 4) | d;
    }
    pos += 4;
    return r;
  };

  const parseString = (): string => {
    pos++; // opening quote
    let out = "";
    let chunk = pos;
    for (;;) {
      if (pos >= src.length) throw syntax("unterminated string");
      const c = src.charCodeAt(pos);
      if (c === 0x22) {
        out += src.slice(chunk, pos);
        pos++;
        return out;
      }
      if (c === 0x5c) {
        out += src.slice(chunk, pos);
        pos++;
        if (pos >= src.length) throw syntax("unterminated escape");
        const e = src.charCodeAt(pos);
        pos++;
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += "\\"; break;
          case 0x2f: out += "/"; break;
          case 0x62: out += "\b"; break;
          case 0x66: out += "\f"; break;
          case 0x6e: out += "\n"; break;
          case 0x72: out += "\r"; break;
          case 0x74: out += "\t"; break;
          case 0x75: {
            const r = hex4();
            if (r >= 0xdc00 && r <= 0xdfff) {
              throw new ContractError("invalid_utf8", "", `unpaired low surrogate escape before offset ${pos}`);
            }
            if (r >= 0xd800 && r <= 0xdbff) {
              if (pos + 1 >= src.length || src.charCodeAt(pos) !== 0x5c || src.charCodeAt(pos + 1) !== 0x75) {
                throw new ContractError("invalid_utf8", "", `unpaired high surrogate escape before offset ${pos}`);
              }
              pos += 2;
              const lo = hex4();
              if (lo < 0xdc00 || lo > 0xdfff) {
                throw new ContractError("invalid_utf8", "", `unpaired high surrogate escape before offset ${pos}`);
              }
              out += String.fromCharCode(r, lo);
            } else {
              out += String.fromCharCode(r);
            }
            break;
          }
          default:
            throw syntax("invalid escape");
        }
        chunk = pos;
        continue;
      }
      if (c < 0x20) throw syntax("unescaped control character in string");
      pos++;
    }
  };

  const parseNumber = (): JsonValue => {
    const start = pos;
    if (peek() === 0x2d) pos++;
    const first = peek();
    if (first === 0x30) pos++;
    else if (first >= 0x31 && first <= 0x39) while (isDigit(peek())) pos++;
    else throw syntax("invalid number");
    if (peek() === 0x2e) {
      pos++;
      if (!isDigit(peek())) throw syntax("invalid number");
      while (isDigit(peek())) pos++;
    }
    if (peek() === 0x65 || peek() === 0x45) {
      pos++;
      if (peek() === 0x2b || peek() === 0x2d) pos++;
      if (!isDigit(peek())) throw syntax("invalid number");
      while (isDigit(peek())) pos++;
    }
    const literal = src.slice(start, pos);
    if (!isCanonicalSafeInteger(literal)) {
      throw new ContractError("invalid_number", "", `number ${literal} is not a non-negative integer of at most ${MAX_SAFE_INTEGER}`);
    }
    return { kind: "number", literal };
  };

  const parseLiteral = (word: string): JsonValue => {
    if (src.slice(pos, pos + word.length) !== word) throw syntax("invalid literal");
    pos += word.length;
    if (word === "null") return { kind: "null" };
    return { kind: "boolean", value: word === "true" };
  };

  const parseObject = (): JsonValue => {
    enter();
    pos++; // '{'
    const members: JsonMember[] = [];
    skipSpace();
    if (peek() === 0x7d) {
      pos++;
      depth--;
      return { kind: "object", members };
    }
    const seen = new Set<string>();
    for (;;) {
      skipSpace();
      if (peek() !== 0x22) throw syntax("expected a member name");
      const name = parseString();
      if (seen.has(name)) throw new ContractError("duplicate_key", "", `member name ${JSON.stringify(name)} repeated at offset ${pos}`);
      seen.add(name);
      skipSpace();
      if (peek() !== 0x3a) throw syntax("expected ':'");
      pos++;
      skipSpace();
      const value = parseValue();
      members.push({ name, value });
      skipSpace();
      const c = peek();
      if (c === 0x2c) {
        pos++;
      } else if (c === 0x7d) {
        pos++;
        depth--;
        return { kind: "object", members };
      } else {
        throw syntax("expected ',' or '}'");
      }
    }
  };

  const parseArray = (): JsonValue => {
    enter();
    pos++; // '['
    const items: JsonValue[] = [];
    skipSpace();
    if (peek() === 0x5d) {
      pos++;
      depth--;
      return { kind: "array", items };
    }
    for (;;) {
      skipSpace();
      items.push(parseValue());
      skipSpace();
      const c = peek();
      if (c === 0x2c) {
        pos++;
      } else if (c === 0x5d) {
        pos++;
        depth--;
        return { kind: "array", items };
      } else {
        throw syntax("expected ',' or ']'");
      }
    }
  };

  const parseValue = (): JsonValue => {
    if (pos >= src.length) throw syntax("unexpected end of input");
    const c = src.charCodeAt(pos);
    if (c === 0x7b) return parseObject();
    if (c === 0x5b) return parseArray();
    if (c === 0x22) return { kind: "string", value: parseString() };
    if (c === 0x2d || isDigit(c)) return parseNumber();
    if (c === 0x74) return parseLiteral("true");
    if (c === 0x66) return parseLiteral("false");
    if (c === 0x6e) return parseLiteral("null");
    throw syntax("unexpected character");
  };

  skipSpace();
  const value = parseValue();
  skipSpace();
  if (pos !== src.length) throw syntax("unexpected data after the top-level value");
  return value;
}

function isCanonicalSafeInteger(literal: string): boolean {
  if (literal.length === 0 || literal.length > 16) return false;
  if (literal.charCodeAt(0) === 0x30) return literal === "0";
  for (let i = 0; i < literal.length; i++) {
    const c = literal.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return BigInt(literal) <= MAX_SAFE_INTEGER;
}

/** UTF-8 byte length of a well-formed string (the parser rejects lone surrogates). */
export function utf8Length(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      n += 4;
      i++;
    } else n += 3;
  }
  return n;
}

// --- Section 2: evaluator-only member names --------------------------------

const RESERVED_NAMES = new Set([
  "acceptable_hypotheses", "answer", "answers", "baseline_applicability",
  "diagnosis", "expected", "fix", "gold", "ground_truth", "injected_fault",
  "repair", "root_cause", "supporting_spans", "unsupported_claims",
  "verified_outcome", "verified_repair",
]);
const RESERVED_PREFIXES = ["expected_", "gold_", "eval_", "evaluator_"];

const isReserved = (name: string) => RESERVED_NAMES.has(name) || RESERVED_PREFIXES.some((p) => name.startsWith(p));

export function findEvaluatorField(v: JsonValue, ptr: string): void {
  if (v.kind === "object") {
    for (const m of v.members) {
      const child = `${ptr}/${escapePointer(m.name)}`;
      if (isReserved(m.name)) {
        throw new ContractError("evaluator_field", child, `evaluator-only member ${JSON.stringify(m.name)} is not allowed in an input bundle`);
      }
      findEvaluatorField(m.value, child);
    }
  } else if (v.kind === "array") {
    v.items.forEach((item, i) => findEvaluatorField(item, `${ptr}/${i}`));
  }
}

// --- Section 3: objects and members ----------------------------------------

export const RE_CASE_ID = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const RE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const RE_SHA = /^[0-9a-f]{40}$/;
export const RE_DIGEST = /^[0-9a-f]{64}$/;
export const RE_REPO_NAME = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
export const RE_WORKFLOW_PATH = /^\.github\/workflows\/[A-Za-z0-9._-]{1,100}\.ya?ml$/;
export const RE_BRANCH = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/;
const RE_LABEL = /^[A-Za-z0-9._-]{1,64}$/;
const RE_MATRIX_KEY = /^[A-Za-z0-9_-]{1,64}$/;
const RE_SEGMENT = /^[A-Za-z0-9._-]+$/;

const BUNDLE_MEMBERS = ["schema", "case_id", "evidence_class", "created_at", "redaction", "runs", "sources", "evidence_sha256"];
export const RUN_MEMBERS = ["role", "repository", "workflow", "run_id", "run_attempt", "attempt_started_at", "event", "branch", "head_sha", "job", "checkout", "matrix", "runner"];
const REPOSITORY_MEMBERS = ["id", "full_name"];
export const WORKFLOW_MEMBERS = ["id", "path"];
export const JOB_MEMBERS = ["id", "name", "conclusion", "started_at", "completed_at"];
const RUNNER_MEMBERS = ["os", "arch", "labels", "evidence"];
const SPAN_MEMBERS = ["source_id", "start", "end"];
const MATRIX_VALUE_MEMBERS = ["key", "value"];
const SOURCE_MEMBERS = ["id", "kind", "run_role", "status", "path", "revision", "missing_reason", "extent", "line_count", "lines", "omitted"];
export const LINE_MEMBERS = ["n", "text"];
export const OMITTED_MEMBERS = ["start", "end", "reason"];

export const CHECKOUT_REASONS = ["dynamic_ref", "multiple_checkouts", "log_missing", "reusable_workflow", "output_unverifiable", "no_checkout_step"];
export const MATRIX_REASONS = ["custom_job_name", "log_missing", "ambiguous"];
export const MISSING_REASONS = ["expired", "not_found", "too_large", "limit_reached", "access_denied", "not_collected"];
const OMITTED_REASONS = ["outside_selected_span", "line_too_long", "line_limit"]; // "redacted" is reserved; v0 has no redaction
export const REQUIRED_KINDS = ["job_log", "workflow_file", "manifest", "lockfile"];

export type SpanDoc = { ptr: string; sourceId: string; start: number; end: number };
export type RunDoc = {
  ptr: string;
  role: string;
  repoId: number;
  repoName: string;
  workflowPath: string;
  attemptStarted: string;
  jobCompleted: string;
  spanLists: SpanDoc[][];
};
export type RangeDoc = { start: number; end: number; reason: string };
export type SourceDoc = {
  ptr: string;
  id: string;
  kind: string;
  runRole: string;
  present: boolean;
  path: string;
  lineCount: number;
  lines: number[]; // original line numbers of included lines
  omitted: RangeDoc[];
};
type BundleDoc = { runs: RunDoc[]; sources: SourceDoc[]; digest: string };

/** An object whose member names have been checked. */
export class Obj {
  readonly ptr: string;
  readonly order: JsonMember[];
  readonly members: Map<string, JsonValue>;

  constructor(ptr: string, order: JsonMember[], members: Map<string, JsonValue>) {
    this.ptr = ptr;
    this.order = order;
    this.members = members;
  }

  at(name: string): string {
    return `${this.ptr}/${name}`;
  }

  has(name: string): boolean {
    return this.members.has(name);
  }

  require(...names: string[]): void {
    for (const name of names) {
      if (!this.has(name)) throw schemaErr(this.at(name), `required member ${JSON.stringify(name)} is missing`);
    }
  }

  /** Reports the first member, in document order, that the selected form does not allow. */
  onlyForm(...allowed: string[]): void {
    for (const m of this.order) {
      if (!allowed.includes(m.name)) throw schemaErr(this.at(m.name), `member ${JSON.stringify(m.name)} is not allowed in this form`);
    }
  }

  get(name: string): JsonValue {
    const v = this.members.get(name);
    if (v === undefined) throw schemaErr(this.at(name), `required member ${JSON.stringify(name)} is missing`);
    return v;
  }

  str(name: string): string {
    const v = this.get(name);
    if (v.kind !== "string") throw schemaErr(this.at(name), `expected a string, found ${v.kind}`);
    return v.value;
  }

  integer(name: string, min: number): number {
    const v = this.get(name);
    if (v.kind !== "number") throw schemaErr(this.at(name), `expected an integer, found ${v.kind}`);
    const n = Number(v.literal); // exact: the parser guarantees 0..2^53-1
    if (n < min) throw schemaErr(this.at(name), `must be at least ${min}`);
    return n;
  }

  enum(name: string, ...allowed: string[]): string {
    const s = this.str(name);
    if (!allowed.includes(s)) throw schemaErr(this.at(name), `${JSON.stringify(s)} is not one of ${allowed.join(", ")}`);
    return s;
  }

  match(name: string, re: RegExp): string {
    const s = this.str(name);
    if (!re.test(s)) throw schemaErr(this.at(name), `${JSON.stringify(s)} does not match ${re.source}`);
    return s;
  }

  timestamp(name: string): string {
    const s = this.str(name);
    if (!validTimestamp(s)) throw schemaErr(this.at(name), `${JSON.stringify(s)} is not a valid YYYY-MM-DDTHH:MM:SSZ timestamp`);
    return s;
  }

  display(name: string): string {
    const s = this.str(name);
    const n = utf8Length(s);
    if (n < 1 || n > 256 || hasControl(s, false)) throw schemaErr(this.at(name), "must be 1-256 UTF-8 bytes without control characters");
    return s;
  }

  array(name: string): JsonValue[] {
    const v = this.get(name);
    if (v.kind !== "array") throw schemaErr(this.at(name), `expected an array, found ${v.kind}`);
    return v.items;
  }

  child(name: string, allowed: string[], required: string[]): Obj {
    return object(this.get(name), this.at(name), allowed, required);
  }
}

export function object(v: JsonValue, ptr: string, allowed: string[], required: string[]): Obj {
  if (v.kind !== "object") throw schemaErr(ptr, `expected an object, found ${v.kind}`);
  const members = new Map<string, JsonValue>();
  for (const m of v.members) {
    if (!allowed.includes(m.name)) {
      throw new ContractError("unknown_field", `${ptr}/${escapePointer(m.name)}`, `member ${JSON.stringify(m.name)} is not allowed here`);
    }
    members.set(m.name, m.value);
  }
  const o = new Obj(ptr, v.members, members);
  o.require(...required);
  return o;
}

/** U+0000-U+001F or U+007F; tab is allowed in line text. */
function hasControl(s: string, allowTab: boolean): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x7f || (c < 0x20 && !(allowTab && c === 0x09))) return true;
  }
  return false;
}

export function validTimestamp(s: string): boolean {
  if (s.length !== 20) return false;
  for (let i = 0; i < 20; i++) {
    const c = s.charCodeAt(i);
    if (i === 4 || i === 7) {
      if (c !== 0x2d) return false;
    } else if (i === 10) {
      if (c !== 0x54) return false;
    } else if (i === 13 || i === 16) {
      if (c !== 0x3a) return false;
    } else if (i === 19) {
      if (c !== 0x5a) return false;
    } else if (c < 0x30 || c > 0x39) {
      return false;
    }
  }
  const num = (a: number, b: number) => Number(s.slice(a, b));
  const year = num(0, 4), month = num(5, 7), day = num(8, 10);
  const hour = num(11, 13), minute = num(14, 16), second = num(17, 19);
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) return false;
  return hour <= 23 && minute <= 59 && second <= 59;
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return month === 4 || month === 6 || month === 9 || month === 11 ? 30 : 31;
}

export function validRelativePath(p: string): boolean {
  const n = utf8Length(p);
  if (n < 1 || n > 256) return false;
  return p.split("/").every((seg) => seg !== "." && seg !== ".." && RE_SEGMENT.test(seg));
}

export const lastSegment = (p: string) => p.slice(p.lastIndexOf("/") + 1);

function checkBundle(root: JsonValue): BundleDoc {
  const o = object(root, "", BUNDLE_MEMBERS, BUNDLE_MEMBERS);
  o.enum("schema", SCHEMA_VERSION);
  o.match("case_id", RE_CASE_ID);
  o.enum("evidence_class", "simulated");
  o.timestamp("created_at");
  o.enum("redaction", "none");

  const runValues = o.array("runs");
  if (runValues.length < 1 || runValues.length > 2) throw schemaErr(o.at("runs"), `expected 1 or 2 runs, found ${runValues.length}`);
  const runs = runValues.map((v, i) => checkRun(v, `${o.at("runs")}/${i}`));
  runs.forEach((r, i) => {
    const want = i === 1 ? "baseline" : "failed";
    if (r.role !== want) throw schemaErr(`${r.ptr}/role`, `runs[${i}] must have role ${JSON.stringify(want)}`);
  });

  const sourceValues = o.array("sources");
  if (sourceValues.length > MAX_SOURCES) {
    throw new ContractError("too_many_sources", o.at("sources"), `${sourceValues.length} sources; the limit is ${MAX_SOURCES}`);
  }
  const sources = sourceValues.map((v, i) => checkSource(v, `${o.at("sources")}/${i}`));
  for (let i = 1; i < sources.length; i++) {
    if (sources[i - 1].id >= sources[i].id) throw schemaErr(`${sources[i].ptr}/id`, "source ids must be strictly ascending");
  }

  const digest = o.match("evidence_sha256", RE_DIGEST);
  return { runs, sources, digest };
}

function checkRun(v: JsonValue, ptr: string): RunDoc {
  const o = object(v, ptr, RUN_MEMBERS, RUN_MEMBERS);
  const role = o.enum("role", "failed", "baseline");
  const repo = o.child("repository", REPOSITORY_MEMBERS, REPOSITORY_MEMBERS);
  const repoId = repo.integer("id", 1);
  const repoName = repo.match("full_name", RE_REPO_NAME);
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
  job.display("name");
  const conclusion = job.enum("conclusion", "failure", "success");
  const started = job.timestamp("started_at");
  const completed = job.timestamp("completed_at");

  const spanLists: SpanDoc[][] = [checkCheckout(o)];
  const matrix = checkMatrix(o);
  if (matrix !== null) spanLists.push(matrix);
  spanLists.push(checkRunner(o));

  const want = role === "baseline" ? "success" : "failure";
  if (conclusion !== want) throw schemaErr(job.at("conclusion"), `a ${role} run's job must have conclusion ${JSON.stringify(want)}`);
  if (completed < started) throw schemaErr(job.at("completed_at"), "completed_at is earlier than started_at");
  return { ptr, role, repoId, repoName, workflowPath, attemptStarted, jobCompleted: completed, spanLists };
}

export function checkCheckout(run: Obj, reasons: string[] = CHECKOUT_REASONS): SpanDoc[] {
  const o = run.child("checkout", ["status", "sha", "reason", "evidence"], ["status"]);
  const status = o.enum("status", "resolved", "unresolved");
  if (status === "resolved") {
    o.onlyForm("status", "sha", "evidence");
    o.require("sha", "evidence");
    o.match("sha", RE_SHA);
    return spans(o, "evidence", 1, 4);
  }
  o.onlyForm("status", "reason", "evidence");
  o.require("reason", "evidence");
  o.enum("reason", ...reasons);
  return spans(o, "evidence", 0, 4);
}

/** Returns the matrix evidence spans, or null for status "none". v1 passes its own display-string rule. */
export function checkMatrix(run: Obj, reasons: string[] = MATRIX_REASONS, display: (o: Obj, name: string) => string = (o, name) => o.display(name)): SpanDoc[] | null {
  const o = run.child("matrix", ["status", "values", "reason", "evidence"], ["status"]);
  const status = o.enum("status", "none", "resolved", "unresolved");
  if (status === "none") {
    o.onlyForm("status");
    return null;
  }
  if (status === "resolved") {
    o.onlyForm("status", "values", "evidence");
    o.require("values", "evidence");
    const items = o.array("values");
    if (items.length < 1 || items.length > 8) throw schemaErr(o.at("values"), `expected 1 to 8 matrix values, found ${items.length}`);
    const keys = items.map((item, i) => {
      const mv = object(item, `${o.at("values")}/${i}`, MATRIX_VALUE_MEMBERS, MATRIX_VALUE_MEMBERS);
      const key = mv.match("key", RE_MATRIX_KEY);
      display(mv, "value");
      return key;
    });
    for (let i = 1; i < keys.length; i++) {
      if (keys[i - 1] >= keys[i]) throw schemaErr(`${o.at("values")}/${i}/key`, "matrix keys must be strictly ascending");
    }
    return spans(o, "evidence", 0, 4);
  }
  o.onlyForm("status", "reason", "evidence");
  o.require("reason", "evidence");
  o.enum("reason", ...reasons);
  return spans(o, "evidence", 0, 4);
}

export function checkRunner(run: Obj): SpanDoc[] {
  const o = run.child("runner", RUNNER_MEMBERS, RUNNER_MEMBERS);
  o.enum("os", "Linux", "Windows", "macOS", "unknown");
  o.enum("arch", "X64", "ARM64", "X86", "ARM", "unknown");
  const labels = o.array("labels");
  if (labels.length > 10) throw schemaErr(o.at("labels"), `at most 10 labels, found ${labels.length}`);
  labels.forEach((l, i) => {
    if (l.kind !== "string" || !RE_LABEL.test(l.value)) throw schemaErr(`${o.at("labels")}/${i}`, `labels must be strings matching ${RE_LABEL.source}`);
  });
  return spans(o, "evidence", 0, 4);
}

function spans(o: Obj, name: string, min: number, max: number): SpanDoc[] {
  const items = o.array(name);
  if (items.length < min || items.length > max) throw schemaErr(o.at(name), `expected ${min} to ${max} spans, found ${items.length}`);
  return items.map((item, i) => {
    const sp = object(item, `${o.at(name)}/${i}`, SPAN_MEMBERS, SPAN_MEMBERS);
    const sourceId = sp.match("source_id", RE_ID);
    const start = sp.integer("start", 0);
    const end = sp.integer("end", 0);
    return { ptr: sp.ptr, sourceId, start, end };
  });
}

function checkSource(v: JsonValue, ptr: string): SourceDoc {
  const o = object(v, ptr, SOURCE_MEMBERS, ["id", "kind", "run_role", "status"]);
  const s: SourceDoc = { ptr, id: "", kind: "", runRole: "", present: false, path: "", lineCount: 0, lines: [], omitted: [] };
  s.id = o.match("id", RE_ID);
  s.kind = o.enum("kind", ...REQUIRED_KINDS);
  s.runRole = o.enum("run_role", "failed", "baseline");
  const status = o.enum("status", "present", "missing");

  if (s.kind === "job_log") {
    for (const name of ["path", "revision"]) {
      if (o.has(name)) throw schemaErr(o.at(name), `${name} is not allowed for a job_log source`);
    }
  } else {
    s.path = o.str("path");
    let ok = validRelativePath(s.path);
    if (s.kind === "workflow_file") ok = ok && RE_WORKFLOW_PATH.test(s.path);
    else if (s.kind === "manifest") ok = ok && lastSegment(s.path) === "package.json";
    else if (s.kind === "lockfile") ok = ok && lastSegment(s.path) === "package-lock.json";
    if (!ok) throw schemaErr(o.at("path"), `${JSON.stringify(s.path)} is not a valid ${s.kind} path`);
    o.match("revision", RE_SHA);
  }

  if (status === "missing") {
    o.enum("missing_reason", ...MISSING_REASONS);
    for (const name of ["extent", "line_count", "lines", "omitted"]) {
      if (o.has(name)) throw schemaErr(o.at(name), `${name} is not allowed for a missing source`);
    }
    return s;
  }

  s.present = true;
  if (o.has("missing_reason")) throw schemaErr(o.at("missing_reason"), "missing_reason is not allowed for a present source");
  o.enum("extent", "complete", "prefix");
  s.lineCount = o.integer("line_count", 0);
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
    if (hasControl(text, true)) throw schemaErr(ln.at("text"), "line text contains a control character other than tab");
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
    const reason = om.enum("reason", ...OMITTED_REASONS);
    s.omitted.push({ start, end, reason });
  });
  return s;
}

// --- Section 6: cross-checks -----------------------------------------------

function crossCheck(b: BundleDoc): void {
  if (b.runs.length === 2 && (b.runs[0].repoId !== b.runs[1].repoId || b.runs[0].repoName !== b.runs[1].repoName)) {
    throw schemaErr(`${b.runs[1].ptr}/repository`, "both runs must use the same repository");
  }
  if (b.runs.length === 2 && b.runs[1].jobCompleted >= b.runs[0].attemptStarted) {
    throw schemaErr(`${b.runs[1].ptr}/job/completed_at`, `the baseline job must complete before the failed attempt started at ${b.runs[0].attemptStarted}`);
  }
  const roles = new Set(b.runs.map((r) => r.role));
  for (const s of b.sources) {
    if (!roles.has(s.runRole)) throw new ContractError("unknown_reference", `${s.ptr}/run_role`, `no run has role ${JSON.stringify(s.runRole)}`);
  }
  for (const r of b.runs) {
    for (const kind of REQUIRED_KINDS) {
      const found = b.sources.filter((s) => s.runRole === r.role && s.kind === kind);
      if (found.length === 0) {
        throw new ContractError("missing_source_entry", r.ptr, `the ${r.role} run has no ${kind} source; list it with status missing if it could not be obtained`);
      }
      if (found.length > 1) throw schemaErr(`${found[1].ptr}/kind`, `the ${r.role} run has more than one ${kind} source`);
    }
  }
  for (const r of b.runs) {
    for (const s of b.sources) {
      if (s.runRole === r.role && s.kind === "workflow_file" && s.path !== r.workflowPath) {
        throw schemaErr(`${s.ptr}/path`, `workflow file path differs from the run's workflow path ${JSON.stringify(r.workflowPath)}`);
      }
    }
  }
  for (const s of b.sources) {
    if (s.present) checkLineMap(s);
  }
  const byId = new Map(b.sources.map((s) => [s.id, s]));
  for (const r of b.runs) {
    for (const list of r.spanLists) {
      for (const sp of list) checkSpan(sp, r, byId);
    }
  }
}

export function checkLineMap(s: SourceDoc): void {
  const linePtr = (k: number) => `${s.ptr}/lines/${k}/n`;
  const rangePtr = (k: number, field: string) => `${s.ptr}/omitted/${k}/${field}`;
  const fail = (pointer: string, detail: string) => new ContractError("line_map_invalid", pointer, detail);
  for (let k = 1; k < s.lines.length; k++) {
    if (s.lines[k] <= s.lines[k - 1]) throw fail(linePtr(k), "line numbers must be strictly ascending");
  }
  s.omitted.forEach((r, k) => {
    if (r.start > r.end) throw fail(rangePtr(k, "end"), "omitted range ends before it starts");
    if (k > 0) {
      const prev = s.omitted[k - 1];
      if (r.start <= prev.start) throw fail(rangePtr(k, "start"), "omitted ranges must be in ascending order");
      if (prev.end + 1 === r.start && prev.reason === r.reason) throw fail(rangePtr(k, "reason"), "adjacent omitted ranges must have different reasons");
    }
  });
  let next = 1;
  let li = 0;
  let oi = 0;
  while (li < s.lines.length || oi < s.omitted.length) {
    let start: number;
    let end: number;
    let ptr: string;
    if (li < s.lines.length && (oi >= s.omitted.length || s.lines[li] <= s.omitted[oi].start)) {
      start = s.lines[li];
      end = start;
      ptr = linePtr(li);
      li++;
    } else {
      start = s.omitted[oi].start;
      end = s.omitted[oi].end;
      ptr = rangePtr(oi, "start");
      oi++;
    }
    if (start !== next) throw fail(ptr, `expected line ${next} next, found ${start}`);
    next = end + 1;
  }
  if (next !== s.lineCount + 1) throw fail(`${s.ptr}/line_count`, `lines and omitted ranges cover 1..${next - 1}, not 1..${s.lineCount}`);
}

export function checkSpan(sp: SpanDoc, r: RunDoc, byId: Map<string, SourceDoc>): void {
  const src = byId.get(sp.sourceId);
  const invalid = (pointer: string, detail: string) => new ContractError("span_invalid", pointer, detail);
  if (src === undefined) throw new ContractError("unknown_reference", `${sp.ptr}/source_id`, `no source has id ${JSON.stringify(sp.sourceId)}`);
  if (!src.present) throw invalid(`${sp.ptr}/source_id`, `source ${JSON.stringify(sp.sourceId)} is missing`);
  if (src.runRole !== r.role) throw invalid(`${sp.ptr}/source_id`, `source ${JSON.stringify(sp.sourceId)} belongs to the ${src.runRole} run`);
  if (sp.start < 1) throw invalid(`${sp.ptr}/start`, "start must be at least 1");
  if (sp.end < sp.start) throw invalid(`${sp.ptr}/end`, "end is before start");
  if (sp.end > src.lineCount) throw invalid(`${sp.ptr}/end`, `end is beyond line_count ${src.lineCount}`);
  const included = src.lines.filter((n) => n >= sp.start && n <= sp.end).length;
  if (included !== sp.end - sp.start + 1) {
    throw invalid(sp.ptr, `lines ${sp.start}-${sp.end} of ${JSON.stringify(sp.sourceId)} are not all included`);
  }
}

// --- Section 7: evidence digest --------------------------------------------

const utf8Encoder = new TextEncoder();
const EVIDENCE_MEMBERS = new Set(["schema", "evidence_class", "runs", "sources"]);

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/** Length-prefixed canonical encoding of a parsed value (section 7). */
export function canonicalEncode(v: JsonValue): Uint8Array {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const push = (b: Uint8Array) => {
    chunks.push(b);
    total += b.length;
  };
  const ascii = (s: string) => push(utf8Encoder.encode(s));
  const string = (bytes: Uint8Array) => {
    ascii(`s${bytes.length}:`);
    push(bytes);
  };
  const walk = (x: JsonValue): void => {
    switch (x.kind) {
      case "object": {
        const members = x.members.map((m) => ({ key: utf8Encoder.encode(m.name), value: m.value }));
        members.sort((a, b) => compareBytes(a.key, b.key));
        ascii("d");
        for (const m of members) {
          string(m.key);
          walk(m.value);
        }
        ascii("e");
        return;
      }
      case "array":
        ascii("l");
        for (const item of x.items) walk(item);
        ascii("e");
        return;
      case "string":
        string(utf8Encoder.encode(x.value));
        return;
      case "number":
        ascii(`i${x.literal}e`);
        return;
      default:
        throw new Error(`${x.kind} values have no canonical encoding`);
    }
  };
  walk(v);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** Digest of a bundle that passed checkBundle; file metadata is excluded. */
async function evidenceDigest(root: JsonValue): Promise<string> {
  return evidenceDigestFor(root, DIGEST_TAG, EVIDENCE_MEMBERS);
}

/** SHA-256 of tag followed by the canonical encoding of root's members named in members. */
export async function evidenceDigestFor(root: JsonValue, tagText: string, members: Set<string>): Promise<string> {
  if (root.kind !== "object") throw new Error("unreachable: root is not an object");
  const evidence: JsonValue = { kind: "object", members: root.members.filter((m) => members.has(m.name)) };
  const tag = utf8Encoder.encode(tagText);
  const body = canonicalEncode(evidence);
  const input = new Uint8Array(tag.length + body.length);
  input.set(tag, 0);
  input.set(body, tag.length);
  return sha256Hex(input);
}
