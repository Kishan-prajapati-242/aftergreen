// Shared v1 conformance cases (contracts/cases-v1/manifest.json). The Go
// suite reads the same file and must agree on acceptance, error code, JSON
// Pointer and digest. Run from the repository root:
//   node --test contracts/ts/bundle-v1.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ERROR_CODES, validateBundle } from "./bundle.ts";
import { SCHEMA_VERSION_V1, validateBundleV1 } from "./bundle-v1.ts";

const here = dirname(fileURLToPath(import.meta.url));
const casesDirV1 = join(here, "..", "cases-v1");
const casesDirV0 = join(here, "..", "cases");

type Json = any;

function onlyKeys(obj: Json, allowed: string[], where: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) throw new Error(`${where}: unknown manifest key ${JSON.stringify(key)}`);
  }
}

function loadManifest(dir: string, schema: string, contract: string, topKeys: string[]): Json {
  const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  onlyKeys(m, topKeys, "manifest");
  if (m.schema !== schema || m.contract !== contract) throw new Error(`unexpected manifest schema ${m.schema} / contract ${m.contract}`);
  for (const c of m.cases) {
    onlyKeys(c, ["id", "note", "input", "expect"], c.id);
    onlyKeys(c.input, ["file", "base", "raw", "raw_hex", "replace", "pad_to_bytes"], `${c.id} input`);
    onlyKeys(c.expect, ["result", "code", "pointer", "evidence_sha256"], `${c.id} expect`);
    for (const op of c.input.replace ?? []) {
      onlyKeys(op, ["find", "with", "with_hex", "with_repeat"], `${c.id} replace`);
      if (op.with_repeat) onlyKeys(op.with_repeat, ["item", "count", "separator"], `${c.id} with_repeat`);
    }
  }
  return m;
}

function countOccurrences(hay: Buffer, needle: Buffer): number {
  let n = 0;
  for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + needle.length)) n++;
  return n;
}

function applyReplace(data: Buffer, op: Json): Buffer {
  const find = Buffer.from(op.find, "utf8");
  const n = countOccurrences(data, find);
  if (n !== 1 || find.length === 0) throw new Error(`replace: find occurs ${n} times: ${JSON.stringify(op.find.slice(0, 60))}`);
  const forms = ["with", "with_hex", "with_repeat"].filter((k) => op[k] !== undefined);
  if (forms.length !== 1) throw new Error("replace needs exactly one of with, with_hex, with_repeat");
  let replacement: Buffer;
  if (op.with !== undefined) replacement = Buffer.from(op.with, "utf8");
  else if (op.with_hex !== undefined) replacement = Buffer.from(op.with_hex, "hex");
  else replacement = Buffer.from(Array(op.with_repeat.count).fill(op.with_repeat.item).join(op.with_repeat.separator), "utf8");
  const at = data.indexOf(find);
  return Buffer.concat([data.subarray(0, at), replacement, data.subarray(at + find.length)]);
}

// Follows contracts/README.md exactly; the Go harness implements the same rules.
function buildInput(dir: string, input: Json): Uint8Array {
  const forms = [input.file !== undefined, input.base !== undefined, input.raw !== undefined, input.raw_hex !== undefined].filter(Boolean).length;
  if (forms !== 1) throw new Error("input needs exactly one of file, base, raw, raw_hex");
  if (input.base === undefined && (input.replace !== undefined || input.pad_to_bytes !== undefined)) {
    throw new Error("replace and pad_to_bytes are only allowed with base");
  }
  const read = (name: string) => {
    if (/[/\\]/.test(name)) throw new Error(`case file ${JSON.stringify(name)} must be a plain file name`);
    return readFileSync(join(dir, name));
  };
  let data: Buffer;
  if (input.file !== undefined) data = read(input.file);
  else if (input.base !== undefined) data = read(input.base);
  else if (input.raw !== undefined) data = Buffer.from(input.raw, "utf8");
  else data = Buffer.from(input.raw_hex, "hex");
  for (const op of input.replace ?? []) data = applyReplace(data, op);
  if (input.pad_to_bytes !== undefined) {
    if (data.length > input.pad_to_bytes) throw new Error(`input is already ${data.length} bytes, more than pad_to_bytes ${input.pad_to_bytes}`);
    data = Buffer.concat([data, Buffer.alloc(input.pad_to_bytes - data.length, 0x20)]);
  }
  return new Uint8Array(data);
}

const manifest = loadManifest(casesDirV1, "aftergreen.bundle-cases.v1", SCHEMA_VERSION_V1, ["schema", "contract", "cases"]);

test("v1 manifest covers every error code", () => {
  const seen = new Set<string>();
  const expected = new Set<string>();
  for (const c of manifest.cases) {
    assert.ok(!seen.has(c.id), `duplicate case id ${c.id}`);
    seen.add(c.id);
    if (c.expect.result === "accept") {
      assert.ok(c.expect.code === undefined && c.expect.pointer === undefined && /^[0-9a-f]{64}$/.test(c.expect.evidence_sha256), `${c.id}: an accept case needs only evidence_sha256`);
    } else {
      assert.equal(c.expect.result, "reject", `${c.id}: unknown expected result`);
      assert.ok((ERROR_CODES as readonly string[]).includes(c.expect.code) && c.expect.evidence_sha256 === undefined, `${c.id}: unknown expected code or stray digest`);
      expected.add(c.expect.code);
    }
  }
  for (const code of ERROR_CODES) assert.ok(expected.has(code), `no v1 case expects error code ${code}`);
});

for (const c of manifest.cases) {
  test(`v1 case ${c.id}`, async () => {
    const got = await validateBundleV1(buildInput(casesDirV1, c.input));
    if (c.expect.result === "accept") {
      assert.ok(got.ok, got.ok ? "" : `rejected with ${got.code} at ${JSON.stringify(got.pointer)} (${got.detail}); want accept`);
      assert.equal(got.evidenceSha256, c.expect.evidence_sha256);
      return;
    }
    assert.ok(!got.ok, got.ok ? `accepted with digest ${got.evidenceSha256}; want ${c.expect.code}` : "");
    assert.deepEqual({ code: got.code, pointer: got.pointer }, { code: c.expect.code, pointer: c.expect.pointer ?? "" }, `detail: ${got.detail}`);
  });
}

// Negative control: v1 is not v0, and v0 is not v1.
test("v0 rejects every accepted v1 case, and v1 rejects every accepted v0 case", async () => {
  for (const c of manifest.cases) {
    if (c.expect.result !== "accept") continue;
    const got = await validateBundle(buildInput(casesDirV1, c.input));
    assert.deepEqual(got.ok ? { ok: true } : { code: got.code, pointer: got.pointer }, { code: "unknown_field", pointer: "/collection" }, c.id);
  }
  const v0 = loadManifest(casesDirV0, "aftergreen.bundle-cases.v0", "aftergreen.bundle.v0", ["schema", "contract", "cases", "canonical_vectors"]);
  for (const c of v0.cases) {
    if (c.expect.result !== "accept") continue;
    const got = await validateBundleV1(buildInput(casesDirV0, c.input));
    assert.ok(!got.ok, `${c.id}: a v0 bundle was accepted as v1`);
  }
});
