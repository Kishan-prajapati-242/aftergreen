// Shared conformance cases (contracts/cases/manifest.json). The Go suite in
// contracts/go reads the same file and must agree on every case.
// Run from the repository root: node --test contracts/ts/bundle.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ERROR_CODES, SCHEMA_VERSION, canonicalEncode, parseStrict, sha256Hex, validateBundle } from "./bundle.ts";

const casesDir = join(dirname(fileURLToPath(import.meta.url)), "..", "cases");

type Json = any;

// Mirrors Go's DisallowUnknownFields for the manifest itself.
function onlyKeys(obj: Json, allowed: string[], where: string): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) throw new Error(`${where}: unknown manifest key ${JSON.stringify(key)}`);
  }
}

function loadManifest(): Json {
  const m = JSON.parse(readFileSync(join(casesDir, "manifest.json"), "utf8"));
  onlyKeys(m, ["schema", "contract", "cases", "canonical_vectors"], "manifest");
  if (m.schema !== "aftergreen.bundle-cases.v0" || m.contract !== SCHEMA_VERSION) {
    throw new Error(`unexpected manifest schema ${m.schema} / contract ${m.contract}`);
  }
  for (const c of m.cases) {
    onlyKeys(c, ["id", "note", "input", "expect"], c.id);
    onlyKeys(c.input, ["file", "base", "raw", "raw_hex", "replace", "pad_to_bytes"], `${c.id} input`);
    onlyKeys(c.expect, ["result", "code", "pointer", "evidence_sha256"], `${c.id} expect`);
    for (const op of c.input.replace ?? []) {
      onlyKeys(op, ["find", "with", "with_hex", "with_repeat"], `${c.id} replace`);
      if (op.with_repeat) onlyKeys(op.with_repeat, ["item", "count", "separator"], `${c.id} with_repeat`);
    }
  }
  for (const v of m.canonical_vectors) onlyKeys(v, ["id", "json", "canonical_hex", "sha256"], v.id);
  return m;
}

function readCase(name: string): Buffer {
  if (/[/\\]/.test(name)) throw new Error(`case file ${JSON.stringify(name)} must be a plain file name`);
  return readFileSync(join(casesDir, name));
}

// Non-overlapping occurrences, like Go's bytes.Count.
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
function buildInput(input: Json): Uint8Array {
  const forms = [input.file !== undefined, input.base !== undefined, input.raw !== undefined, input.raw_hex !== undefined].filter(Boolean).length;
  if (forms !== 1) throw new Error("input needs exactly one of file, base, raw, raw_hex");
  if (input.base === undefined && (input.replace !== undefined || input.pad_to_bytes !== undefined)) {
    throw new Error("replace and pad_to_bytes are only allowed with base");
  }
  let data: Buffer;
  if (input.file !== undefined) data = readCase(input.file);
  else if (input.base !== undefined) data = readCase(input.base);
  else if (input.raw !== undefined) data = Buffer.from(input.raw, "utf8");
  else data = Buffer.from(input.raw_hex, "hex");
  for (const op of input.replace ?? []) data = applyReplace(data, op);
  if (input.pad_to_bytes !== undefined) {
    if (data.length > input.pad_to_bytes) throw new Error(`input is already ${data.length} bytes, more than pad_to_bytes ${input.pad_to_bytes}`);
    data = Buffer.concat([data, Buffer.alloc(input.pad_to_bytes - data.length, 0x20)]);
  }
  return new Uint8Array(data);
}

const manifest = loadManifest();

test("manifest covers every error code", () => {
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
  for (const code of ERROR_CODES) assert.ok(expected.has(code), `no case expects error code ${code}`);
});

for (const c of manifest.cases) {
  test(`case ${c.id}`, async () => {
    const got = await validateBundle(buildInput(c.input));
    if (c.expect.result === "accept") {
      assert.ok(got.ok, got.ok ? "" : `rejected with ${got.code} at ${JSON.stringify(got.pointer)} (${got.detail}); want accept`);
      assert.equal(got.evidenceSha256, c.expect.evidence_sha256);
      return;
    }
    assert.ok(!got.ok, got.ok ? `accepted with digest ${got.evidenceSha256}; want ${c.expect.code}` : "");
    assert.deepEqual(
      { code: got.code, pointer: got.pointer },
      { code: c.expect.code, pointer: c.expect.pointer ?? "" },
      `detail: ${got.detail}`,
    );
  });
}

for (const v of manifest.canonical_vectors) {
  test(`canonical vector ${v.id}`, async () => {
    const encoded = canonicalEncode(parseStrict(v.json));
    assert.equal(Buffer.from(encoded).toString("hex"), v.canonical_hex);
    assert.equal(await sha256Hex(encoded), v.sha256);
  });
}
