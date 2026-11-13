// The command-line checker agrees with the Go command's output format.
//   node --test contracts/ts/validate.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "./validate.ts";

const contracts = join(dirname(fileURLToPath(import.meta.url)), "..");

async function run(argv: string[]): Promise<{ code: number; lines: string[]; errs: string[] }> {
  const lines: string[] = [];
  const errs: string[] = [];
  const code = await main(argv, (s) => lines.push(s), (s) => errs.push(s));
  return { code, lines, errs };
}

test("accepted and rejected files", async () => {
  for (const [schema, file, code, accepted, errCode] of [
    ["v1", "cases-v1/valid-producer-fixture.json", 0, true, undefined],
    ["v1", "cases-v1/valid-collected-job-log.json", 0, true, undefined],
    ["v0", "cases-v1/valid-collected-job-log.json", 1, false, "unknown_field"],
    ["v0", "cases/valid-simulated-stale-lockfile.json", 0, true, undefined],
    ["v1", "cases/valid-simulated-stale-lockfile.json", 1, false, "schema_violation"],
  ] as const) {
    const r = await run(["-schema", schema, join(contracts, file)]);
    assert.equal(r.code, code, file);
    assert.equal(r.lines.length, 1);
    const o = JSON.parse(r.lines[0]);
    assert.equal(o.accepted, accepted, file);
    assert.equal(o.code, errCode, file);
    if (accepted) assert.match(o.evidence_sha256, /^[0-9a-f]{64}$/);
  }
});

test("the producer fixture's digest matches the manifest", async () => {
  const r = await run(["-schema", "v1", join(contracts, "cases-v1/valid-producer-fixture.json")]);
  assert.equal(
    r.lines[0],
    '{"contract":"aftergreen.bundle.v1","accepted":true,"evidence_sha256":"e84636121f38103f29cdb919e3d6429605d9b1983c85c47a5f367db9018793be"}',
  );
});

test("arguments, oversize input and pointer text", async () => {
  for (const argv of [[], ["x.json"], ["-schema", "v2", "x.json"], ["-schema", "v1"], ["-schema", "v1", "a", "b"], ["-schema", "v1", "/nonexistent/bundle.json"]]) {
    const r = await run(argv);
    assert.equal(r.code, 2, JSON.stringify(argv));
    assert.equal(r.lines.length, 0);
  }
  const dir = mkdtempSync(join(tmpdir(), "aftergreen-validate-"));
  writeFileSync(join(dir, "big.json"), " ".repeat(200000));
  const big = await run(["-schema", "v1", join(dir, "big.json")]);
  assert.equal(JSON.parse(big.lines[0]).code, "input_too_large");
  writeFileSync(join(dir, "odd.json"), '{"schema":"aftergreen.bundle.v1","\\u001b[2J\\u202e":1}');
  const odd = await run(["-schema", "v1", join(dir, "odd.json")]);
  assert.deepEqual(JSON.parse(odd.lines[0]), { contract: "aftergreen.bundle.v1", accepted: false, code: "unknown_field", pointer: "/?[2J?" });
});

// The exact bytes, which the Go command's TestValidateRawLine checks too.
test("raw output line", async () => {
  const dir = mkdtempSync(join(tmpdir(), "aftergreen-validate-"));
  writeFileSync(join(dir, "html.json"), '{"<a&b>":1}');
  const r = await run(["-schema", "v1", join(dir, "html.json")]);
  assert.equal(r.lines[0], '{"contract":"aftergreen.bundle.v1","accepted":false,"code":"unknown_field","pointer":"/<a&b>"}');
});

// As a command, also when its path goes through a symlink: it must check the
// file and print the line, never exit 0 silently.
test("command run directly and through a symlinked path", () => {
  const fixture = join(contracts, "cases-v1/valid-producer-fixture.json");
  const want = '{"contract":"aftergreen.bundle.v1","accepted":true,"evidence_sha256":"e84636121f38103f29cdb919e3d6429605d9b1983c85c47a5f367db9018793be"}\n';
  const link = join(mkdtempSync(join(tmpdir(), "aftergreen-link-")), "contracts");
  symlinkSync(contracts, link, "dir");
  for (const script of [join(contracts, "ts/validate.ts"), join(link, "ts/validate.ts")]) {
    const r = spawnSync(process.execPath, [script, "-schema", "v1", fixture], { encoding: "utf8" });
    assert.equal(r.status, 0, script);
    assert.equal(r.stdout, want, script);
  }
  const bad = spawnSync(process.execPath, [join(link, "ts/validate.ts"), "-schema", "v1", join(contracts, "cases-v1/manifest.json")], { encoding: "utf8" });
  assert.equal(bad.status, 1);
  assert.equal(JSON.parse(bad.stdout).accepted, false);
});
