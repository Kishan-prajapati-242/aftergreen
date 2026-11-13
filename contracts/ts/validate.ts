// Checks one bundle file against contract v0 or v1 and prints one JSON line,
// the same line contracts/go/cmd/aftergreen-validate prints: the contract
// checked, whether the bundle was accepted, and either its evidence digest or
// the error code and JSON Pointer of the first failed check. Nothing else from
// the file is printed; the pointer is shown in printable ASCII, at most 256
// bytes. Dependency-free; Node 22.18 or later runs it with type stripping:
//
//   node contracts/ts/validate.ts -schema v0|v1 FILE
//
// Exit status: 0 accepted, 1 rejected, 2 invalid arguments or an unreadable file.

import { closeSync, openSync, readSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { MAX_INPUT_BYTES, SCHEMA_VERSION, validateBundle } from "./bundle.ts";
import { SCHEMA_VERSION_V1, validateBundleV1 } from "./bundle-v1.ts";

export type Output = { contract: string; accepted: boolean; evidence_sha256?: string; code?: string; pointer?: string };

// printable keeps printable ASCII, replaces anything else with "?", and
// truncates to 256 bytes, as the Go command does.
export function printable(s: string): string {
  let out = "";
  for (const ch of s) {
    if (out.length >= 256) break;
    const c = ch.codePointAt(0)!;
    out += c >= 0x20 && c <= 0x7e ? ch : "?";
  }
  return out;
}

// readBounded reads at most MAX_INPUT_BYTES + 1 bytes: one past the limit is
// enough for the validator to report input_too_large.
function readBounded(path: string): Uint8Array {
  const fd = openSync(path, "r");
  try {
    const buf = new Uint8Array(MAX_INPUT_BYTES + 1);
    let n = 0;
    for (;;) {
      const got = readSync(fd, buf, n, buf.length - n, null);
      if (got === 0 || n + got === buf.length) {
        n += got;
        break;
      }
      n += got;
    }
    return buf.subarray(0, n);
  } finally {
    closeSync(fd);
  }
}

export async function validateFile(schema: "v0" | "v1", path: string): Promise<Output> {
  const raw = readBounded(path);
  const r = schema === "v1" ? await validateBundleV1(raw) : await validateBundle(raw);
  const contract = schema === "v1" ? SCHEMA_VERSION_V1 : SCHEMA_VERSION;
  if (r.ok) return { contract, accepted: true, evidence_sha256: r.evidenceSha256 };
  const out: Output = { contract, accepted: false, code: r.code };
  if (r.pointer !== "") out.pointer = printable(r.pointer);
  return out;
}

// main returns the exit status and writes the line to out, or a message to err.
export async function main(argv: string[], out: (s: string) => void, err: (s: string) => void): Promise<number> {
  const usage = "usage: node contracts/ts/validate.ts -schema v0|v1 FILE";
  if (argv.length !== 3 || argv[0] !== "-schema" || (argv[1] !== "v0" && argv[1] !== "v1")) {
    err(usage);
    return 2;
  }
  let o: Output;
  try {
    o = await validateFile(argv[1], argv[2]);
  } catch {
    err("validate.ts: cannot read the file");
    return 2;
  }
  out(JSON.stringify(o));
  return o.accepted ? 0 : 1;
}

// Run as a command, not when imported. Node gives the main module's real
// path but argv[1] as typed, so both are resolved: run through a symlinked
// path, the command must still check the file and print its line.
export function isMain(argv1: string | undefined, moduleURL: string): boolean {
  if (argv1 === undefined) return false;
  try {
    return realpathSync(argv1) === realpathSync(fileURLToPath(moduleURL));
  } catch {
    return false;
  }
}

if (isMain(process.argv[1], import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2), (s) => process.stdout.write(s + "\n"), (s) => process.stderr.write(s + "\n"));
}
