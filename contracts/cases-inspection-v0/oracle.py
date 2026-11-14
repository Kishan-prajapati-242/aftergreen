"""Derives the expected inspection results (contracts/inspection-v0.md) for the
bundles in bundles/, writing expected/<name>.json.

A separate implementation of sections 2-5 of the contract, written from the
contract text and kept apart from the Go inspector, so that the two can be
checked against each other. It assumes its input bundles are valid v1 (the Go
tests validate them). Standard library only:

    python3 -I contracts/cases-inspection-v0/oracle.py
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z ")
MARKERS = ["gha_error", "npm_error", "go_test_fail", "pytest_failed", "python_traceback",
           "go_panic", "error_line", "timeout", "failed_count"]
REASONS = ["outside_selected_span", "line_too_long", "line_limit", "redacted"]
MAX_LISTED = 200
EXIT = re.compile(r"Process completed with exit code ([1-9][0-9]{0,9})(?![0-9])")
TIMEOUT = re.compile(r"(?<![A-Za-z0-9_])(?:TimeoutError|Timed out|timed out)(?![A-Za-z0-9_])")
FAILED_COUNT = re.compile(r"(?<![A-Za-z0-9_])[1-9][0-9]* failed(?![A-Za-z0-9_])")
ERROR_LINE = re.compile(r"[A-Za-z]*Error: ")


def body_of(text):
    m = TIMESTAMP.match(text)
    return text[m.end():] if m else text


def markers_of(body):
    unindented = body.lstrip(" \t")
    found = []
    if "##[error]" in body:
        found.append("gha_error")
    if body.startswith("npm ERR!") or body == "npm error" or body.startswith("npm error "):
        found.append("npm_error")
    if unindented.startswith("--- FAIL: ") or body == "FAIL" or body.startswith("FAIL ") or body.startswith("FAIL\t"):
        found.append("go_test_fail")
    if body.startswith("FAILED "):
        found.append("pytest_failed")
    if unindented.startswith("Traceback (most recent call last):"):
        found.append("python_traceback")
    if body.startswith("panic: "):
        found.append("go_panic")
    if ERROR_LINE.match(unindented):
        found.append("error_line")
    if TIMEOUT.search(body):
        found.append("timeout")
    if FAILED_COUNT.search(body):
        found.append("failed_count")
    return found


def citation(sid, n):
    return {"source_id": sid, "start": n, "end": n}


def inspect(bundle):
    job = next(s for s in bundle["sources"] if s["kind"] == "job_log")
    sid = job["id"]
    run = bundle["runs"][0]
    result = {
        "schema": "aftergreen.inspection.v0",
        "bundle_schema": "aftergreen.bundle.v1",
        "bundle_evidence_sha256": bundle["evidence_sha256"],
        "evidence_class": bundle["evidence_class"],
    }
    lims = []
    observations = []
    counts = {"error_marker": {m: 0 for m in MARKERS}, "nonzero_exit": 0, "step_header": 0, "observations": 0}

    if job["status"] == "missing":
        result["job_log"] = {"source_id": sid, "status": "missing", "missing_reason": job["missing_reason"]}
        lims.append({"code": "log_missing", "source_id": sid, "missing_reason": job["missing_reason"]})
    else:
        line_count = job["line_count"]
        text = {l["n"]: l["text"] for l in job["lines"]}
        omitted = {}
        omitted_lines = {r: 0 for r in REASONS}
        for o in job["omitted"]:
            omitted_lines[o["reason"]] += o["end"] - o["start"] + 1
            for n in range(o["start"], o["end"] + 1):
                omitted[n] = o["reason"]
        result["job_log"] = {
            "source_id": sid, "status": "present", "extent": job["extent"], "line_count": line_count,
            "included_lines": len(job["lines"]), "omitted_lines": omitted_lines,
            "omitted_ranges": len(job["omitted"]), "inline_redactions": job["redactions"],
        }
        headers = {n for n, t in text.items() if body_of(t).startswith("##[group]Run ")}

        def step_of(n):
            for k in range(n, 0, -1):
                if k in omitted:
                    return None, "lines_omitted_before"
                if k in headers:
                    return k, None
            return None, "no_step_header_before"

        for n in sorted(text):
            body = body_of(text[n])
            for m in markers_of(body):
                observations.append({"kind": "error_marker", "marker": m, "citation": citation(sid, n)})
                counts["error_marker"][m] += 1
            e = EXIT.search(body)
            if e:
                observations.append({"kind": "nonzero_exit", "exit_code": int(e.group(1)), "citation": citation(sid, n)})
                counts["nonzero_exit"] += 1
            if n in headers:
                observations.append({"kind": "step_header", "citation": citation(sid, n)})
                counts["step_header"] += 1
        counts["observations"] = len(observations)
        listed = observations[:MAX_LISTED]
        context, steps = {}, {}
        last_cited = False
        for o in listed:
            if o["kind"] == "step_header":
                continue
            n = o["citation"]["start"]
            last_cited = last_cited or n == line_count
            h, reason = step_of(n)
            if h is not None:
                o["step_header"] = citation(sid, h)
            else:
                steps[n] = reason
            before = n > 1 and n - 1 in omitted
            after = n < line_count and n + 1 in omitted
            if before or after:
                context[n] = "both" if before and after else ("before" if before else "after")
        observations = listed

        if job["extent"] != "complete":
            lims.append({"code": "log_incomplete", "source_id": sid, "extent": job["extent"]})
            if last_cited:
                lims.append({"code": "line_may_be_cut", "source_id": sid, "line": line_count})

    for s in sorted((s for s in bundle["sources"] if s["kind"] != "job_log" and s["status"] == "missing"), key=lambda s: s["id"]):
        lims.append({"code": "source_missing", "source_id": s["id"], "kind": s["kind"], "missing_reason": s["missing_reason"]})
    if job["status"] == "present":
        ranges = {r: 0 for r in REASONS}
        for o in job["omitted"]:
            ranges[o["reason"]] += 1
        for r in REASONS:
            if omitted_lines[r]:
                lims.append({"code": "lines_omitted", "source_id": sid, "reason": r, "count": omitted_lines[r], "ranges": ranges[r]})
        for n in sorted(context):
            lims.append({"code": "context_omitted", "source_id": sid, "line": n, "side": context[n]})
        for n in sorted(steps):
            lims.append({"code": "step_undetermined", "source_id": sid, "line": n, "reason": steps[n]})
    if run["checkout"]["status"] == "unresolved":
        lims.append({"code": "checkout_unresolved", "reason": run["checkout"]["reason"]})
    if run["matrix"]["status"] == "unresolved":
        lims.append({"code": "matrix_unresolved", "reason": run["matrix"]["reason"]})
    if job["status"] == "present" and sum(counts["error_marker"].values()) + counts["nonzero_exit"] == 0:
        lims.append({"code": "no_markers", "source_id": sid})
    if counts["observations"] > MAX_LISTED:
        lims.append({"code": "observations_truncated", "total": counts["observations"], "listed": MAX_LISTED})

    result["observations"] = observations
    result["counts"] = counts
    result["limitations"] = lims
    return result


def main():
    names = sorted(f[:-5] for f in os.listdir(os.path.join(HERE, "bundles")) if f.endswith(".json"))
    for name in names:
        with open(os.path.join(HERE, "bundles", name + ".json"), encoding="utf-8") as f:
            bundle = json.load(f)
        with open(os.path.join(HERE, "expected", name + ".json"), "w", encoding="utf-8") as f:
            json.dump(inspect(bundle), f, indent=1, ensure_ascii=True)
            f.write("\n")
        print("wrote expected/" + name + ".json")


if __name__ == "__main__":
    main()
