package logbundle

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"aftergreen/collector/inspect"
	"aftergreen/contracts/bundle"
)

// Step spans. The inspector cites a step header for an observation only when
// the header and every line through the observation are included
// (contracts/inspection-v0.md section 4). The logs of stepCases were written,
// with their expected selection and step attribution worked out by hand from
// the rule in select.go, before the rule was implemented; against the
// selector of that time, the 13 cases that need a span failed and the other
// 13 passed. reviewStepCases were added after review, derived the same way.
// None is a real run.

const (
	omittedBefore  = -1 // step_undetermined, reason lines_omitted_before
	noHeaderBefore = -2 // step_undetermined, reason no_step_header_before
)

type stepCase struct {
	name     string
	lines    []string
	included string           // the included lines, as ranges: "1-5,27-33"
	steps    map[int64]int64  // every line with an error_marker or nonzero_exit observation: the step header cited, or omittedBefore or noHeaderBefore
	reasons  map[int64]string // the omission reasons of some omitted lines
}

// stepLog is n lines of plain step output, with the given lines replaced.
func stepLog(n int, set map[int]string) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("  step output %d", i+1)
	}
	for k, v := range set {
		lines[k-1] = v
	}
	return lines
}

func header(cmd string) string { return "##[group]Run " + cmd }

const exitLine = "##[error]Process completed with exit code 1."

func stepCases() []stepCase {
	const out, tooLong, limit, red = "outside_selected_span", "line_too_long", "line_limit", "redacted"
	var cases []stepCase
	add := func(c stepCase) { cases = append(cases, c) }

	// Nearby headers.
	add(stepCase{name: "header within the failure's context",
		lines:    stepLog(60, map[int]string{27: header("npm test"), 30: exitLine}),
		included: "1-5,27-33,41-60", steps: map[int64]int64{30: 27}})
	add(stepCase{name: "header one line beyond the context",
		lines:    stepLog(60, map[int]string{26: header("npm test"), 30: exitLine}),
		included: "1-5,26-33,41-60", steps: map[int64]int64{30: 26}, reasons: map[int64]string{25: out}})
	add(stepCase{name: "header among the first lines",
		lines:    stepLog(200, map[int]string{3: header("npm test"), 90: exitLine}),
		included: "1-93,181-200", steps: map[int64]int64{90: 3}})

	// Distant headers and the 500-line limit. Without the span, 32 lines are
	// included: 1-5, the failure's 7 and the last 20.
	add(stepCase{name: "distant header, an error between",
		lines:    stepLog(700, map[int]string{100: header("npm test"), 250: "    Error: expected 2, received 1", 400: exitLine}),
		included: "1-5,100-403,681-700", steps: map[int64]int64{250: 100, 400: 100}, reasons: map[int64]string{99: out, 404: out}})
	add(stepCase{name: "span fills the line limit",
		lines:    stepLog(520, map[int]string{10: header("npm test"), 481: exitLine}), // 32 + 468 = 500 lines
		included: "1-5,10-484,501-520", steps: map[int64]int64{481: 10}, reasons: map[int64]string{9: out, 485: out}})
	add(stepCase{name: "span one line over the line limit",
		lines:    stepLog(520, map[int]string{9: header("npm test"), 481: exitLine}), // 32 + 469 = 501 lines
		included: "1-5,478-484,501-520", steps: map[int64]int64{481: omittedBefore}, reasons: map[int64]string{9: out, 477: out}})
	// The header is included as one of the first 5 lines, the failure as a
	// failure line, but the lines between do not fit: nothing bridges them.
	add(stepCase{name: "header included, span over the line limit",
		lines:    stepLog(520, map[int]string{3: header("npm test"), 481: exitLine}), // 32 + 472 = 504 lines
		included: "1-5,478-484,501-520", steps: map[int64]int64{481: omittedBefore}, reasons: map[int64]string{6: out, 477: out}})
	add(stepCase{name: "span over the line budget",
		lines: func() []string {
			l := stepLog(300, map[int]string{100: header("npm test"), 160: exitLine})
			for n := 101; n <= 159; n++ {
				l[n-1] = fmt.Sprintf("  output %03d ", n) + strings.Repeat("q", 1985) // 1,998 bytes: 56 such lines are over 110,000
			}
			return l
		}(),
		included: "1-5,157-163,281-300", steps: map[int64]int64{160: omittedBefore}, reasons: map[int64]string{100: out, 156: out}})

	// Several headers and errors.
	add(stepCase{name: "two steps with failure lines",
		lines: stepLog(300, map[int]string{40: header("npm run lint"), 70: "##[error]Lint found 3 problems",
			120: header("npm test"), 150: "    Error: expected 2, received 1", 200: exitLine}),
		included: "1-5,40-73,120-203,281-300", steps: map[int64]int64{70: 40, 150: 120, 200: 120}, reasons: map[int64]string{74: out, 119: out}})
	add(stepCase{name: "several failure lines in one step",
		lines: stepLog(300, map[int]string{50: header("npm test"), 80: "##[error]first annotation", 120: "##[error]second annotation",
			150: exitLine}),
		included: "1-5,50-153,281-300", steps: map[int64]int64{80: 50, 120: 50, 150: 50}})
	// Only failure lines get a span. A step with another error signal and no
	// failure line keeps an undetermined step.
	add(stepCase{name: "a step with an error but no failure line",
		lines: stepLog(300, map[int]string{30: header("npm ci"), 60: "Error: retrying the download", 120: header("npm test"),
			160: exitLine}),
		included: "1-5,57-63,120-163,281-300", steps: map[int64]int64{60: omittedBefore, 160: 120}, reasons: map[int64]string{30: out, 56: out}})

	// Composite and printed header-shaped text: the nearest header-shaped line
	// is cited, whoever printed it.
	add(stepCase{name: "composite action",
		lines: stepLog(200, map[int]string{30: header("./.github/actions/build-and-test"), 31: "##[endgroup]",
			40: header("npm ci"), 41: "##[endgroup]", 60: header("npm test"), 61: "##[endgroup]", 90: exitLine}),
		included: "1-5,60-93,181-200", steps: map[int64]int64{90: 60}, reasons: map[int64]string{30: out, 40: out, 59: out}})
	add(stepCase{name: "printed header-shaped line",
		lines: stepLog(200, map[int]string{30: header("npm test"), 60: "##[group]Run printed by a test, not by the runner",
			65: "echo ##[group]Run not at the start of the line", 70: "##[group]Running is not a step header",
			75: "##[group] Run has a space first", 90: exitLine}),
		included: "1-5,60-93,181-200", steps: map[int64]int64{90: 60}, reasons: map[int64]string{30: out, 59: out}})
	add(stepCase{name: "failure line that is itself a header",
		lines:    stepLog(200, map[int]string{50: header(`echo "##[error]this is only an echo"`), 90: exitLine}),
		included: "1-5,47-93,181-200", steps: map[int64]int64{50: 50, 90: 50}})
	add(stepCase{name: "timestamped lines",
		lines: func() []string {
			l := stepLog(200, map[int]string{30: header("npm test"), 90: exitLine})
			for i := range l {
				l[i] = fmt.Sprintf("2026-11-01T10:%02d:%02d.0000000Z ", (i/60)%60, i%60) + l[i]
			}
			return l
		}(),
		included: "1-5,30-93,181-200", steps: map[int64]int64{90: 30}})

	// Withheld and over-long lines: a span holding one is never included.
	add(stepCase{name: "private key inside the span",
		lines: stepLog(200, map[int]string{30: header("deploy"), 50: "-----BEGIN RSA PRIVATE KEY-----", 51: fakeKeyBody,
			52: "-----END RSA PRIVATE KEY-----", 90: exitLine}),
		included: "1-5,87-93,181-200", steps: map[int64]int64{90: omittedBefore},
		reasons: map[int64]string{30: out, 50: red, 51: red, 52: red, 53: out}})
	add(stepCase{name: "private key before the header",
		lines: stepLog(200, map[int]string{10: "-----BEGIN RSA PRIVATE KEY-----", 11: fakeKeyBody, 12: "-----END RSA PRIVATE KEY-----",
			30: header("deploy"), 90: exitLine}),
		included: "1-5,30-93,181-200", steps: map[int64]int64{90: 30}, reasons: map[int64]string{10: red, 11: red, 12: red}})
	add(stepCase{name: "secret redacted in place inside the span",
		lines:    stepLog(200, map[int]string{30: header("deploy"), 50: "using token=" + fakePassword, 90: exitLine}),
		included: "1-5,30-93,181-200", steps: map[int64]int64{90: 30}})
	add(stepCase{name: "escape-hidden secret inside the span",
		lines:    stepLog(200, map[int]string{30: header("deploy"), 50: "\x1b[31mtoken=" + fakeBearer + "\x1b[0m", 90: exitLine}),
		included: "1-5,87-93,181-200", steps: map[int64]int64{90: omittedBefore}, reasons: map[int64]string{50: red}})
	add(stepCase{name: "over-long line inside the span",
		lines:    stepLog(200, map[int]string{30: header("npm test"), 50: strings.Repeat("x", 2100), 90: exitLine}),
		included: "1-5,87-93,181-200", steps: map[int64]int64{90: omittedBefore}, reasons: map[int64]string{30: out, 50: out}})
	add(stepCase{name: "over-long line in the failure's context",
		lines:    stepLog(200, map[int]string{30: header("npm test"), 88: strings.Repeat("x", 2100), 90: exitLine}),
		included: "1-5,87,89-93,181-200", steps: map[int64]int64{90: omittedBefore}, reasons: map[int64]string{30: out, 88: tooLong}})
	add(stepCase{name: "line over-long only after redaction", // 2,030 bytes, 2,049 once the value is replaced
		lines: stepLog(200, map[int]string{30: header("npm test"), 50: strings.Repeat("w", 2030-len(" token=ab")) + " token=ab",
			90: exitLine}),
		included: "1-5,87-93,181-200", steps: map[int64]int64{90: omittedBefore}, reasons: map[int64]string{30: out, 50: out}})

	// No header before the failure.
	add(stepCase{name: "no step header",
		lines:    stepLog(200, map[int]string{90: exitLine}),
		included: "1-5,87-93,181-200", steps: map[int64]int64{90: omittedBefore}})
	add(stepCase{name: "header only after the failure",
		lines:    stepLog(200, map[int]string{90: exitLine, 100: header("next step")}),
		included: "1-5,87-93,181-200", steps: map[int64]int64{90: omittedBefore}, reasons: map[int64]string{100: out}})
	add(stepCase{name: "short log with no header",
		lines:    stepLog(20, map[int]string{10: exitLine}),
		included: "1-20", steps: map[int64]int64{10: noHeaderBefore}})

	// Crowded failures: 125 test failures 4 lines apart, with their context,
	// fill the 500 lines before the step span is tried. The 10 earliest
	// context lines, the first 5 and the last 20 lines are line_limit.
	crowded := map[int]string{1000: header("npm run e2e"), 1030: exitLine}
	crowdedSteps := map[int64]int64{1030: omittedBefore}
	for k := 0; k < 125; k++ {
		crowded[10+4*k] = fmt.Sprintf("--- FAIL: TestCrowded%d (0.00s)", k)
		crowdedSteps[int64(10+4*k)] = omittedBefore
	}
	add(stepCase{name: "crowded failures",
		lines: stepLog(1100, crowded), included: "10,14,18,20-509,1027-1033", steps: crowdedSteps,
		reasons: map[int64]string{1: limit, 5: limit, 6: out, 7: limit, 19: limit, 510: out, 1000: out, 1026: out, 1081: limit, 1100: limit}})
	return cases
}

// reviewStepCases pin the longest span and a header on line 1.
func reviewStepCases() []stepCase {
	return []stepCase{
		{name: "500-line span from line 1",
			lines:    stepLog(500, map[int]string{1: header("npm test"), 500: exitLine}),
			included: "1-500", steps: map[int64]int64{500: 1}},
		{name: "501-line span from line 1",
			lines:    stepLog(501, map[int]string{1: header("npm test"), 501: exitLine}),
			included: "1-5,482-501", steps: map[int64]int64{501: omittedBefore},
			reasons: map[int64]string{6: "outside_selected_span", 481: "outside_selected_span"}},
	}
}

func allStepCases() []stepCase { return append(stepCases(), reviewStepCases()...) }

// lineSet reads "1-5,27-33" as a set of line numbers.
func lineSet(t *testing.T, spec string) map[int64]bool {
	t.Helper()
	set := map[int64]bool{}
	for _, part := range strings.Split(spec, ",") {
		lo, hi, ok := strings.Cut(part, "-")
		if !ok {
			hi = lo
		}
		a, err1 := strconv.ParseInt(lo, 10, 64)
		b, err2 := strconv.ParseInt(hi, 10, 64)
		if err1 != nil || err2 != nil || a > b {
			t.Fatalf("bad line set %q", spec)
		}
		for n := a; n <= b; n++ {
			set[n] = true
		}
	}
	return set
}

// rangesOf writes a set of line numbers as "1-5,27-33".
func rangesOf(set map[int64]bool) string {
	var ns []int64
	for n := range set {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(a, b int) bool { return ns[a] < ns[b] })
	var parts []string
	for i := 0; i < len(ns); {
		j := i
		for j+1 < len(ns) && ns[j+1] == ns[j]+1 {
			j++
		}
		if i == j {
			parts = append(parts, strconv.FormatInt(ns[i], 10))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", ns[i], ns[j]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

// stepsOf reads the step attribution of every listed error_marker and
// nonzero_exit observation from an inspection.
func stepsOf(r *inspect.Result) map[int64]int64 {
	got := map[int64]int64{}
	for _, o := range r.Observations {
		if o.Kind != "step_header" && o.StepHeader != nil {
			got[o.Citation.Start] = o.StepHeader.Start
		}
	}
	for _, l := range r.Limitations {
		if l.Code == "step_undetermined" {
			got[*l.Line] = map[string]int64{"lines_omitted_before": omittedBefore, "no_step_header_before": noHeaderBefore}[l.Reason]
		}
	}
	return got
}

func TestStepSpans(t *testing.T) {
	for _, c := range allStepCases() {
		t.Run(c.name, func(t *testing.T) {
			in := logInput(joinLines(c.lines))
			raw, _, j := mustBuild(t, in, testOpt)
			fate := account(t, j)
			got := map[int64]bool{}
			for n, f := range fate {
				if f == "included" {
					got[n] = true
				}
			}
			if g, w := rangesOf(got), rangesOf(lineSet(t, c.included)); g != w {
				t.Errorf("included %s\n          want %s", g, w)
			}
			for n, want := range c.reasons {
				if fate[n] != want {
					t.Errorf("line %d is %s, want %s", n, fate[n], want)
				}
			}
			res, err := inspect.Inspect(raw)
			if err != nil {
				t.Fatal(err)
			}
			if ps := inspect.Verify(raw, res); ps != nil {
				t.Fatalf("the verifier rejects the inspection: %+v", ps)
			}
			if res.Counts.Observations > inspect.MaxListed {
				t.Fatalf("%d observations: the case must list them all", res.Counts.Observations)
			}
			if g := stepsOf(res); !reflect.DeepEqual(g, c.steps) {
				t.Errorf("steps %v\n want %v", g, c.steps)
			}
			if l := leaked(raw); len(l) > 0 {
				t.Errorf("sentinels %q in the bundle", l)
			}
		})
	}
}

// The fixture of "line over-long only after redaction" reaches that path.
func TestStepCaseOverLongAfterRedaction(t *testing.T) {
	for _, c := range stepCases() {
		if c.name != "line over-long only after redaction" {
			continue
		}
		_, lines, err := prepareLog(logInput(joinLines(c.lines)).Log, testOpt)
		if err != nil {
			t.Fatal(err)
		}
		if l := lines[49]; !l.tooLong || l.withheld || len(l.clean) > maxLineBytes || len(l.text) <= maxLineBytes {
			t.Fatalf("line 50: too long %v, withheld %v, %d bytes cleaned, %d redacted", l.tooLong, l.withheld, len(l.clean), len(l.text))
		}
		return
	}
	t.Fatal("case not found")
}

// compareSpans builds in with and without step spans and checks what the
// spans may change: only outside_selected_span lines become included, each
// in a complete step span; no omitted range is added; no pattern the audit
// counts loses an included line, and only step headers gain any; and every
// observation listed in both inspections that cites a step header without
// the spans cites the same one with them. An observation listed without the
// spans may be missing with them only when the inspection with them is
// truncated: a header a span adds is an observation too, and the inspector
// lists 200 (see TestStepSpanCanPushAnObservationOutOfTheList). It returns
// the number of lines the spans added and the bundle with them.
func compareSpans(t *testing.T, name string, in Input) (int, []byte) {
	t.Helper()
	opt := testOpt
	opt.Audit = true
	off := opt
	off.noStepSpans = true
	rawOff, sumOff, jOff := mustBuild(t, in, off)
	rawOn, sumOn, jOn := mustBuild(t, in, opt)
	if !in.Log.Obtained {
		return 0, rawOn
	}
	fOff, fOn := account(t, jOff), account(t, jOn)
	added := 0
	for n, before := range fOff {
		if after := fOn[n]; after != before {
			if before != "outside_selected_span" || after != "included" {
				t.Fatalf("%s: line %d went from %s to %s", name, n, before, after)
			}
			added++
		}
	}
	if len(jOn.Omitted) > len(jOff.Omitted) || sumOn.JobLog.DroppedToFitRanges != sumOff.JobLog.DroppedToFitRanges {
		t.Fatalf("%s: %d ranges with spans, %d without; dropped %d and %d", name, len(jOn.Omitted), len(jOff.Omitted),
			sumOn.JobLog.DroppedToFitRanges, sumOff.JobLog.DroppedToFitRanges)
	}
	if sumOff.JobLog.DroppedToFitRanges > 0 && added > 0 {
		t.Fatalf("%s: spans added after lines were dropped to fit the ranges", name)
	}
	// A line a span adds matches no error pattern in its bundle text, since
	// each is a selection signal, but it may match a step header or have had
	// a match removed by inline redaction.
	for k, a := range sumOff.Audit.Patterns {
		b := sumOn.Audit.Patterns[k]
		if a.Lines != b.Lines || b.Included < a.Included || b.HiddenByInlineRedaction < a.HiddenByInlineRedaction ||
			(a.Pattern != "step_header" && b.Included != a.Included) {
			t.Fatalf("%s: %s audit %+v without spans, %+v with", name, a.Pattern, a, b)
		}
		for reason, n := range b.Omitted {
			if n > a.Omitted[reason] {
				t.Fatalf("%s: %s omits %d lines as %s with spans, %d without", name, a.Pattern, n, reason, a.Omitted[reason])
			}
		}
	}
	resOff, err := inspect.Inspect(rawOff)
	if err != nil {
		t.Fatal(err)
	}
	resOn, err := inspect.Inspect(rawOn)
	if err != nil {
		t.Fatal(err)
	}
	if ps := inspect.Verify(rawOn, resOn); ps != nil {
		t.Fatalf("%s: the verifier rejects the inspection: %+v", name, ps)
	}
	stepsOn := stepsOf(resOn)
	for n, h := range stepsOf(resOff) {
		g, listed := stepsOn[n]
		if !listed && resOn.Counts.Observations <= inspect.MaxListed {
			t.Fatalf("%s: line %d is listed without spans, not with them, and nothing is truncated", name, n)
		}
		if h > 0 && listed && g != h {
			t.Fatalf("%s: line %d cites step header %d with spans, %d without", name, n, g, h)
		}
	}
	return added, rawOn
}

// observationListLog has 200 observations without step spans and 201 with
// them: see TestStepSpanCanPushAnObservationOutOfTheList.
func observationListLog() []string {
	set := map[int]string{50: header("npm test"), 270: exitLine, 400: header("npm run report"), 402: "Error: y"}
	for n := 60; n <= 255; n++ {
		set[n] = "Error: e"
	}
	return stepLog(450, set)
}

// unrecognizedValueLog prints value in an env block that no redaction rule
// matches: see TestStepSpansIncludeUnrecognizedValues.
func unrecognizedValueLog(value string) []string {
	return stepLog(200, map[int]string{30: header("./deploy.sh"), 31: "./deploy.sh", 32: "env:",
		33: "  DEPLOY_HOOK: https://hooks.example.test/services/T000/B000/" + value, 34: "##[endgroup]", 90: exitLine})
}

// The trade-off compareSpans allows. Without spans there are exactly 200
// observations and line 402 cites header 400. The span of the failure line at
// 270 adds header 50, observation 201, so line 402 is no longer listed: the
// inspection says so with observations_truncated, and lines 60-270 now cite
// header 50. Line 402 and its header stay in the bundle.
func TestStepSpanCanPushAnObservationOutOfTheList(t *testing.T) {
	in := logInput(joinLines(observationListLog()))
	off := testOpt
	off.noStepSpans = true
	rawOff, _, _ := mustBuild(t, in, off)
	rawOn, _, jOn := mustBuild(t, in, testOpt)
	resOff, err := inspect.Inspect(rawOff)
	if err != nil {
		t.Fatal(err)
	}
	resOn, err := inspect.Inspect(rawOn)
	if err != nil {
		t.Fatal(err)
	}
	sOff, sOn := stepsOf(resOff), stepsOf(resOn)
	if resOff.Counts.Observations != 200 || sOff[402] != 400 || sOff[270] != omittedBefore {
		t.Fatalf("without spans: %d observations, line 402 -> %d, line 270 -> %d", resOff.Counts.Observations, sOff[402], sOff[270])
	}
	_, listed := sOn[402]
	truncated := false
	for _, l := range resOn.Limitations {
		truncated = truncated || (l.Code == "observations_truncated" && *l.Total == 201 && *l.Listed == 200)
	}
	if resOn.Counts.Observations != 201 || listed || !truncated || sOn[60] != 50 || sOn[255] != 50 || sOn[270] != 50 {
		t.Fatalf("with spans: %d observations, line 402 listed %v, truncated %v, lines 60, 255, 270 -> %d %d %d",
			resOn.Counts.Observations, listed, truncated, sOn[60], sOn[255], sOn[270])
	}
	if fate := account(t, jOn); fate[400] != "included" || fate[402] != "included" {
		t.Fatalf("lines 400 and 402 are %s and %s", fate[400], fate[402])
	}
}

// Redaction is rule-based, and a span includes a step's ordinary lines: its
// printed script and env block among them. A value that no rule recognizes,
// such as a webhook URL with the secret in its path, is outside the selection
// without the span and in the bundle with it. This pins that documented
// limit; it is not a property to keep.
func TestStepSpansIncludeUnrecognizedValues(t *testing.T) {
	value := "WEBHOOKPATH" + "SENTINEL3"
	in := logInput(joinLines(unrecognizedValueLog(value)))
	off := testOpt
	off.noStepSpans = true
	rawOff, _, jOff := mustBuild(t, in, off)
	rawOn, _, jOn := mustBuild(t, in, testOpt)
	if f := account(t, jOff)[33]; f != "outside_selected_span" || bytes.Contains(rawOff, []byte(value)) {
		t.Fatalf("without spans: line 33 is %s, value in the bundle %v", f, bytes.Contains(rawOff, []byte(value)))
	}
	if f := account(t, jOn)[33]; f != "included" || !bytes.Contains(rawOn, []byte(value)) {
		t.Fatalf("with spans: line 33 is %s, value in the bundle %v", f, bytes.Contains(rawOn, []byte(value)))
	}
}

func TestStepSpansKeepTheSelection(t *testing.T) {
	for _, c := range allStepCases() {
		compareSpans(t, c.name, logInput(joinLines(c.lines)))
	}
	for name, raw := range map[string][]byte{"failure log": joinLines(failureLog()), "secret log": secretLog()} {
		compareSpans(t, name, logInput(raw))
	}
}

// Random logs of headers, failure lines, other errors, withheld, redacted,
// over-long and large lines, with and without timestamps. One in eight is
// mostly large lines. (The line budget's limit on a span is tested by the
// "span over the line budget" case and TestAddStepSpansLimits: random logs
// large enough to reach it make this test slow.)
func randomStepLog(r *rand.Rand) []string {
	n := 20 + r.IntN(400)
	headerP, failP := 0.001+0.06*r.Float64(), 0.002+0.05*r.Float64()
	bigP := 0.01
	if r.IntN(8) == 0 {
		n, bigP = 40+r.IntN(80), 0.5
	}
	var l []string
	for len(l) < n {
		switch x := r.Float64(); {
		case x < headerP:
			l = append(l, header(fmt.Sprintf("step %d", len(l))))
		case x < headerP+failP:
			l = append(l, []string{exitLine, fmt.Sprintf("##[error]annotation %d", len(l))}[r.IntN(2)])
		case x < headerP+failP+bigP:
			l = append(l, fmt.Sprintf("  big %d ", len(l))+strings.Repeat("q", 500+r.IntN(1000)))
		default:
			switch k := r.IntN(100); {
			case k < 4:
				l = append(l, fmt.Sprintf("    Error: failure %d", len(l)))
			case k < 5:
				l = append(l, "-----BEGIN RSA PRIVATE KEY-----", fakeKeyBody, "-----END RSA PRIVATE KEY-----")
			case k < 6:
				l = append(l, strings.Repeat("x", 2049+r.IntN(100)))
			case k < 7:
				l = append(l, "using token="+fakePassword)
			case k < 8:
				l = append(l, "\x1b[31mtoken="+fakeBearer+"\x1b[0m")
			case k < 9:
				l = append(l, strings.Repeat("w", 2021)+" token=ab")
			case k < 10:
				l = append(l, "echo ##[group]Run printed")
			default:
				l = append(l, fmt.Sprintf("  output %d", len(l)))
			}
		}
	}
	if r.IntN(3) == 0 {
		for i := range l {
			l[i] = "2026-11-01T10:00:00.0000000Z " + l[i]
		}
	}
	return l
}

func TestStepSpansOnRandomLogs(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 5)) // fixed seed: the same logs every run
	logs, withSpans, lines := 200, 0, 0
	for i := 0; i < logs; i++ {
		a, out := compareSpans(t, fmt.Sprintf("log %d", i), logInput(joinLines(randomStepLog(r))))
		if a > 0 {
			withSpans++
			lines += a
		}
		if l := leaked(out); len(l) > 0 {
			t.Fatalf("log %d: sentinels %q in the bundle", i, l)
		}
	}
	t.Logf("%d of %d logs gained step spans, %d lines in all", withSpans, logs, lines)
	if withSpans < logs/4 {
		t.Errorf("only %d of %d logs gained a span: the generator no longer exercises the rule", withSpans, logs)
	}
}

// Under range pressure no span is added, even one that would fit: lines were
// left out to fit the omitted-range limit, and a span must not take their
// room.
func TestStepSpansUnderRangePressure(t *testing.T) {
	lines := make([]string, 2700) // the last 20 lines start after the span
	for k := range lines {
		lines[k] = "    ok"
		if n := k + 1; n%10 == 5 && n <= 2595 {
			lines[k] = fmt.Sprintf("--- FAIL: Test%d", n)
		}
	}
	lines[2603-1], lines[2610-1] = header("go test ./..."), exitLine
	in := logInput(joinLines(lines))
	raw, sum, j := mustBuild(t, in, testOpt)
	fate := account(t, j)
	off := testOpt
	off.noStepSpans = true
	rawOff, _, _ := mustBuild(t, in, off)
	if sum.JobLog.DroppedToFitRanges == 0 || fate[2610] != "included" || fate[2603] != "outside_selected_span" || !bytes.Equal(raw, rawOff) {
		t.Fatalf("dropped %d, line 2610 %s, line 2603 %s, same as without spans %v", sum.JobLog.DroppedToFitRanges, fate[2610], fate[2603], bytes.Equal(raw, rawOff))
	}
	// The span would fit the line limit and the size limit.
	missing, cost := 0, 0
	for n := int64(2603); n < 2610; n++ {
		if fate[n] != "included" {
			missing++
			cost += lineCost(n, lines[n-1])
		}
	}
	if len(j.Lines)+missing > maxLines || len(raw)+cost > bundle.MaxInputBytes {
		t.Fatalf("the span would not fit: %d lines + %d, %d bytes + %d", len(j.Lines), missing, len(raw), cost)
	}
}

// addStepSpans on hand-made selections: the line budget and the size bound
// are exact, the redaction count's digits are counted, a span of a failure
// line that is not included is not added, and the latest failure line's span
// is tried first.
func TestAddStepSpansLimits(t *testing.T) {
	emails := "contacts:"
	for i := 0; i < 10; i++ {
		emails += fmt.Sprintf(" dev%d@example.com", i)
	}
	log := stepLog(30, map[int]string{2: header("first"), 5: emails, 10: exitLine, 12: header("second"), 20: exitLine})
	_, lines, err := prepareLog(logInput(joinLines(log)).Log, testOpt)
	if err != nil {
		t.Fatal(err)
	}
	rk := rankLines(lines)
	if fmt.Sprint(rk.spans) != "[{1 9} {11 19}]" || redactionsIn(lines[4]) != 10 {
		t.Fatalf("spans %v, line 5 redactions %d", rk.spans, redactionsIn(lines[4]))
	}
	// Only the failure lines are included to begin with.
	sel := func(incl ...int) []decision {
		dec := make([]decision, len(lines))
		for i := range dec {
			dec[i] = outside
		}
		for _, n := range incl {
			dec[n-1] = included
		}
		return dec
	}
	costOf := func(from, to int) int { // lines from..to, 1-based
		c := 0
		for n := from; n <= to; n++ {
			c += lineCost(int64(n), lines[n-1].text)
		}
		return c
	}
	used := costOf(10, 10) + costOf(20, 20)
	first, second := costOf(2, 9), costOf(12, 19)
	const big = 1 << 30
	for _, c := range []struct {
		name         string
		budget, size int
		want         string // the included lines afterwards
	}{
		{"room for both", big, 0, "2-10,12-20"},
		{"the budget fits the later span exactly", used + second, 0, "10,12-20"},
		{"the budget is one byte short of it", used + second - 1, 0, "10,20"},
		{"then the earlier span fits the rest", used + second + first, 0, "2-10,12-20"},
		{"the size fits the later span exactly", big, bundle.MaxInputBytes - second, "10,12-20"},
		{"the size is one byte short of it", big, bundle.MaxInputBytes - second + 1, "10,20"},
		// The earlier span holds the 10 redactions of line 5: the count gains
		// a digit, so the bundle grows by one more byte than its lines.
		{"redaction digits: one byte short", big, bundle.MaxInputBytes - first - second, "10,12-20"},
		{"redaction digits: exact", big, bundle.MaxInputBytes - first - second - 1, "2-10,12-20"},
	} {
		dec := sel(10, 20)
		rk.addStepSpans(lines, dec, c.budget, c.size)
		got := map[int64]bool{}
		for i, d := range dec {
			if d == included {
				got[int64(i+1)] = true
			}
		}
		if rangesOf(got) != c.want {
			t.Errorf("%s: included %s, want %s", c.name, rangesOf(got), c.want)
		}
	}
	dec := sel(20) // line 10 is not included: its span is not tried
	if n := rk.addStepSpans(lines, dec, big, 0); n != 8 || dec[1] != outside {
		t.Errorf("added %d lines; line 2 is %v", n, dec[1])
	}
}
