package logbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"aftergreen/contracts/bundle"
)

// Offline tests. Every secret here is an invented sentinel assembled at run
// time, so this file holds no token-shaped literal.

var (
	fakeGitHubToken = "ghp_" + strings.Repeat("Q7", 18)
	fakePAT         = "github_pat_" + strings.Repeat("Zx4", 10) + "_" + strings.Repeat("Kp", 20)
	fakeAWSKeyID    = "AKIA" + "FAKESENTINEL0000"
	fakeSlack       = "xoxb-" + "000000000000-FAKESENTINELSLACK"
	fakeNPM         = "npm_" + strings.Repeat("N0", 18)
	fakeJWT         = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiJTRU5USU5FTCJ9" + ".SENTINELSIGNATURE0"
	fakeSig         = "SIGSENTINEL" + "77"
	fakeSignedURL   = "https://productionresultssa7.blob.core.windows.net/actions-results/0000/job-logs.txt?rsct=text%2Fplain&se=2026-11-10T00%3A00%3A00Z&sig=" + fakeSig + "%3D&sp=r"
	fakePassword    = "PASSWORD" + "SENTINEL9"
	fakeBearer      = "BEARER" + "SENTINEL0123456789"
	fakeKeyBody     = "MIIE" + "FAKEKEYSENTINEL" + strings.Repeat("A", 40)
)

// sentinels are the distinctive parts of the fake secrets above.
var sentinels = []string{"Q7Q7Q7Q7Q7Q7", "Zx4Zx4Zx4", "FAKESENTINEL0000", "FAKESENTINELSLACK", "N0N0N0N0N0N0",
	"SENTINELSIGNATURE0", fakeSig, fakePassword, fakeBearer, "FAKEKEYSENTINEL", "PASSSENTINEL", "CLIENTSECRETSENTINEL",
	"sentinel.person", "dXNlcjpTRU5USU5FTA"}

func leaked(b []byte) []string {
	var out []string
	for _, s := range sentinels {
		if bytes.Contains(b, []byte(s)) {
			out = append(out, s)
		}
	}
	return out
}

var testOpt = Options{EvidenceClass: "simulated", Tool: "aftergreen-collect", APIVersion: "2026-03-10",
	CreatedAt: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}

func logInput(raw []byte) Input {
	sum := sha256.Sum256(raw)
	return Input{
		RepoID: 1001, FullName: "example-org/example-repo", Public: true,
		WorkflowID: 2001, WorkflowPath: ".github/workflows/ci.yml",
		RunID: 3001, RunAttempt: 1, AttemptStartedAt: "2026-11-09T10:00:00Z",
		Event: "push", Branch: "main", HeadSHA: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
		JobID: 4001, JobName: "test (ubuntu)", JobConclusion: "failure",
		JobStartedAt: "2026-11-09T10:00:05Z", JobCompletedAt: "2026-11-09T10:03:00Z",
		JobLabels: []string{"ubuntu-latest"},
		Log: Log{Obtained: true, Extent: "complete", Authentication: "gh_cli", Bytes: raw,
			ReceivedBytes: int64(len(raw)), SHA256: hex.EncodeToString(sum[:])},
	}
}

func joinLines(lines []string) []byte { return []byte(strings.Join(lines, "\n") + "\n") }

type lineOut struct {
	N    int64  `json:"n"`
	Text string `json:"text"`
}

type omittedOut struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Reason string `json:"reason"`
}

type jobLogOut struct {
	Status        string       `json:"status"`
	MissingReason string       `json:"missing_reason"`
	Extent        string       `json:"extent"`
	LineCount     int64        `json:"line_count"`
	Redactions    int          `json:"redactions"`
	Lines         []lineOut    `json:"lines"`
	Omitted       []omittedOut `json:"omitted"`
}

// checkReasons re-derives every omitted line's exact reason from the line's
// own properties and fails on any other reason, or on an included line that
// may not be included.
func checkReasons(t *testing.T, in Input, opt Options, j jobLogOut) {
	t.Helper()
	_, lines, err := prepareLog(in.Log, opt)
	if err != nil {
		t.Fatal(err)
	}
	rank := rankLines(lines).rank
	for n, f := range account(t, j) {
		l := lines[n-1]
		want := "line_limit"
		switch {
		case l.withheld:
			want = "redacted"
		case rank[n-1] < 0:
			want = "outside_selected_span"
		case l.tooLong:
			want = "line_too_long"
		}
		if f == "included" {
			if want != "line_limit" {
				t.Fatalf("line %d is included, but its reason would be %s", n, want)
			}
			continue
		}
		if f != want {
			t.Fatalf("line %d is %s, but its exact reason is %s", n, f, want)
		}
	}
}

func mustBuild(t *testing.T, in Input, opt Options) ([]byte, *Summary, jobLogOut) {
	t.Helper()
	raw, sum, err := Build(in, opt)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if r := bundle.ValidateV1(raw); !r.Accepted() || r.EvidenceSHA256 != sum.EvidenceSHA256 {
		t.Fatalf("the bundle does not validate: %s at %s (%s)", r.Code, r.Pointer, r.Detail)
	}
	if len(raw) > bundle.MaxInputBytes || sum.Bytes != len(raw) {
		t.Fatalf("bundle is %d bytes (summary says %d)", len(raw), sum.Bytes)
	}
	var doc struct {
		Sources []jobLogOut `json:"sources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if in.Log.Obtained {
		checkReasons(t, in, opt, doc.Sources[0])
	}
	return raw, sum, doc.Sources[0]
}

// account checks that lines and omitted ranges cover 1..line_count exactly
// once and returns each line's fate: "included" or its omission reason.
func account(t *testing.T, j jobLogOut) map[int64]string {
	t.Helper()
	fate := map[int64]string{}
	set := func(n int64, f string) {
		if n < 1 || n > j.LineCount {
			t.Fatalf("line %d is outside 1..%d", n, j.LineCount)
		}
		if old, dup := fate[n]; dup {
			t.Fatalf("line %d is both %s and %s", n, old, f)
		}
		fate[n] = f
	}
	for _, l := range j.Lines {
		set(l.N, "included")
	}
	for _, o := range j.Omitted {
		for n := o.Start; n <= o.End; n++ {
			set(n, o.Reason)
		}
	}
	if int64(len(fate)) != j.LineCount {
		t.Fatalf("%d of %d lines are accounted for", len(fate), j.LineCount)
	}
	return fate
}

func TestSplitLines(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a\n", []string{"a"}},
		{"\n", []string{""}},
		{"\n\n", []string{"", ""}},
		{"a\nb", []string{"a", "b"}},
		{"a\r\nb\r\n", []string{"a", "b"}},
		{"a\rb\n", []string{"a\rb"}},   // a CR not before an LF stays in the line
		{"a\r", []string{"a\r"}},       // and so does a final CR with no LF
		{"a\r\r\n", []string{"a\r"}},   // only the CR directly before the LF goes
		{"a\n\r\n", []string{"a", ""}}, // an empty CRLF line
	} {
		var got []string
		for _, p := range splitLines([]byte(c.raw)) {
			got = append(got, string(p))
		}
		if fmt.Sprint(got) != fmt.Sprint(c.want) || len(got) != len(c.want) {
			t.Errorf("splitLines(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestCleanLine(t *testing.T) {
	for _, c := range []struct {
		in    string
		first bool
		want  string
	}{
		{"plain text", false, "plain text"},
		{"tab\tkept", false, "tab\tkept"},
		{"\x1b[31mred\x1b[0m and \x1b[1;32mgreen\x1b[m", false, "red and green"},
		{"\x1b[38;5;196mcolour\x1b[39m", false, "colour"},
		{"\x1b]8;;https://example.com\x07link\x1b]8;;\x07", false, "link"},
		{"\x1b]0;window title\x1b\\after", false, "after"},
		{"\x1bPdevice control\x1b\\after", false, "after"},
		{"\x1b(Bcharset", false, "charset"},
		{"\x1b7saved\x1b8", false, "saved"},
		{"lone escape\x1b", false, "lone escape"},
		{"unterminated \x1b[12", false, "unterminated "},
		{"unterminated \x1b]0;title", false, "unterminated "},
		{"csi cut \x1b[3\x07x", false, "csi cut x"},
		{"c1 \u009b31mcsi\u009b0m", false, "c1 csi"},
		{"c1 \u009dosc\u009cend", false, "c1 end"},
		{"nul\x00 del\x7f bel\x07 bs\x08 cr\r vt\v ff\f", false, "nul del bel bs cr vt ff"},
		{"c1 \u0085next \u0080\u009f", false, "c1 next "},
		{"bad \xff\xfe utf-8", false, "bad \uFFFD utf-8"}, // one U+FFFD per run of invalid bytes
		{"overlong \xc0\xaf and surrogate \xed\xa0\x80", false, "overlong \uFFFD and surrogate \uFFFD"},
		{"cut \xe2\x82", false, "cut \uFFFD"},
		{"\uFEFFbom on line 1", true, "bom on line 1"},
		{"\uFEFFbom later", false, "\uFEFFbom later"},
		{"##[error]Process completed with exit code 1.", false, "##[error]Process completed with exit code 1."},
	} {
		got := cleanLine([]byte(c.in), c.first)
		if got != c.want {
			t.Errorf("cleanLine(%q) = %q, want %q", c.in, got, c.want)
		}
		if !validText(got) {
			t.Errorf("cleanLine(%q) left a control character: %q", c.in, got)
		}
	}
}

func TestRedactLine(t *testing.T) {
	for _, c := range []struct {
		in    string
		want  string
		rules map[string]int
	}{
		{"Using token " + fakeGitHubToken + " now", "Using token [REDACTED:github-token] now", map[string]int{"github-token": 1}},
		{"PAT=" + fakePAT, "PAT=[REDACTED:github-token]", map[string]int{"github-token": 1}},
		{"curl -H 'Authorization: Bearer abc.def-" + fakeBearer + "' https://api.example.com",
			"curl -H 'Authorization: Bearer [REDACTED:authorization]' https://api.example.com", map[string]int{"authorization": 1}},
		{"authorization=Basic dXNlcjpTRU5USU5FTA==", "authorization=Basic [REDACTED:authorization]", map[string]int{"authorization": 1}},
		{"sent Bearer " + fakeBearer, "sent Bearer [REDACTED:authorization]", map[string]int{"authorization": 1}},
		{"Authorization: Bearer " + fakeGitHubToken, "Authorization: Bearer [REDACTED:github-token]", map[string]int{"github-token": 1}},
		{"git clone https://user:PASSSENTINEL@github.com/o/r.git", "git clone https://[REDACTED:url-userinfo]@github.com/o/r.git", map[string]int{"url-userinfo": 1}},
		{"Downloading " + fakeSignedURL + " done",
			"Downloading https://productionresultssa7.blob.core.windows.net/actions-results/0000/job-logs.txt?[REDACTED:url-query] done", map[string]int{"url-query": 1}},
		{"aws_access_key_id = " + fakeAWSKeyID, "aws_access_key_id = [REDACTED:aws-key-id]", map[string]int{"aws-key-id": 1}},
		{"webhook " + fakeSlack, "webhook [REDACTED:slack-token]", map[string]int{"slack-token": 1}},
		{"//registry.npmjs.org/:_authToken=" + fakeNPM, "//registry.npmjs.org/:_authToken=[REDACTED:npm-token]", map[string]int{"npm-token": 1}},
		{"id_token: " + fakeJWT, "id_token: [REDACTED:jwt]", map[string]int{"jwt": 1}},
		{"DB_PASSWORD=" + fakePassword + " ok", "DB_PASSWORD=[REDACTED:assignment] ok", map[string]int{"assignment": 1}},
		{`{"client_secret": "CLIENTSECRETSENTINEL", "x": 1}`, `{"client_secret": [REDACTED:assignment], "x": 1}`, map[string]int{"assignment": 1}},
		{"Author: sentinel.person@example.com", "Author: [REDACTED:email]", map[string]int{"email": 1}},
		{"key=-----BEGIN RSA PRIVATE KEY-----" + fakeKeyBody + "-----END RSA PRIVATE KEY----- after",
			"key=[REDACTED:private-key] after", map[string]int{"private-key": 1}},
		{"-----BEGIN OPENSSH PRIVATE KEY-----" + fakeKeyBody, "[REDACTED:private-key]", map[string]int{"private-key": 1}},
		{"two " + fakeGitHubToken + " and " + fakeGitHubToken, "two [REDACTED:github-token] and [REDACTED:github-token]", map[string]int{"github-token": 2}},
		{"token: password: " + fakePassword, "token: [REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"secret=token=" + fakePassword, "secret=[REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"token: abc: x", "token: [REDACTED:assignment] x", map[string]int{"assignment": 1}},
		{"'password' => '" + fakePassword + "'", "'password' => [REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"password= 'password' => '" + fakePassword + "'", "password= [REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"token= password : " + fakePassword, "token= [REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"token=" + fakePassword + " => x", "token=[REDACTED:assignment]", map[string]int{"assignment": 1}}, // a secret that looks like a name is still replaced
		{"a_token: b_secret: c_password: " + fakePassword + " end", "a_token: [REDACTED:assignment] end", map[string]int{"assignment": 1}},
		{"token=> :token=>\"" + fakePassword + "\" text", "token=> [REDACTED:assignment] text", map[string]int{"assignment": 1}},
		{"x_token=a:password=>\"" + fakePassword + "\"", "x_token=[REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"token: " + strings.Repeat("password:", 40) + " " + fakePassword + " rest", "token: [REDACTED:assignment]", map[string]int{"assignment": 1}}, // a long chain: the rest of the line goes
		{":password=>\"" + fakePassword + "\"", ":password=>[REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"password := \"" + fakePassword + "\"", "password := [REDACTED:assignment]", map[string]int{"assignment": 1}},
		{"Authorization => 'token " + fakeBearer + "'", "Authorization => 'token [REDACTED:authorization]'", map[string]int{"authorization": 1}},
	} {
		got, counts := redactLine(c.in)
		if got != c.want {
			t.Errorf("redactLine(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		if fmt.Sprint(counts) != fmt.Sprint(c.rules) {
			t.Errorf("redactLine(%q) counts %v, want %v", c.in, counts, c.rules)
		}
		if l := leaked([]byte(got)); len(l) > 0 {
			t.Errorf("redactLine(%q) left %q", c.in, l)
		}
	}
	// Ordinary CI output is left alone.
	for _, s := range []string{
		"2026-11-09T10:02:41.0000000Z ##[error]Process completed with exit code 1.",
		"  token: ***",
		"  password: ***",
		`  api_key: "***"`,
		"Run actions/checkout@v4",
		"Error: expect(received).toBe(expected) // Object.is equality",
		"See https://playwright.dev/docs/intro for details",
		"npm ERR! code ELIFECYCLE",
		"Version: 1.49.0-beta.1",
		"\tat Object.<anonymous> (/home/runner/work/app/app/tests/a.spec.ts:10:5)",
		"[REDACTED:github-token] is already a placeholder",
		"password: |",  // a YAML block follows: no value on this line, so no marker
		"  secret: >",  // likewise
		"token := ***", // GitHub's mask
	} {
		if got, counts := redactLine(s); got != s || counts != nil {
			t.Errorf("redactLine(%q) = %q, %v; want it unchanged", s, got, counts)
		}
	}
}

func TestKeyBlocks(t *testing.T) {
	lines := []string{
		"before",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		fakeKeyBody,
		"-----END OPENSSH PRIVATE KEY-----",
		"between",
		"x -----BEGIN RSA PRIVATE KEY----- y -----END RSA PRIVATE KEY----- z", // one-line key: the inline rule's
		"p -----BEGIN EC PRIVATE KEY----- k -----END EC PRIVATE KEY----- -----BEGIN PRIVATE KEY-----",
		fakeKeyBody,
		"-----END PRIVATE KEY----- tail",
		"after",
		"-----BEGIN PGP PRIVATE KEY BLOCK-----",
		fakeKeyBody, // no END: the block runs to the end of the log
		"last",
	}
	want := []bool{false, true, true, true, false, false, true, true, true, false, true, true, true}
	if got := keyBlocks(lines); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("keyBlocks = %v\n     want %v", got, want)
	}
}

// failureLog has 2000 numbered lines, a failure at line 1500 and another
// error signal at line 1200.
func failureLog() []string {
	lines := make([]string, 2000)
	for i := range lines {
		lines[i] = fmt.Sprintf("2026-11-09T10:00:00.0000000Z step output L%04d", i+1)
	}
	lines[1199] = "2026-11-09T10:00:00.0000000Z npm ERR! code ELIFECYCLE L1200"
	lines[1499] = "2026-11-09T10:00:00.0000000Z ##[error]Process completed with exit code 1. L1500"
	return lines
}

func TestBuildSelectsFailureContext(t *testing.T) {
	lines := failureLog()
	_, sum, j := mustBuild(t, logInput(joinLines(lines)), testOpt)
	fate := account(t, j)
	want := map[int64]bool{}
	for _, r := range [][2]int64{{1, 5}, {1197, 1203}, {1497, 1503}, {1981, 2000}} {
		for n := r[0]; n <= r[1]; n++ {
			want[n] = true
		}
	}
	for n := int64(1); n <= 2000; n++ {
		switch {
		case want[n] && fate[n] != "included":
			t.Errorf("line %d is %s, want included", n, fate[n])
		case !want[n] && fate[n] != "outside_selected_span":
			t.Errorf("line %d is %s, want outside_selected_span", n, fate[n])
		}
	}
	for _, l := range j.Lines {
		if l.Text != lines[l.N-1] {
			t.Errorf("line %d text %q, want %q", l.N, l.Text, lines[l.N-1])
		}
	}
	if j.LineCount != 2000 || sum.JobLog.IncludedLines != len(want) || sum.JobLog.OmittedLines["outside_selected_span"] != 2000-int64(len(want)) {
		t.Errorf("summary %+v", sum.JobLog)
	}
}

// Line numbers belong to the original lines and survive every transform.
func TestLineNumbersSurviveTransforms(t *testing.T) {
	raw := []byte("\uFEFFL0001 start\r\n" +
		"L0002 \x1b[31mError: boom\x1b[0m\r\n" +
		"L0003 token=" + fakePassword + "\r\n" +
		"L0004 bad \xff byte and \x00 nul\n" +
		"L0005 \x1b]0;title\x07osc\n" +
		"-----BEGIN RSA PRIVATE KEY-----\n" +
		fakeKeyBody + "\n" +
		"-----END RSA PRIVATE KEY-----\n" +
		"L0009 Authorization: Bearer " + fakeBearer + "\n" +
		"L0010 end")
	_, sum, j := mustBuild(t, logInput(raw), testOpt)
	fate := account(t, j)
	if j.LineCount != 10 {
		t.Fatalf("line_count %d, want 10", j.LineCount)
	}
	for n := int64(6); n <= 8; n++ {
		if fate[n] != "redacted" {
			t.Errorf("line %d is %s, want redacted", n, fate[n])
		}
	}
	wantText := map[int64]string{
		1:  "L0001 start",
		2:  "L0002 Error: boom",
		3:  "L0003 token=[REDACTED:assignment]",
		4:  "L0004 bad \uFFFD byte and  nul",
		5:  "L0005 osc",
		9:  "L0009 Authorization: Bearer [REDACTED:authorization]",
		10: "L0010 end",
	}
	for _, l := range j.Lines {
		if w, ok := wantText[l.N]; !ok || l.Text != w {
			t.Errorf("line %d text %q, want %q", l.N, l.Text, w)
		}
	}
	if len(j.Lines) != len(wantText) || j.Redactions != 2 || sum.JobLog.OmittedLines["redacted"] != 3 {
		t.Errorf("lines %d, redactions %d, withheld lines %d", len(j.Lines), j.Redactions, sum.JobLog.OmittedLines["redacted"])
	}
	if l := leaked([]byte(fmt.Sprint(j))); len(l) > 0 {
		t.Errorf("sentinels left: %q", l)
	}
}

func TestNewlineCases(t *testing.T) {
	for _, c := range []struct {
		raw   string
		count int64
		texts []string
	}{
		{"", 0, nil},
		{"\n", 1, []string{""}},
		{"a", 1, []string{"a"}},
		{"a\n", 1, []string{"a"}},
		{"a\n\n", 2, []string{"a", ""}},
		{"a\r\nb", 2, []string{"a", "b"}},
		{"a\rb\n", 1, []string{"ab"}},
		{"a\r", 1, []string{"a"}},
	} {
		_, _, j := mustBuild(t, logInput([]byte(c.raw)), testOpt)
		account(t, j)
		var texts []string
		for _, l := range j.Lines {
			texts = append(texts, l.Text)
		}
		if j.LineCount != c.count || fmt.Sprint(texts) != fmt.Sprint(c.texts) || len(texts) != len(c.texts) {
			t.Errorf("%q: line_count %d, texts %q; want %d, %q", c.raw, j.LineCount, texts, c.count, c.texts)
		}
	}
}

func TestLongLines(t *testing.T) {
	lines := failureLog()[:80]
	lines[9] = "Error: " + strings.Repeat("x", 2041)       // 2048 bytes: fits
	lines[13] = "Error: " + strings.Repeat("\u00e9", 1020) // 2047 bytes of UTF-8
	lines[14] = "Error: " + strings.Repeat("y", 2042)      // 2049 bytes, within line 14's context: too long
	lines[19] = "Error: " + strings.Repeat("v", 2042)      // too long and in no context: not scanned, so not selected
	lines[29] = strings.Repeat("\u00e9", 3000)             // long, but not selected
	_, _, j := mustBuild(t, logInput(joinLines(lines)), testOpt)
	fate := account(t, j)
	// A line too long to include is not scanned, so it brings in no context.
	for n, want := range map[int64]string{10: "included", 14: "included", 15: "line_too_long", 17: "included",
		18: "outside_selected_span", 20: "outside_selected_span", 21: "outside_selected_span", 30: "outside_selected_span"} {
		if fate[n] != want {
			t.Errorf("line %d is %s, want %s", n, fate[n], want)
		}
	}
}

func TestByteBudget(t *testing.T) {
	lines := make([]string, 600)
	for i := range lines {
		lines[i] = fmt.Sprintf("Error: L%04d ", i+1) + strings.Repeat("z", 1500)
	}
	raw, sum, j := mustBuild(t, logInput(joinLines(lines)), testOpt)
	fate := account(t, j)
	if len(raw) > bundle.MaxInputBytes || len(j.Lines) < 50 {
		t.Fatalf("bundle %d bytes with %d lines", len(raw), len(j.Lines))
	}
	// The latest lines are kept; the rest are omitted for the limit.
	first := j.Lines[0].N
	for n := int64(1); n <= 600; n++ {
		if want := map[bool]string{true: "included", false: "line_limit"}[n >= first]; fate[n] != want {
			t.Fatalf("line %d is %s, want %s", n, fate[n], want)
		}
	}
	if sum.JobLog.OmittedLines["line_limit"] != first-1 {
		t.Errorf("summary %+v", sum.JobLog)
	}
}

func TestLineLimit(t *testing.T) {
	lines := make([]string, 1000)
	for i := range lines {
		lines[i] = fmt.Sprintf("Error: L%04d", i+1)
	}
	_, _, j := mustBuild(t, logInput(joinLines(lines)), testOpt)
	fate := account(t, j)
	if len(j.Lines) != 500 || j.Lines[0].N != 501 || fate[500] != "line_limit" || len(j.Omitted) != 1 {
		t.Errorf("%d lines from %d; omitted %+v", len(j.Lines), j.Lines[0].N, j.Omitted)
	}
}

// exactRanges is an independent recount for the range-limit tests: the
// omitted ranges a decision list needs once every included block with a
// line_limit line on each side is left out (the only change fitRanges may
// make, since it keeps every omitted line's reason).
func exactRanges(dec []decision) int {
	d := append([]decision(nil), dec...)
	for i := 0; i < len(d); i++ {
		if d[i] != included {
			continue
		}
		j := i
		for j+1 < len(d) && d[j+1] == included {
			j++
		}
		if i > 0 && j+1 < len(d) && d[i-1] == overLimit && d[j+1] == overLimit {
			for k := i; k <= j; k++ {
				d[k] = overLimit
			}
		}
		i = j
	}
	runs := 0
	for i := range d {
		if d[i] != included && (i == 0 || d[i-1] != d[i]) {
			runs++
		}
	}
	return runs
}

// Omission reasons are exact. Listing them may need more than 501 ranges;
// the producer may then leave out selected lines (line_limit), and if that
// is not enough it builds no bundle. It never gives a line another reason.
func TestOmissionReasonsStayExact(t *testing.T) {
	t.Run("line_limit: isolated failures fit by leaving out selected lines", func(t *testing.T) {
		// A long go test -v run: 260 failures, each with context cut by the
		// line budget, need about 700 ranges.
		lines := make([]string, 2600)
		fail := map[int64]bool{}
		for k := range lines {
			lines[k] = "    ok"
			if (k+1)%10 == 5 {
				lines[k] = fmt.Sprintf("--- FAIL: Test%d", k+1)
				fail[int64(k+1)] = true
			}
		}
		_, sum, j := mustBuild(t, logInput(joinLines(lines)), testOpt)
		fate := account(t, j)
		candidate := func(n int64) bool {
			if n <= headLines || n > 2600-tailLines {
				return true
			}
			for d := int64(-contextLines); d <= contextLines; d++ {
				if fail[n+d] {
					return true
				}
			}
			return false
		}
		for n := int64(1); n <= 2600; n++ {
			want := "outside_selected_span"
			if candidate(n) {
				want = "line_limit"
			}
			if f := fate[n]; f != "included" && f != want {
				t.Fatalf("line %d is %s, want included or %s", n, f, want)
			}
		}
		if len(j.Omitted) > 501 || sum.JobLog.DroppedToFitRanges == 0 || sum.JobLog.OmittedLines["line_limit"] == 0 || len(j.Lines) == 0 {
			t.Errorf("%d ranges, %d dropped, omitted %v, %d included", len(j.Omitted), sum.JobLog.DroppedToFitRanges, sum.JobLog.OmittedLines, len(j.Lines))
		}
		if fate[2595] != "included" { // the latest failure is the last one dropped
			t.Errorf("the last failure line is %s", fate[2595])
		}
	})

	// Withheld private-key lines alternating with ordinary lines: before
	// this was fixed, the withheld lines were relabelled
	// outside_selected_span and the redacted count went to zero.
	keyLog := func(blocks int) []byte {
		l := []string{"Error: setup failed"}
		for i := 0; i < blocks; i++ {
			l = append(l, "-----BEGIN RSA PRIVATE KEY-----", fakeKeyBody, "-----END RSA PRIVATE KEY-----", fmt.Sprintf("ordinary line %d", i))
		}
		return joinLines(append(l, "##[error]Process completed with exit code 1."))
	}
	t.Run("redacted: fits", func(t *testing.T) {
		raw, sum, j := mustBuild(t, logInput(keyLog(150)), testOpt)
		fate := account(t, j)
		for b := 0; b < 150; b++ {
			for k := int64(0); k < 3; k++ {
				if n := int64(2+4*b) + k; fate[n] != "redacted" {
					t.Fatalf("key-block line %d is %s", n, fate[n])
				}
			}
		}
		if sum.JobLog.OmittedLines["redacted"] != 450 || sum.JobLog.DroppedToFitRanges != 0 || len(leaked(raw)) > 0 {
			t.Errorf("omitted %v, dropped %d", sum.JobLog.OmittedLines, sum.JobLog.DroppedToFitRanges)
		}
	})
	t.Run("redacted: too many ranges builds no bundle", func(t *testing.T) {
		raw, sum, err := Build(logInput(keyLog(300)), testOpt)
		if !errors.Is(err, ErrRangeLimit) || !errors.Is(err, ErrIncomplete) || raw != nil || sum != nil {
			t.Fatalf("err %v, bundle %d bytes", err, len(raw))
		}
	})

	t.Run("line_limit with withheld lines: reasons survive dropping", func(t *testing.T) {
		lines := make([]string, 2600)
		for k := range lines {
			lines[k] = "    ok"
			if (k+1)%10 == 5 {
				lines[k] = fmt.Sprintf("--- FAIL: Test%d", k+1)
			}
		}
		for _, at := range []int{700, 1300, 2100} { // lines at+1..at+3 inside a failure's context
			lines[at], lines[at+1], lines[at+2] = "-----BEGIN RSA PRIVATE KEY-----", fakeKeyBody, "-----END RSA PRIVATE KEY-----"
		}
		raw, sum, j := mustBuild(t, logInput(joinLines(lines)), testOpt)
		fate := account(t, j)
		for _, at := range []int64{701, 1301, 2101} {
			for n := at; n < at+3; n++ {
				if fate[n] != "redacted" {
					t.Fatalf("key-block line %d is %s", n, fate[n])
				}
			}
		}
		if sum.JobLog.OmittedLines["redacted"] != 9 || sum.JobLog.DroppedToFitRanges == 0 || len(j.Omitted) > 501 || len(leaked(raw)) > 0 {
			t.Errorf("omitted %v, dropped %d, %d ranges", sum.JobLog.OmittedLines, sum.JobLog.DroppedToFitRanges, len(j.Omitted))
		}
	})

	t.Run("range and size limits together", func(t *testing.T) {
		// 301 over-long context lines between 1,000-byte failure lines. The
		// first budgets (107 down to 104 lines) fit the ranges but not the
		// size; 103 lines fit both, so a bundle is built. Fewer than 101
		// lines would fit only the size.
		var l []string
		for i := 0; i < 301; i++ {
			l = append(l, "Error: "+strings.Repeat("a", 993), "Error: "+strings.Repeat("b", 2100))
		}
		raw, sum, j := mustBuild(t, logInput(joinLines(l)), testOpt)
		if len(raw) > bundle.MaxInputBytes || len(j.Omitted) != 499 || sum.JobLog.OmittedLines["line_too_long"] != 301 || len(j.Lines) != 103 {
			t.Errorf("%d bytes, %d ranges, omitted %v, %d included", len(raw), len(j.Omitted), sum.JobLog.OmittedLines, len(j.Lines))
		}
	})

	longLog := func(pairs int) []byte {
		l := make([]string, 0, 2*pairs)
		for i := 0; i < pairs; i++ {
			l = append(l, "Error: short", "Error: "+strings.Repeat("w", 3000))
		}
		return joinLines(l)
	}
	// Each over-long line between included lines is one range: 500 fit, and
	// with 501 the earliest short line is over the 500-line limit too.
	for _, pairs := range []int{300, 500} {
		t.Run(fmt.Sprintf("line_too_long: %d fit", pairs), func(t *testing.T) {
			_, sum, j := mustBuild(t, logInput(longLog(pairs)), testOpt)
			fate := account(t, j)
			for n := int64(2); n <= int64(2*pairs); n += 2 {
				if fate[n] != "line_too_long" {
					t.Fatalf("line %d is %s", n, fate[n])
				}
			}
			if sum.JobLog.OmittedLines["line_too_long"] != int64(pairs) {
				t.Errorf("omitted %v", sum.JobLog.OmittedLines)
			}
		})
	}
	for _, pairs := range []int{501, 550} {
		t.Run(fmt.Sprintf("line_too_long: %d build no bundle", pairs), func(t *testing.T) {
			if raw, _, err := Build(logInput(longLog(pairs)), testOpt); !errors.Is(err, ErrRangeLimit) || raw != nil {
				t.Fatalf("err %v, bundle %d bytes", err, len(raw))
			}
		})
	}

	t.Run("a log that fits drops nothing", func(t *testing.T) {
		if _, sum, _ := mustBuild(t, logInput(joinLines(failureLog())), testOpt); sum.JobLog.DroppedToFitRanges != 0 {
			t.Errorf("dropped %d", sum.JobLog.DroppedToFitRanges)
		}
	})
}

// The budgets Build tries: startBudget first, each smaller by at most
// budgetStep, no value twice, and literally 0 last, once. A budget of 0
// admits no line at all.
func TestLineBudgets(t *testing.T) {
	b := lineBudgets()
	if len(b) < 2 || b[0] != startBudget || b[len(b)-1] != 0 {
		t.Fatalf("budgets run %v ... %v, want %d ... 0", b[:min(3, len(b))], b[max(0, len(b)-3):], startBudget)
	}
	for i := 1; i < len(b); i++ {
		if d := b[i-1] - b[i]; d <= 0 || d > budgetStep {
			t.Fatalf("budget %d follows %d", b[i], b[i-1])
		}
	}
	// 110,000 - 107 * 1,024 = 432 is the last positive budget.
	if len(b) != 109 || b[len(b)-2] != 432 {
		t.Errorf("%d budgets, last positive %d; want 109 and 432", len(b), b[len(b)-2])
	}
	_, lines, err := prepareLog(logInput(joinLines(failureLog())).Log, testOpt)
	if err != nil {
		t.Fatal(err)
	}
	for i, d := range rankLines(lines).admit(0) {
		if d == included {
			t.Fatalf("budget 0 included line %d", i+1)
		}
	}
}

// Metadata that bundle v1 cannot hold is reported as a metadata problem,
// with or without a log, and never as the omitted-range limit.
func TestMetadataProblemsAreNotRangeLimits(t *testing.T) {
	// A log whose exact reasons cannot fit 501 ranges: an invalid log field
	// must still be reported as metadata, not as the range limit.
	keys := []string{"Error: x"}
	for i := 0; i < 300; i++ {
		keys = append(keys, "-----BEGIN RSA PRIVATE KEY-----", fakeKeyBody, "-----END RSA PRIVATE KEY-----", "ordinary")
	}
	for name, edit := range map[string]func(*Input){
		"oversized job name, log present": func(in *Input) { in.JobName = strings.Repeat("x", 140_000) },
		"oversized job name, log missing": func(in *Input) {
			in.JobName = strings.Repeat("x", 140_000)
			in.Log = Log{MissingReason: "access_denied", Authentication: "none"}
		},
		"job name over 256 bytes":  func(in *Input) { in.JobName = strings.Repeat("x", 300) },
		"oversized extent":         func(in *Input) { in.Log.Extent = strings.Repeat("x", 140_000) },
		"oversized authentication": func(in *Input) { in.Log.Authentication = strings.Repeat("x", 140_000) },
		"oversized missing reason": func(in *Input) { in.Log = Log{MissingReason: strings.Repeat("x", 140_000)} },
		"no authentication, too many ranges": func(in *Input) {
			*in = logInput(joinLines(keys))
			in.Log.Authentication = ""
		},
	} {
		in := logInput(joinLines(failureLog()))
		edit(&in)
		raw, sum, err := Build(in, testOpt)
		if !errors.Is(err, ErrIncomplete) || errors.Is(err, ErrRangeLimit) || raw != nil || sum != nil ||
			!strings.Contains(err.Error(), "metadata") {
			t.Errorf("%s: err %v", name, err)
		}
	}
	in := logInput(joinLines(failureLog()))
	in.JobName = strings.Repeat("x", 300)
	if _, _, err := Build(in, testOpt); err == nil || !strings.Contains(err.Error(), "/runs/0/job/name") {
		t.Errorf("err %v, want the job name's pointer", err)
	}
}

// fitRanges on hand-made decisions: it drops only blocks between line_limit
// lines, least important first, and keeps every omitted reason.
func TestFitRanges(t *testing.T) {
	const L, I, O, R = overLimit, included, outside, redacted
	var dec []decision
	var rank []int
	for i := 0; i < 200; i++ { // each unit (outside, line_limit, included, line_limit) is 3 ranges, or 2 once its block is dropped
		dec = append(dec, O, L, I, L)
		rank = append(rank, -1, 2, 1, 2)
	}
	dec[2*4+2], rank[2*4+2] = I, 3 // a less important block, in unit 2
	before := append([]decision(nil), dec...)
	if len(omittedRanges(dec)) <= maxOmitted {
		t.Fatal("the fixture fits already")
	}
	dropped, ok := fitRanges(dec, rank)
	if !ok || len(omittedRanges(dec)) != maxOmitted || dropped != len(omittedRanges(before))-maxOmitted {
		t.Fatalf("ok %v, %d ranges, %d dropped", ok, len(omittedRanges(dec)), dropped)
	}
	if dec[2*4+2] != L {
		t.Error("the least important block was kept")
	}
	for i := range dec {
		if before[i] != I && dec[i] != before[i] {
			t.Fatalf("line %d changed reason from %v to %v", i, before[i], dec[i])
		}
		if before[i] == I && dec[i] != I && dec[i] != L {
			t.Fatalf("dropped line %d became %v", i, dec[i])
		}
	}
	// Alternating fixed reasons cannot be fitted by dropping anything.
	alt := make([]decision, 2*maxOmitted)
	for i := range alt {
		alt[i] = []decision{O, R}[i%2]
	}
	if _, ok := fitRanges(alt, make([]int, len(alt))); ok {
		t.Error("alternating reasons reported as fitting")
	}
}

func TestBuildMissingLog(t *testing.T) {
	in := logInput(nil)
	in.Log = Log{MissingReason: "access_denied", Authentication: "none"}
	raw, sum, j := mustBuild(t, in, testOpt)
	if j.Status != "missing" || j.MissingReason != "access_denied" || j.Lines != nil || sum.JobLog.Status != "missing" {
		t.Errorf("job log %+v, summary %+v", j, sum.JobLog)
	}
	if bytes.Contains(raw, []byte(`"extent"`)) || bytes.Contains(raw, []byte(`"authentication"`)) {
		t.Error("a missing log carries present-only members")
	}
}

func TestBuildExtents(t *testing.T) {
	for _, extent := range []string{"complete", "prefix", "partial"} {
		in := logInput([]byte("Error: one\ntwo, cut mid-li"))
		in.Log.Extent = extent
		if _, _, j := mustBuild(t, in, testOpt); j.Extent != extent || j.LineCount != 2 {
			t.Errorf("extent %q: got %q with %d lines", extent, j.Extent, j.LineCount)
		}
	}
}

func TestBuildRefusesWhatItCannotRepresent(t *testing.T) {
	good := logInput(joinLines(failureLog()))
	for name, c := range map[string]struct {
		edit       func(*Input, *Options)
		incomplete bool
	}{
		"not public":      {func(in *Input, _ *Options) { in.Public = false }, true},
		"dynamic path":    {func(in *Input, _ *Options) { in.WorkflowPath = "dynamic/pages/pages-build-deployment" }, true},
		"branch control":  {func(in *Input, _ *Options) { in.Branch = "main\x1b[2J" }, true},
		"job succeeded":   {func(in *Input, _ *Options) { in.JobConclusion = "success" }, true},
		"no job start":    {func(in *Input, _ *Options) { in.JobStartedAt = "" }, true},
		"pull request":    {func(in *Input, _ *Options) { in.Event = "pull_request" }, true},
		"unknown reason":  {func(in *Input, _ *Options) { in.Log = Log{MissingReason: "timeout"} }, true},
		"no auth mode":    {func(in *Input, _ *Options) { in.Log.Authentication = "" }, true},
		"hash mismatch":   {func(in *Input, _ *Options) { in.Log.SHA256 = strings.Repeat("0", 64) }, false},
		"byte mismatch":   {func(in *Input, _ *Options) { in.Log.ReceivedBytes++ }, false},
		"bad class":       {func(_ *Input, o *Options) { o.EvidenceClass = "real" }, false},
		"no created time": {func(_ *Input, o *Options) { o.CreatedAt = time.Time{} }, false},
		"bad api version": {func(_ *Input, o *Options) { o.APIVersion = "2026-02-30" }, true},
	} {
		in, opt := good, testOpt
		c.edit(&in, &opt)
		raw, sum, err := Build(in, opt)
		if err == nil || raw != nil || sum != nil || errors.Is(err, ErrIncomplete) != c.incomplete {
			t.Errorf("%s: err %v (incomplete %v), bundle %d bytes", name, err, errors.Is(err, ErrIncomplete), len(raw))
		}
		if l := leaked([]byte(fmt.Sprint(err))); len(l) > 0 || strings.Contains(fmt.Sprint(err), "L0001") {
			t.Errorf("%s: the error shows log text: %v", name, err)
		}
	}
}

// secretLog puts every sentinel into lines the selection includes.
func secretLog() []byte {
	return joinLines([]string{
		"Error: setup failed with token " + fakeGitHubToken,
		"PAT=" + fakePAT,
		"Authorization: Bearer " + fakeBearer,
		"git clone https://user:PASSSENTINEL@github.com/o/r.git",
		"Downloading " + fakeSignedURL,
		"aws_access_key_id = " + fakeAWSKeyID,
		"webhook " + fakeSlack,
		"//registry.npmjs.org/:_authToken=" + fakeNPM,
		"id_token: " + fakeJWT,
		"DB_PASSWORD=" + fakePassword,
		`{"client_secret": "CLIENTSECRETSENTINEL"}`,
		"Author: sentinel.person@example.com",
		"authorization=Basic dXNlcjpTRU5USU5FTA==",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		fakeKeyBody,
		"-----END OPENSSH PRIVATE KEY-----",
		"##[error]Process completed with exit code 1.",
	})
}

func TestRedactionRemovesSentinels(t *testing.T) {
	raw, sum, j := mustBuild(t, logInput(secretLog()), testOpt)
	if l := leaked(raw); len(l) > 0 {
		t.Fatalf("the bundle holds sentinels %q", l)
	}
	if len(j.Lines) != 14 || sum.JobLog.OmittedLines["redacted"] != 3 {
		t.Errorf("%d lines included, %d withheld", len(j.Lines), sum.JobLog.OmittedLines["redacted"])
	}
	total := 0
	for _, n := range sum.JobLog.Redactions {
		total += n
	}
	if total != j.Redactions || j.Redactions != 13 {
		t.Errorf("redactions %d, by rule %v", j.Redactions, sum.JobLog.Redactions)
	}
}

// Negative control: with redaction off, the same check sees the sentinels,
// and collected evidence without redaction is refused.
func TestLeakedSentinelNegativeControl(t *testing.T) {
	opt := testOpt
	opt.noRedaction = true
	raw, _, _ := mustBuild(t, logInput(secretLog()), opt)
	if l := leaked(raw); len(l) != len(sentinels) {
		t.Errorf("with redaction off only %d of %d sentinels were found: %q", len(l), len(sentinels), l)
	}
	if !bytes.Contains(raw, []byte(`"redaction":{"status":"none"}`)) {
		t.Error("redaction status is not none")
	}
	opt.EvidenceClass = "collected_public"
	if _, _, err := Build(logInput(secretLog()), opt); !errors.Is(err, ErrIncomplete) {
		t.Errorf("collected evidence without redaction: err = %v, want ErrIncomplete", err)
	}
}

// A malformed escape sequence can swallow the start of a key marker or an
// assignment once escapes are removed. The marker is still found in the text
// with escapes kept, and a line whose escapes hide a match is withheld.
func TestEscapesCannotHideSecrets(t *testing.T) {
	raw := joinLines([]string{
		"Error: setup failed",
		"\x1b[-----BEGIN RSA PRIVATE KEY-----", // cleaned: "EGIN RSA PRIVATE KEY-----"
		fakeKeyBody,
		"-----END RSA PRIVATE KEY-----",
		"\x1b[ token=" + fakePassword,                  // cleaned: "oken=..."
		"\u009b password: " + fakePassword + " :x",     // cleaned: "assword: ... :x"
		"\x1b[31mtoken=" + fakeBearer + "\x1b[0m",      // a colour code and a match: withheld whole, conservatively
		`{\"client_secret\":\"CLIENTSECRETSENTINEL\"}`, // logged with backslash escapes: the rules see \", not "
		"token=\\\"" + fakePassword + "\\\"",           // token=\"...\": in the cleaned text the value is a lone backslash
		"##[error]Process completed with exit code 1.",
	})
	for _, l := range []string{`{\"client_secret\":\"CLIENTSECRETSENTINEL\"}`, "token=\\\"" + fakePassword + "\\\""} {
		if got, counts := redactLine(l); got != l || counts != nil {
			t.Fatalf("the fixture no longer escapes the inline rules: %q", got)
		}
	}
	if got := cleanLine([]byte("\x1b[-----BEGIN RSA PRIVATE KEY-----"), false); got != "EGIN RSA PRIVATE KEY-----" {
		t.Fatalf("the fixture no longer hides the marker: %q", got)
	}
	out, _, j := mustBuild(t, logInput(raw), testOpt)
	fate := account(t, j)
	for n, want := range map[int64]string{1: "included", 2: "redacted", 3: "redacted", 4: "redacted", 5: "redacted", 6: "redacted", 7: "redacted",
		8: "redacted", 9: "redacted", 10: "included"} {
		if fate[n] != want {
			t.Errorf("line %d is %s, want %s", n, fate[n], want)
		}
	}
	if l := leaked(out); len(l) > 0 {
		t.Errorf("sentinels %q in the bundle", l)
	}
	// Without escapes in the way, the same secrets are replaced in place.
	plainRaw := joinLines([]string{"Error: setup failed", "token=" + fakePassword, "token=" + fakeBearer})
	if _, _, j := mustBuild(t, logInput(plainRaw), testOpt); len(j.Lines) != 3 || j.Redactions != 2 {
		t.Errorf("%d lines, %d redactions", len(j.Lines), j.Redactions)
	}
}

// A rejection of the job log's line map is the producer's defect; one of
// collected metadata means the input cannot be represented (ErrIncomplete).
func TestProducerBuiltPointers(t *testing.T) {
	for p, want := range map[string]bool{
		"": true, "/sources/0/lines": true, "/sources/0/lines/3/text": true, "/sources/0/omitted/0/end": true,
		"/sources/0/line_count": true, "/sources/0/redactions": true,
		"/sources/0/authentication": false, "/sources/0/extent": false, "/sources/0/missing_reason": false,
		"/sources/0/linesx": false, "/runs/0/branch": false, "/collection/api_version": false,
	} {
		if producerBuilt(p) != want {
			t.Errorf("producerBuilt(%q) = %v", p, !want)
		}
	}
}

var lineNumberRE = regexp.MustCompile(`\{"n":([0-9]+),"text"`)

// Negative controls: the validator catches a shifted line map and a missing
// omission in producer output.
func TestLineMapNegativeControls(t *testing.T) {
	raw, _, _ := mustBuild(t, logInput(joinLines(failureLog())), testOpt)
	shifted := lineNumberRE.ReplaceAllFunc(raw, func(m []byte) []byte {
		n, _ := strconv.Atoi(string(lineNumberRE.FindSubmatch(m)[1]))
		return []byte(fmt.Sprintf(`{"n":%d,"text"`, n+1))
	})
	dropped := regexp.MustCompile(`("omitted":\[)\{"start":[0-9]+,"end":[0-9]+,"reason":"[a-z_]+"\},?`).ReplaceAll(raw, []byte("$1"))
	for name, b := range map[string][]byte{"shifted line numbers": shifted, "missing omission": dropped} {
		if bytes.Equal(b, raw) {
			t.Fatalf("%s: the mutation changed nothing", name)
		}
		if r := bundle.ValidateV1(b); r.Code != bundle.CodeLineMapInvalid || !strings.HasPrefix(r.Pointer, "/sources/0/") {
			t.Errorf("%s: %s at %s, want line_map_invalid in /sources/0", name, r.Code, r.Pointer)
		}
	}
}

// Negative control: a v1 bundle from the producer is not a v0 bundle.
func TestProducerOutputIsNotV0(t *testing.T) {
	raw, _, _ := mustBuild(t, logInput(joinLines(failureLog())), testOpt)
	if r := bundle.Validate(raw); r.Accepted() {
		t.Fatal("v0 accepted a v1 bundle")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	a, _, _ := mustBuild(t, logInput(secretLog()), testOpt)
	b, _, _ := mustBuild(t, logInput(secretLog()), testOpt)
	if !bytes.Equal(a, b) {
		t.Error("two builds of the same input differ")
	}
}

// fragments are the pieces random logs are made of. None holds a sentinel.
var fragments = []string{
	"\n", "\n", "\n", "\r\n", "\r", "\t", " ", "text ", "L", "0", "=", ":", "@", "?", "/", "\uFEFF", "\u00e9", "\u2028",
	"\x00", "\x07", "\x1b", "\x1b[", "\x1b[31m", "\x1b[0m", "\x1b]0;t", "\x1b]8;;", "\x1b\\", "\x1b(B", "\u009b", "\u009d", "\u009c",
	"\xff", "\xc0\xaf", "\xed\xa0\x80", "\xe2\x82",
	"Error: ", "##[error]", "Process completed with exit code 1.", "npm ERR! ", "FAILED ", "Timed out ",
	"-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
	"token", "password", "Authorization", "Bearer ", "https://", "ghp_", "AKIA", "eyJ", "=>", ":=", `\`, `\"`, `\'`,
}

// secretForms are sentinels in forms the rules are documented to match,
// each set off by spaces or whole lines.
var secretForms = []string{
	" token=" + fakePassword + " ", " password: " + fakePassword + " ", " DB_PASSWORD=" + fakePassword + " ",
	" Authorization: Bearer " + fakeBearer + " ", " Bearer " + fakeBearer + " ", " authorization=Basic dXNlcjpTRU5USU5FTA== ",
	" https://user:PASSSENTINEL@example.com/r.git ", " https://example.com/p?sig=" + fakeSig + " ", " " + fakeSignedURL + " ",
	" " + fakeGitHubToken + " ", " PAT=" + fakePAT + " ", " " + fakeAWSKeyID + " ", " " + fakeSlack + " ", " " + fakeNPM + " ",
	" " + fakeJWT + " ", " sentinel.person@example.com ", ` {"client_secret": "CLIENTSECRETSENTINEL"} `,
	"\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + fakeKeyBody + "\n" + fakeKeyBody + "\n-----END OPENSSH PRIVATE KEY-----\n",
	" -----BEGIN EC PRIVATE KEY-----" + fakeKeyBody + "-----END EC PRIVATE KEY----- ",
	" 'password' => '" + fakePassword + "' ", " password := " + fakePassword + " ", " :token=>\"" + fakePassword + "\" ",
	` {\"client_secret\":\"CLIENTSECRETSENTINEL\"} `, " token=\\\"" + fakePassword + "\\\" ",
}

func randomLog(r *rand.Rand) []byte {
	var b bytes.Buffer
	for n := r.IntN(400); n > 0; n-- {
		switch k := r.IntN(100); {
		case k < 2:
			b.WriteString(strings.Repeat("x", 1900+r.IntN(300))) // near the line limit
		case k < 3:
			b.WriteString(strings.Repeat("Error: y\n", 50+r.IntN(600)))
		case k < 15:
			b.WriteString(secretForms[r.IntN(len(secretForms))])
		default:
			b.WriteString(fragments[r.IntN(len(fragments))])
		}
	}
	return b.Bytes()
}

// Random logs built from awkward fragments and documented secret forms:
// every bundle validates, accounts for every line, keeps each included
// line's number and transformed text, and holds no sentinel, whatever
// escape sequences, controls or malformed bytes surround the secret forms.
func TestRandomLogs(t *testing.T) { checkRandomLogs(t, 3, 7, 1500) } // fixed seed: the same logs every run

func checkRandomLogs(t *testing.T, seed1, seed2 uint64, n int) {
	r := rand.New(rand.NewPCG(seed1, seed2))
	for iter := 0; iter < n; iter++ {
		raw := randomLog(r)
		out, sum, err := Build(logInput(raw), testOpt)
		if err != nil {
			t.Fatalf("log %d: %v", iter, err) // any error fails, ErrRangeLimit included: these logs are too short to reach it
		}
		if v := bundle.ValidateV1(out); !v.Accepted() {
			t.Fatalf("log %d: %s at %s", iter, v.Code, v.Pointer)
		}
		var doc struct {
			Sources []jobLogOut `json:"sources"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		j := doc.Sources[0]
		checkReasons(t, logInput(raw), testOpt, j)
		orig := splitLines(raw)
		if j.LineCount != int64(len(orig)) || sum.JobLog.LineCount != j.LineCount {
			t.Fatalf("log %d: line_count %d for %d lines", iter, j.LineCount, len(orig))
		}
		texts := make([]string, len(orig))
		for i, l := range orig {
			texts[i] = cleanLine(l, i == 0)
		}
		blocks := keyBlocks(texts)
		for _, l := range j.Lines {
			want, _ := redactLine(texts[l.N-1])
			if blocks[l.N-1] || l.Text != want || len(l.Text) > maxLineBytes || !validText(l.Text) {
				t.Fatalf("log %d: line %d is %q, want %q (block %v)", iter, l.N, l.Text, want, blocks[l.N-1])
			}
		}
		if l := leaked(out); len(l) > 0 {
			t.Fatalf("log %d: sentinels %q in the bundle", iter, l)
		}
	}
}

func FuzzBuild(f *testing.F) {
	f.Add([]byte("Error: x\n\x1b[31m##[error]boom\x1b[0m\r\nlast"))
	f.Add(secretLog())
	f.Add([]byte("\xff\xfe\x00\n\n\r\r\n-----BEGIN PRIVATE KEY-----\n"))
	// The range limit, which must be justified, and both limits together.
	keys := []string{"Error: x"}
	for i := 0; i < 300; i++ {
		keys = append(keys, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "ordinary")
	}
	f.Add(joinLines(keys))
	var both []string
	for i := 0; i < 301; i++ {
		both = append(both, "Error: "+strings.Repeat("a", 993), "Error: "+strings.Repeat("b", 2100))
	}
	f.Add(joinLines(both))
	f.Fuzz(func(t *testing.T, raw []byte) {
		out, sum, err := Build(logInput(raw), testOpt)
		if errors.Is(err, ErrRangeLimit) {
			// Allowed only when an independent recount agrees that the exact
			// reasons cannot fit.
			_, lines, perr := prepareLog(logInput(raw).Log, testOpt)
			if perr != nil {
				t.Fatal(perr)
			}
			// Build reached budget 0, whose selection includes nothing and
			// always fits the size limit: its ranges must not fit.
			dec, _ := choose(lines, 0)
			if exactRanges(dec) <= maxOmitted {
				t.Fatalf("ErrRangeLimit, but with no line included the exact reasons fit in %d ranges", exactRanges(dec))
			}
			return
		}
		if err != nil {
			t.Fatalf("Build: %v", err) // the metadata is valid, so no other error is allowed
		}
		if r := bundle.ValidateV1(out); !r.Accepted() {
			t.Fatalf("invalid output: %s at %s", r.Code, r.Pointer)
		}
		var doc struct {
			Sources []jobLogOut `json:"sources"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		j := doc.Sources[0]
		checkReasons(t, logInput(raw), testOpt, j)
		if j.LineCount != int64(len(splitLines(raw))) || sum.JobLog.LineCount != j.LineCount {
			t.Fatalf("line_count %d for %d lines", j.LineCount, len(splitLines(raw)))
		}
		for _, l := range j.Lines {
			if !utf8.ValidString(l.Text) || !validText(l.Text) {
				t.Fatalf("line %d is not clean text", l.N)
			}
		}
	})
}
