package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"aftergreen/collector/logbundle"
	"aftergreen/contracts/bundle"
)

// Offline: the mocked API and download, the collector with the log
// kept in memory, the producer and the v1 validator, end to end. The fixture
// log and every secret in it are invented; the secrets are assembled at run
// time so this file holds no token-shaped literal.

var updateGolden = flag.Bool("update-golden", false, "rewrite the producer fixture bundle in contracts/cases-v1")

const goldenPath = "../../contracts/cases-v1/valid-producer-fixture.json"

var (
	fixtureToken  = "ghp_" + strings.Repeat("F1x", 12)
	fixtureSigned = "https://cdn.example.test/pkg.tgz?se=2026-11-01&sig=FIXTURE-SIGNED-" + "SENTINEL"
	fixtureKey    = "FIXTUREKEY" + "SENTINEL" + strings.Repeat("B", 40)
)

// fixtureSentinels must never appear in a bundle.
var fixtureSentinels = []string{"F1xF1xF1xF1x", "FIXTURE-SIGNED-SENTINEL", "FIXTUREKEYSENTINEL", "SIGNATURE-SENTINEL", "sig=", tLogPath}

var fixedCreated = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func simulatedOpt() logbundle.Options {
	return logbundle.Options{EvidenceClass: "simulated", Tool: "aftergreen-collect", APIVersion: APIVersion, CreatedAt: fixedCreated}
}

// fixtureLog is shaped like a GitHub Actions job log: a byte-order mark,
// timestamps, groups, colour codes, a test failure and its exit code, with a
// token, a signed URL and a private key that a careless step printed.
func fixtureLog() string {
	ts := func(s int) string { return fmt.Sprintf("2026-11-01T10:%02d:%02d.0000000Z ", 1+s/60, s%60) }
	var l []string
	add := func(s int, text string) { l = append(l, ts(s)+text) }
	add(0, "##[group]Runner Image Provisioner")
	add(0, "Hosted Compute Agent")
	add(0, "##[endgroup]")
	add(1, "##[group]Run actions/checkout@v4")
	add(1, "with:")
	add(1, "  token: ***")
	add(1, "##[endgroup]")
	for i := 0; i < 20; i++ {
		add(2+i, fmt.Sprintf("added %d packages in %ds", 10+i, i))
	}
	add(30, "##[group]Run npm test")
	add(30, "npm test")
	add(30, "##[endgroup]")
	for i := 0; i < 15; i++ {
		add(33+i, fmt.Sprintf("  ok %d - fixture test %d", i+1, i+1))
	}
	add(50, "\x1b[31m  1) fixture.spec.ts:12:5 > renders the page\x1b[39m")
	add(50, "debug: using token "+fixtureToken)
	add(50, "debug: fetching "+fixtureSigned)
	add(50, "    Error: expect(received).toBe(expected)")
	add(50, "    Expected: 2")
	add(50, "    Received: 1")
	add(50, "-----BEGIN OPENSSH PRIVATE KEY-----")
	add(50, fixtureKey)
	add(50, "-----END OPENSSH PRIVATE KEY-----")
	for i := 0; i < 25; i++ {
		add(51+i, fmt.Sprintf("  ok %d - fixture test %d", 16+i, 16+i))
	}
	add(80, "  1 failed")
	add(80, "##[error]Process completed with exit code 1.")
	add(81, "Post job cleanup.")
	return "\uFEFF" + strings.Join(l[:10], "\r\n") + "\r\n" + strings.Join(l[10:], "\n") + "\n"
}

type bundleDoc struct {
	Schema        string `json:"schema"`
	EvidenceClass string `json:"evidence_class"`
	Collection    struct {
		MetadataAuthentication string `json:"metadata_authentication"`
	} `json:"collection"`
	Runs []struct {
		HeadSHA  string `json:"head_sha"`
		Checkout struct {
			Status, Reason string
		} `json:"checkout"`
		Matrix struct {
			Status, Reason string
		} `json:"matrix"`
		Runner struct {
			OS, Arch string
			Labels   []string
		} `json:"runner"`
	} `json:"runs"`
	Sources []struct {
		ID             string `json:"id"`
		Status         string `json:"status"`
		MissingReason  string `json:"missing_reason"`
		Extent         string `json:"extent"`
		ReceivedBytes  int64  `json:"received_bytes"`
		ReceivedSHA256 string `json:"received_sha256"`
		Authentication string `json:"authentication"`
		LineCount      int64  `json:"line_count"`
		Redactions     int    `json:"redactions"`
		Lines          []struct {
			N    int64  `json:"n"`
			Text string `json:"text"`
		} `json:"lines"`
		Omitted []struct {
			Start, End int64
			Reason     string
		} `json:"omitted"`
	} `json:"sources"`
}

func decodeBundle(t *testing.T, raw []byte) bundleDoc {
	t.Helper()
	if r := bundle.ValidateV1(raw); !r.Accepted() {
		t.Fatalf("the bundle does not validate: %s at %s", r.Code, r.Pointer)
	}
	var d bundleDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func noSentinels(t *testing.T, raw []byte) {
	t.Helper()
	for _, s := range append(fixtureSentinels, tLogHost) { // the report may name the host; a bundle never does
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("the bundle holds %q", s)
		}
	}
	if containsPiece(raw, tToken) {
		t.Error("the bundle holds a piece of the credential")
	}
}

func TestCollectBundleOffline(t *testing.T) {
	m := newMockH2(t)
	oneFailedJob(m)
	m.logRedirect(2002, textReply(fixtureLog()))
	src := tokenSource()
	rep, raw, sum, err := collectBundle(context.Background(), tRef, DefaultLimits(), m.transport(), src, simulatedOpt())
	if err != nil || rep.Outcome != "complete" || src.calls != 1 {
		t.Fatalf("err %v, outcome %s, stop %+v, source calls %d", err, rep.Outcome, rep.Stop, src.calls)
	}
	if err := credentialPlacement(m.snapshot(), tToken); err != nil {
		t.Fatal(err)
	}
	tokenOffAPI(t, m)
	noToken(t, rep)
	noLeak(t, rep, fixtureSentinels...)
	noSentinels(t, raw)

	d := decodeBundle(t, raw)
	job := d.Sources[0]
	if d.EvidenceClass != "simulated" || d.Collection.MetadataAuthentication != "none" || job.ID != "failed.job_log" ||
		job.Status != "present" || job.Extent != "complete" || job.Authentication != "gh_cli" {
		t.Fatalf("bundle %+v", d)
	}
	// The bundle's received-bytes claims are the collector's measurements.
	if job.ReceivedBytes != rep.Log.BytesRead || job.ReceivedSHA256 != rep.Log.SHA256 || job.LineCount != rep.Log.Lines ||
		job.LineCount != 82 || job.ReceivedBytes != int64(len(fixtureLog())) {
		t.Errorf("job log bytes %d sha %s lines %d; collector %d %s %d", job.ReceivedBytes, job.ReceivedSHA256, job.LineCount,
			rep.Log.BytesRead, rep.Log.SHA256, rep.Log.Lines)
	}
	// Nothing is inferred: head_sha stays run metadata; checkout, matrix and
	// the runner stay unresolved; the other sources are missing.
	run := d.Runs[0]
	if run.HeadSHA != tSHA || run.Checkout.Status != "unresolved" || run.Checkout.Reason != "workflow_not_collected" ||
		run.Matrix.Status != "unresolved" || run.Runner.OS != "unknown" || run.Runner.Arch != "unknown" ||
		fmt.Sprint(run.Runner.Labels) != "[ubuntu-latest]" {
		t.Errorf("run %+v", run)
	}
	for _, s := range d.Sources[1:] {
		if s.Status != "missing" || s.MissingReason != "not_collected" {
			t.Errorf("source %s is %s (%s)", s.ID, s.Status, s.MissingReason)
		}
	}
	if sum.JobLog.Redactions["github-token"] != 1 || sum.JobLog.Redactions["url-query"] != 1 || sum.JobLog.OmittedLines["redacted"] != 3 {
		t.Errorf("summary %+v", sum.JobLog)
	}

	if *updateGolden {
		if err := os.WriteFile(goldenPath, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s (%d bytes, digest %s)", goldenPath, len(raw), sum.EvidenceSHA256)
	}
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("%v (run with -update-golden to create it)", err)
	}
	if !bytes.Equal(raw, golden) {
		t.Error("the producer's output differs from the golden bundle")
	}
}

func TestCollectBundleUnauthenticated(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	m.logRedirect(2002, textReply(fixtureLog()))
	rep, raw, _, err := collectBundle(context.Background(), tRef, DefaultLimits(), m.transport(), nil, simulatedOpt())
	if err != nil {
		t.Fatalf("err %v, stop %+v", err, rep.Stop)
	}
	for _, h := range m.snapshot() {
		if h.header.Get("Authorization") != "" {
			t.Errorf("%s carried a credential", h.key)
		}
	}
	if d := decodeBundle(t, raw); d.Sources[0].Authentication != "none" {
		t.Errorf("authentication %q", d.Sources[0].Authentication)
	}
	noSentinels(t, raw)
}

// Without a selected failed job there is no bundle and gh is never run.
func TestCollectBundleNeedsASelectedJob(t *testing.T) {
	m := newMock(t)
	m.handle(api+"/rate_limit", jsonReply(59, 200, rateLimitBody(59)))
	m.handle(api+runURI(), jsonReply(58, 200, runBody(1, "pull_request", "completed", "failure")))
	m.handle(api+attemptURI(1), jsonReply(57, 200, runBody(1, "pull_request", "completed", "failure")))
	src := tokenSource()
	rep, raw, sum, err := collectBundle(context.Background(), tRef, DefaultLimits(), m.transport(), src, simulatedOpt())
	if !errors.Is(err, logbundle.ErrIncomplete) || raw != nil || sum != nil || src.calls != 0 {
		t.Fatalf("err %v, bundle %d bytes, source calls %d", err, len(raw), src.calls)
	}
	wantStop(t, rep, "stopped", "attempt", "run_not_eligible")
}

// A missing log is recorded as missing, with the reason, not replaced.
func TestCollectBundleLogMissing(t *testing.T) {
	for name, c := range map[string]struct {
		install func(m *mockGH)
		src     credentialSource
		reason  string
	}{
		"log denied": {func(m *mockGH) {
			m.handle(api+logURI(2002), jsonReply(55, http.StatusForbidden, map[string]any{"message": "denied"}))
		}, nil, "access_denied"},
		"log gone": {func(m *mockGH) {
			m.handle(api+logURI(2002), jsonReply(55, http.StatusGone, map[string]any{"message": "gone"}))
		}, nil, "expired"},
		"credential unavailable": {func(m *mockGH) {}, &countingSource{err: errors.New("no login")}, "not_collected"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			c.install(m)
			rep, raw, sum, err := collectBundle(context.Background(), tRef, DefaultLimits(), m.transport(), c.src, simulatedOpt())
			if err != nil || rep.Stop == nil {
				t.Fatalf("err %v, stop %+v", err, rep.Stop)
			}
			d := decodeBundle(t, raw)
			if j := d.Sources[0]; j.Status != "missing" || j.MissingReason != c.reason || j.Lines != nil || sum.JobLog.Status != "missing" {
				t.Errorf("job log %+v", j)
			}
		})
	}
}

// A partial download is labelled partial; its lines are the bytes received.
func TestCollectBundlePartialLog(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	m.logRedirect(2002, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "100000") // more than is sent
		w.Write([]byte("Error: first line\nsecond, cut"))
	})
	_, raw, sum, err := collectBundle(context.Background(), tRef, DefaultLimits(), m.transport(), nil, simulatedOpt())
	if err != nil {
		t.Fatal(err)
	}
	if j := decodeBundle(t, raw).Sources[0]; j.Status != "present" || j.Extent != "partial" || j.LineCount != 2 || sum.JobLog.Extent != "partial" {
		t.Errorf("job log %+v", j)
	}
}

// The final guard: a bundle that would hold part of the credential is
// discarded. Redaction catches the whole token; a bare piece of it gets past
// redaction and is caught here.
func TestCollectBundleDiscardsCredentialEcho(t *testing.T) {
	for name, c := range map[string]struct {
		log  string
		want error
	}{
		"whole token is redacted": {"Error: echo " + tToken + "\n", nil},
		"a piece is caught":       {"Error: echo " + tToken[6:22] + "\n", ErrCredentialInBundle},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			m.logRedirect(2002, textReply(c.log))
			rep, raw, _, err := collectBundle(context.Background(), tRef, DefaultLimits(), m.transport(), tokenSource(), simulatedOpt())
			if !errors.Is(err, c.want) || (err != nil) != (raw == nil) {
				t.Fatalf("err %v, bundle %d bytes", err, len(raw))
			}
			if raw != nil && containsPiece(raw, tToken) {
				t.Fatal("the bundle holds a piece of the credential")
			}
			noToken(t, rep)
		})
	}
}

// The exported entry point labels its bundle collected_public and checks its
// auth argument before any request.
func TestCollectBundleEntryPoint(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	m.logRedirect(2002, textReply(fixtureLog()))
	src := tokenSource()
	useEntryPoints(t, m.transport(), src)
	_, raw, _, err := CollectBundle(context.Background(), tRef, DefaultLimits(), "gh", fixedCreated)
	if err != nil || src.calls != 1 {
		t.Fatalf("err %v, source calls %d", err, src.calls)
	}
	if d := decodeBundle(t, raw); d.EvidenceClass != "collected_public" {
		t.Errorf("evidence class %q", d.EvidenceClass)
	}
	if err := credentialPlacement(m.snapshot(), tToken); err != nil {
		t.Error(err)
	}

	ct := &countingTransport{t: t, fail: true}
	useEntryPoints(t, ct, src)
	if rep, raw, _, err := CollectBundle(context.Background(), tRef, DefaultLimits(), "token", fixedCreated); err == nil || rep != nil || raw != nil {
		t.Errorf("auth %q accepted", "token")
	}
	for _, ref := range invalidRefs() {
		if _, raw, _, err := CollectBundle(context.Background(), ref, DefaultLimits(), "gh", fixedCreated); err == nil || raw != nil {
			t.Errorf("invalid ref %+v produced a bundle", ref)
		}
	}
	if ct.calls.Load() != 0 || src.calls != 1 {
		t.Errorf("%d requests and %d credential calls for invalid input", ct.calls.Load(), src.calls-1)
	}
}
