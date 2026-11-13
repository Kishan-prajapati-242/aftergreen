package github

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"
)

// Offline tests: every connection goes to a local TLS test server, whatever
// host the URL names, and the server answers by Host and request URI. The
// fixtures are invented; nothing here is a real GitHub response.

const (
	tOwner   = "probe-test"
	tRepo    = "fixture"
	tRun     = int64(1001)
	tSHA     = "0123456789abcdef0123456789abcdef01234567"
	api      = "api.github.com"
	tLogHost = "productionresultssa7.blob.core.windows.net"
	tLogPath = "/actions-results/0000/job-logs.txt"
	tLogSig  = "rsct=text%2Fplain&se=2026-11-07T00%3A01%3A00Z&sig=SIGNATURE-SENTINEL-77&sp=r"
	sentinel = "LOG-TEXT-SENTINEL"
)

var tRef = RunRef{Owner: tOwner, Repo: tRepo, RunID: tRun}

func runURI() string {
	return fmt.Sprintf("/repos/%s/%s/actions/runs/%d?exclude_pull_requests=true", tOwner, tRepo, tRun)
}

func attemptURI(a int64) string {
	return fmt.Sprintf("/repos/%s/%s/actions/runs/%d/attempts/%d?exclude_pull_requests=true", tOwner, tRepo, tRun, a)
}

func jobsURI(a int64, page int) string {
	return fmt.Sprintf("/repos/%s/%s/actions/runs/%d/attempts/%d/jobs?page=%d&per_page=100", tOwner, tRepo, tRun, a, page)
}

func logURI(job int64) string {
	return fmt.Sprintf("/repos/%s/%s/actions/jobs/%d/logs", tOwner, tRepo, job)
}

const blobURI = tLogHost + tLogPath + "?" + tLogSig

type hit struct {
	key    string // host + request URI
	header http.Header
}

type mockGH struct {
	t       *testing.T
	srv     *httptest.Server
	release chan struct{}
	mu      sync.Mutex
	routes  map[string]http.HandlerFunc
	hits    []hit
	dialed  []string
}

func newMock(t *testing.T) *mockGH { return startMock(t, false) }

// newMockH2 serves HTTP/2 as well, which the production transport prefers.
func newMockH2(t *testing.T) *mockGH { return startMock(t, true) }

func startMock(t *testing.T, h2 bool) *mockGH {
	m := &mockGH{t: t, release: make(chan struct{}), routes: map[string]http.HandlerFunc{}}
	m.srv = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	m.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	m.srv.EnableHTTP2 = h2
	m.srv.StartTLS()
	t.Cleanup(m.srv.Close)
	t.Cleanup(func() { close(m.release) }) // runs first: unblocks handlers before Close
	return m
}

func (m *mockGH) serve(w http.ResponseWriter, r *http.Request) {
	key := r.Host + r.URL.RequestURI()
	m.mu.Lock()
	m.hits = append(m.hits, hit{key: key, header: r.Header.Clone()})
	h := m.routes[key]
	m.mu.Unlock()
	if h == nil {
		m.t.Errorf("unexpected request %s", key)
		http.Error(w, "no such route", http.StatusTeapot)
		return
	}
	h(w, r)
}

func (m *mockGH) handle(key string, h http.HandlerFunc) {
	m.mu.Lock()
	m.routes[key] = h
	m.mu.Unlock()
}

// block holds a response until the client goes away or the test ends.
func (m *mockGH) block(r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-m.release:
	}
}

// transport is the production transport (NewTransport) with two changes:
// every connection goes to the mock, whatever host the URL names, skipping
// the public-address check that loopback would fail; and TLS is verified
// against the mock's certificate. Every other setting is production's.
func (m *mockGH) transport() *http.Transport {
	tr := NewTransport()
	roots := m.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "example.com"} // the httptest certificate's name
	addr := m.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		m.mu.Lock()
		m.dialed = append(m.dialed, address)
		m.mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	return tr
}

func (m *mockGH) probe(ref RunRef, lim Limits) *Report {
	return probe(context.Background(), ref, lim, m.transport(), nil)
}

func (m *mockGH) keys() []string {
	var out []string
	for _, h := range m.snapshot() {
		out = append(out, h.key)
	}
	return out
}

func (m *mockGH) snapshot() []hit {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.hits)
}

func rateHeaders(w http.ResponseWriter, remaining int64) {
	w.Header().Set("X-RateLimit-Limit", "60")
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))
	w.Header().Set("X-RateLimit-Used", strconv.FormatInt(60-remaining, 10))
	w.Header().Set("X-RateLimit-Reset", "1794102693")
	w.Header().Set("X-RateLimit-Resource", "core")
}

func jsonReply(remaining int64, status int, v any) http.HandlerFunc {
	body, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rateHeaders(w, remaining)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-GitHub-Api-Version-Selected", APIVersion)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(status)
		w.Write(body)
	}
}

func rateLimitBody(remaining int64) map[string]any {
	return map[string]any{"resources": map[string]any{"core": map[string]any{
		"limit": 60, "remaining": remaining, "reset": 1794102693, "used": 60 - remaining}}}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func runBody(attempt int64, event, status, conclusion string) map[string]any {
	repo := map[string]any{"id": 42, "full_name": tOwner + "/" + tRepo, "private": false}
	return map[string]any{
		"id": tRun, "name": "CI", "head_branch": "main", "head_sha": tSHA, "path": ".github/workflows/ci.yml",
		"run_number": 7, "run_attempt": attempt, "event": event, "status": nullable(status), "conclusion": nullable(conclusion),
		"workflow_id": 99, "created_at": "2026-11-01T10:00:00Z", "updated_at": "2026-11-01T12:30:00Z",
		"run_started_at": fmt.Sprintf("2026-11-01T1%d:00:00Z", attempt), "repository": repo, "head_repository": repo,
	}
}

func jobBody(id, attempt int64, name, conclusion string) map[string]any {
	return map[string]any{
		"id": id, "run_id": tRun, "run_attempt": attempt, "head_sha": tSHA, "status": "completed",
		"conclusion": conclusion, "name": name, "started_at": "2026-11-01T10:01:00Z", "completed_at": "2026-11-01T10:05:00Z",
		"labels": []string{"ubuntu-latest"},
		"steps": []any{
			map[string]any{"name": "Set up job", "number": 1, "status": "completed", "conclusion": "success"},
			map[string]any{"name": "npm ci", "number": 2, "status": "completed", "conclusion": conclusion},
		},
	}
}

func jobsBody(jobs ...map[string]any) map[string]any {
	return map[string]any{"total_count": len(jobs), "jobs": jobs}
}

// standard installs the allowance, run, attempt and first jobs page routes.
func (m *mockGH) standard(latest int64, jobsByAttempt map[int64][]map[string]any) {
	m.handle(api+"/rate_limit", jsonReply(59, 200, rateLimitBody(59)))
	m.handle(api+runURI(), jsonReply(58, 200, runBody(latest, "push", "completed", "failure")))
	for a, jobs := range jobsByAttempt {
		m.handle(api+attemptURI(a), jsonReply(57, 200, runBody(a, "push", "completed", "failure")))
		m.handle(api+jobsURI(a, 1), jsonReply(56, 200, jobsBody(jobs...)))
	}
}

// logRedirect installs the documented job-log redirect and its destination.
func (m *mockGH) logRedirect(job int64, blob http.HandlerFunc) {
	m.handle(api+logURI(job), func(w http.ResponseWriter, r *http.Request) {
		rateHeaders(w, 55)
		w.Header().Set("Location", "https://"+tLogHost+tLogPath+"?"+tLogSig)
		w.WriteHeader(http.StatusFound)
	})
	m.handle(blobURI, blob)
}

func textReply(text string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(text)))
		io.WriteString(w, text)
	}
}

// chunkedReply writes the parts with a flush between them, so the response
// has no Content-Length.
func chunkedReply(parts ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for _, p := range parts {
			io.WriteString(w, p)
			w.(http.Flusher).Flush()
		}
	}
}

func oneFailedJob(m *mockGH) {
	m.standard(1, map[int64][]map[string]any{1: {jobBody(2001, 1, "lint", "success"), jobBody(2002, 1, "test", "failure")}})
}

func reportText(t *testing.T, rep *Report) string {
	t.Helper()
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// noLeak checks that the report holds no signed URL part, log text or token.
func noLeak(t *testing.T, rep *Report, extra ...string) {
	t.Helper()
	text := reportText(t, rep)
	for _, s := range append([]string{"SIGNATURE-SENTINEL", "sig=", tLogPath, sentinel, "TOKEN-SENTINEL"}, extra...) {
		if strings.Contains(text, s) {
			t.Errorf("report contains %q", s)
		}
	}
}

func wantStop(t *testing.T, rep *Report, outcome, stage, code string) {
	t.Helper()
	if rep.Outcome != outcome || rep.Stop == nil || rep.Stop.Stage != stage || rep.Stop.Code != code {
		t.Fatalf("outcome %s, stop %+v; want %s with %s at %s", rep.Outcome, rep.Stop, outcome, code, stage)
	}
}

func TestProbeCompleteRun(t *testing.T) {
	t.Run("HTTP/1.1", func(t *testing.T) { completeRun(t, newMock(t), "HTTP/1.1") })
	t.Run("HTTP/2", func(t *testing.T) { completeRun(t, newMockH2(t), "HTTP/2.0") })
}

func completeRun(t *testing.T, m *mockGH, proto string) {
	t.Setenv("GITHUB_TOKEN", "TOKEN-SENTINEL") // the code never reads the environment; this guards that
	t.Setenv("GH_TOKEN", "TOKEN-SENTINEL")
	oneFailedJob(m)
	text := "first " + sentinel + "\r\nsecond\nthird" // three lines by bundle v0 section 4
	m.logRedirect(2002, textReply(text))

	rep := m.probe(tRef, DefaultLimits())
	if rep.Outcome != "complete" || rep.Stop != nil {
		t.Fatalf("outcome %s, stop %+v", rep.Outcome, rep.Stop)
	}
	wantKeys := []string{api + "/rate_limit", api + runURI(), api + attemptURI(1), api + jobsURI(1, 1), api + logURI(2002), blobURI}
	if got := m.keys(); !slices.Equal(got, wantKeys) {
		t.Fatalf("requests\n got %q\nwant %q", got, wantKeys)
	}
	hits := m.snapshot()
	for i, h := range hits {
		if h.header.Get("Authorization") != "" || h.header.Get("Cookie") != "" {
			t.Errorf("request %d carried a credential or cookie", i+1)
		}
		if i < 5 && (h.header.Get("X-GitHub-Api-Version") != APIVersion || h.header.Get("Accept") != "application/vnd.github+json") {
			t.Errorf("API request %d headers %v", i+1, h.header)
		}
	}
	for name, v := range hits[5].header {
		if name != "User-Agent" && !(name == "Connection" && v[0] == "close") {
			t.Errorf("the redirected download carried header %s; want only User-Agent", name)
		}
	}
	for i, rq := range rep.Requests {
		if rq.Proto != proto {
			t.Errorf("request %d protocol %q; want %q", i+1, rq.Proto, proto)
		}
	}
	m.mu.Lock()
	dials := len(m.dialed)
	m.mu.Unlock()
	if dials != 6 {
		t.Errorf("%d connections for 6 requests; keep-alive should be off", dials)
	}
	if _, err := time.Parse(time.RFC3339, rep.StartedAt); err != nil {
		t.Errorf("started_at %q: %v", rep.StartedAt, err)
	}
	sum := sha256.Sum256([]byte(text))
	declared := int64(len(text))
	wantLog := LogInfo{State: "complete", APIStatus: 302, RedirectHost: tLogHost, DownloadStatus: 200, ContentType: "text/plain",
		DeclaredBytes: &declared, BytesRead: int64(len(text)), Lines: 3, SHA256: hex.EncodeToString(sum[:])}
	if got, want := jsonText(rep.Log), jsonText(wantLog); got != want {
		t.Errorf("log\n got %s\nwant %s", got, want)
	}
	r, j := rep.Run, rep.Job
	if r.ID != tRun || r.Attempt != 1 || r.LatestAttempt != 1 || r.Event != "push" || r.Status != "completed" ||
		r.Conclusion != "failure" || r.HeadSHA != tSHA || r.HeadBranch != "main" || r.WorkflowPath != ".github/workflows/ci.yml" ||
		r.RunStartedAt != "2026-11-01T11:00:00Z" || rep.Repository.ID != 42 {
		t.Errorf("run %+v repository %+v", r, rep.Repository)
	}
	if j.ID != 2002 || j.Name != "test" || *j.RunAttempt != 1 || j.Conclusion != "failure" ||
		jsonText(j.FailedSteps) != `[{"number":2,"name":"npm ci"}]` {
		t.Errorf("job %+v", j)
	}
	if rep.Allowance == nil || rep.Allowance.Remaining != 59 || rep.Allowance.Needed != 6 {
		t.Errorf("allowance %+v", rep.Allowance)
	}
	if rl := rep.Requests[1].RateLimit; rl == nil || *rl.Remaining != 58 || rl.ResetAt != "2026-11-08T01:51:33Z" || rl.Resource != "core" {
		t.Errorf("rate limit record %+v", rl)
	}
	if rep.Budget.Requests != 6 || rep.Requests[5].Route != "GET [job-log redirect destination; path and query not recorded]" ||
		rep.Requests[5].BodyBytes != int64(len(text)) || rep.Requests[4].BodyBytes != 0 {
		t.Errorf("budget %+v, requests %s", rep.Budget, jsonText(rep.Requests))
	}
	var total int64
	for _, rq := range rep.Requests {
		total += rq.BodyBytes
	}
	if rep.Budget.BodyBytes != total {
		t.Errorf("budget body bytes %d; requests sum to %d", rep.Budget.BodyBytes, total)
	}
	for _, want := range []string{"latest attempt at probe time (1)", "head_sha is run metadata", "hashed and counted, then discarded"} {
		if !strings.Contains(strings.Join(rep.Uncertainty, " | "), want) {
			t.Errorf("uncertainty %q lacks %q", rep.Uncertainty, want)
		}
	}
	noLeak(t, rep)
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestProbeAttemptIdentity(t *testing.T) {
	two := map[int64][]map[string]any{
		1: {jobBody(2101, 1, "test", "failure")},
		2: {jobBody(2201, 2, "test", "failure")},
	}
	t.Run("no attempt in the URL: the latest attempt and its own jobs route", func(t *testing.T) {
		m := newMock(t)
		m.standard(2, two)
		m.logRedirect(2201, textReply("ok\n"))
		rep := m.probe(tRef, DefaultLimits())
		if rep.Outcome != "complete" || rep.Run.Attempt != 2 || rep.Job.ID != 2201 {
			t.Fatalf("outcome %s attempt %d job %+v stop %+v", rep.Outcome, rep.Run.Attempt, rep.Job, rep.Stop)
		}
		if keys := m.keys(); !slices.Contains(keys, api+jobsURI(2, 1)) || slices.Contains(keys, api+jobsURI(1, 1)) {
			t.Errorf("requests %q", keys)
		}
	})
	t.Run("an earlier attempt from the URL", func(t *testing.T) {
		m := newMock(t)
		m.standard(2, two)
		m.logRedirect(2101, textReply("ok\n"))
		ref := tRef
		ref.Attempt = 1
		rep := m.probe(ref, DefaultLimits())
		if rep.Outcome != "complete" || rep.Run.Attempt != 1 || rep.Run.LatestAttempt != 2 || rep.Job.ID != 2101 ||
			rep.Run.RunStartedAt != "2026-11-01T11:00:00Z" {
			t.Fatalf("outcome %s run %+v job %+v stop %+v", rep.Outcome, rep.Run, rep.Job, rep.Stop)
		}
		if keys := m.keys(); slices.Contains(keys, api+jobsURI(2, 1)) || slices.Contains(keys, api+attemptURI(2)) {
			t.Errorf("requests %q", keys)
		}
		if !strings.Contains(strings.Join(rep.Uncertainty, " "), "Attempt 1 is not the run's latest attempt (2)") {
			t.Errorf("uncertainty %q", rep.Uncertainty)
		}
	})
	t.Run("an attempt after the latest", func(t *testing.T) {
		m := newMock(t)
		m.standard(2, two)
		ref := tRef
		ref.Attempt = 3
		rep := m.probe(ref, DefaultLimits())
		wantStop(t, rep, "stopped", "run", "attempt_not_found")
		if len(m.keys()) != 2 {
			t.Errorf("requests %q", m.keys())
		}
	})
	t.Run("the attempt endpoint describes another attempt", func(t *testing.T) {
		m := newMock(t)
		m.standard(2, two)
		m.handle(api+attemptURI(1), jsonReply(57, 200, runBody(2, "push", "completed", "failure")))
		ref := tRef
		ref.Attempt = 1
		wantStop(t, m.probe(ref, DefaultLimits()), "stopped", "attempt", "attempt_mismatch")
	})
	t.Run("the attempt's job list holds a job of another attempt", func(t *testing.T) {
		m := newMock(t)
		m.standard(2, map[int64][]map[string]any{1: {jobBody(2101, 1, "lint", "success"), jobBody(2201, 2, "test", "failure")}})
		ref := tRef
		ref.Attempt = 1
		rep := m.probe(ref, DefaultLimits())
		wantStop(t, rep, "stopped", "jobs", "attempt_mismatch")
		if rep.Job != nil || slices.Contains(m.keys(), api+logURI(2201)) {
			t.Error("a job of another attempt was used")
		}
	})
	t.Run("the attempt's job list holds a job of another run", func(t *testing.T) {
		m := newMock(t)
		other := jobBody(2102, 1, "test", "failure")
		other["run_id"] = 999
		m.standard(1, map[int64][]map[string]any{1: {other}})
		wantStop(t, m.probe(tRef, DefaultLimits()), "stopped", "jobs", "attempt_mismatch")
	})
	t.Run("an explicit job of another attempt", func(t *testing.T) {
		m := newMock(t)
		m.standard(2, two)
		ref := tRef
		ref.Attempt, ref.JobID = 1, 2201
		wantStop(t, m.probe(ref, DefaultLimits()), "stopped", "select", "job_not_in_attempt")
	})
	t.Run("jobs that do not state their attempt", func(t *testing.T) {
		m := newMock(t)
		j := jobBody(2101, 1, "test", "failure")
		delete(j, "run_attempt")
		m.standard(1, map[int64][]map[string]any{1: {j}})
		m.logRedirect(2101, textReply("ok\n"))
		rep := m.probe(tRef, DefaultLimits())
		if rep.Outcome != "complete" || rep.Job.RunAttempt != nil ||
			!strings.Contains(strings.Join(rep.Uncertainty, " "), "did not state run_attempt") {
			t.Fatalf("outcome %s job %+v uncertainty %q", rep.Outcome, rep.Job, rep.Uncertainty)
		}
	})
}

func TestProbeJobSelection(t *testing.T) {
	jobs := map[int64][]map[string]any{1: {
		jobBody(2001, 1, "lint", "failure"), jobBody(2002, 1, "test (20)", "failure"), jobBody(2003, 1, "build", "success"),
	}}
	t.Run("several failed jobs need an explicit choice", func(t *testing.T) {
		m := newMock(t)
		m.standard(1, jobs)
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "select", "job_choice_required")
		if got := jsonText(rep.Jobs.Failed); got != `[{"id":2001,"name":"lint"},{"id":2002,"name":"test (20)"}]` {
			t.Errorf("choices %s", got)
		}
		if rep.Jobs.FailedCount != 2 || rep.Jobs.Conclusions["success"] != 1 || rep.Job != nil || len(m.keys()) != 4 {
			t.Errorf("jobs %+v job %+v requests %q", rep.Jobs, rep.Job, m.keys())
		}
	})
	t.Run("an explicit failed job", func(t *testing.T) {
		m := newMock(t)
		m.standard(1, jobs)
		m.logRedirect(2002, textReply("ok\n"))
		ref := tRef
		ref.JobID = 2002
		if rep := m.probe(ref, DefaultLimits()); rep.Outcome != "complete" || rep.Job.ID != 2002 {
			t.Fatalf("outcome %s job %+v stop %+v", rep.Outcome, rep.Job, rep.Stop)
		}
	})
	t.Run("an explicit job that did not fail", func(t *testing.T) {
		m := newMock(t)
		m.standard(1, jobs)
		ref := tRef
		ref.JobID = 2003
		wantStop(t, m.probe(ref, DefaultLimits()), "stopped", "select", "job_not_failed")
	})
	t.Run("no failed job", func(t *testing.T) {
		m := newMock(t)
		m.standard(1, map[int64][]map[string]any{1: {jobBody(2003, 1, "build", "success")}})
		wantStop(t, m.probe(tRef, DefaultLimits()), "stopped", "select", "no_failed_job")
	})
}

func TestProbeJobPages(t *testing.T) {
	page := func(from, n int, failID int64) []map[string]any {
		var out []map[string]any
		for id := int64(from); id < int64(from+n); id++ {
			c := "success"
			if id == failID {
				c = "failure"
			}
			out = append(out, jobBody(id, 1, "shard "+strconv.FormatInt(id, 10), c))
		}
		return out
	}
	install := func(m *mockGH, failID int64) {
		m.standard(1, nil)
		m.handle(api+attemptURI(1), jsonReply(57, 200, runBody(1, "push", "completed", "failure")))
		m.handle(api+jobsURI(1, 1), jsonReply(56, 200, map[string]any{"total_count": 150, "jobs": page(3000, 100, failID)}))
		m.handle(api+jobsURI(1, 2), jsonReply(55, 200, map[string]any{"total_count": 150, "jobs": page(3100, 50, failID)}))
	}
	t.Run("the failed job is on the second page", func(t *testing.T) {
		m := newMock(t)
		install(m, 3149)
		m.logRedirect(3149, textReply("ok\n"))
		rep := m.probe(tRef, DefaultLimits())
		if rep.Outcome != "complete" || rep.Job.ID != 3149 || rep.Jobs.Pages != 2 || rep.Jobs.Listed != 150 || !rep.Jobs.Complete {
			t.Fatalf("outcome %s jobs %+v stop %+v", rep.Outcome, rep.Jobs, rep.Stop)
		}
	})
	t.Run("more jobs than the page limit and no -job", func(t *testing.T) {
		m := newMock(t)
		install(m, 3050)
		lim := DefaultLimits()
		lim.MaxJobPages = 1
		rep := m.probe(tRef, lim)
		wantStop(t, rep, "stopped", "select", "job_list_incomplete")
		if rep.Jobs.Complete || rep.Jobs.Listed != 100 || slices.Contains(m.keys(), api+jobsURI(1, 2)) {
			t.Errorf("jobs %+v requests %q", rep.Jobs, m.keys())
		}
	})
	t.Run("more jobs than the page limit with a listed -job", func(t *testing.T) {
		m := newMock(t)
		install(m, 3050)
		m.logRedirect(3050, textReply("ok\n"))
		lim := DefaultLimits()
		lim.MaxJobPages = 1
		ref := tRef
		ref.JobID = 3050
		if rep := m.probe(ref, lim); rep.Outcome != "complete" || rep.Job.ID != 3050 {
			t.Fatalf("outcome %s stop %+v", rep.Outcome, rep.Stop)
		}
	})
	t.Run("an unlisted -job when the list is incomplete", func(t *testing.T) {
		m := newMock(t)
		install(m, 3149)
		lim := DefaultLimits()
		lim.MaxJobPages = 1
		ref := tRef
		ref.JobID = 3149
		wantStop(t, m.probe(ref, lim), "stopped", "select", "job_list_incomplete")
	})
}

func TestProbeLogUnavailable(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		code    string
		status  int
		detail  string
	}{
		{"access denied", jsonReply(50, 403, map[string]any{"message": "Must have admin rights to Repository."}),
			"access_denied", 403, "HTTP 403: Must have admin rights to Repository."},
		{"authentication required", jsonReply(50, 401, map[string]any{"message": "Requires authentication"}),
			"authentication_required", 401, "HTTP 401: Requires authentication"},
		{"not found", jsonReply(50, 404, map[string]any{"message": "Not Found"}), "not_found", 404, "HTTP 404: Not Found"},
		{"expired", jsonReply(50, 410, map[string]any{"message": "Gone"}), "gone", 410, "HTTP 410 (GitHub's message is withheld"},
		{"redirect without Location", func(w http.ResponseWriter, r *http.Request) {
			rateHeaders(w, 50)
			w.WriteHeader(http.StatusFound)
		}, "redirect_rejected", 302, "no Location header"},
		{"200 instead of the documented redirect", textReply(sentinel), "unexpected_status", 200, "documented response is 302"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			m.handle(api+logURI(2002), c.handler)
			rep := m.probe(tRef, DefaultLimits())
			wantStop(t, rep, "incomplete", "log", c.code)
			if rep.Stop.HTTPStatus != c.status || !strings.Contains(rep.Stop.Detail, c.detail) {
				t.Errorf("stop %+v; want status %d and detail containing %q", rep.Stop, c.status, c.detail)
			}
			if rep.Log.State != "unavailable" || rep.Log.BytesRead != 0 || rep.Log.SHA256 != "" || len(m.keys()) != 5 {
				t.Errorf("log %+v requests %q", rep.Log, m.keys())
			}
			noLeak(t, rep)
		})
	}
}

func TestProbeLogDownloadFailures(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		code    string
		status  int
	}{
		{"expired link", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "<Error>AuthenticationFailed SIGNATURE-SENTINEL-77</Error>")
		}, "download_failed", 403},
		{"missing blob", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }, "download_failed", 404},
		{"a second redirect", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://productionresultssa8.blob.core.windows.net/other")
			w.WriteHeader(http.StatusFound)
		}, "redirect_limit", 302},
		{"an unrequested encoding", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			io.WriteString(w, sentinel)
		}, "unexpected_encoding", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			m.logRedirect(2002, c.handler)
			rep := m.probe(tRef, DefaultLimits())
			wantStop(t, rep, "incomplete", "log_download", c.code)
			if rep.Stop.HTTPStatus != c.status || rep.Log.State != "unavailable" || rep.Log.RedirectHost != tLogHost {
				t.Errorf("stop %+v log %+v", rep.Stop, rep.Log)
			}
			if rep.Requests[5].BodyBytes != 0 || len(m.keys()) != 6 {
				t.Errorf("download body bytes %d, requests %q", rep.Requests[5].BodyBytes, m.keys())
			}
			noLeak(t, rep)
		})
	}
}

// A redirect that fails the policy is never requested or even dialed, and no
// part of its path or signed query reaches the report. Every Location below
// carries the fixture's signed path and query.
func TestProbeRejectsUnsafeRedirects(t *testing.T) {
	signed := tLogPath + "?" + tLogSig
	for _, loc := range []string{
		"https://evil.example" + signed,
		"http://" + tLogHost + signed,
		"https://user:pass@" + tLogHost + signed,
		"https://" + tLogHost + ":8443" + signed,
		"https://" + tLogHost + ":443" + signed,
		"https://" + tLogHost + ":x443" + signed,                // unparsable port
		"https://" + tLogHost + "/actions-results/%zz" + signed, // unparsable escape
		"https://20.60.0.1" + signed,
		"https://[::1]" + signed,
		"https://" + tLogHost + ".evil.example" + signed,
		"https://productionresultssa20.blob.core.windows.net" + signed,
		"https://evil.blob.core.windows.net" + signed,
		"https://pipelinesghubeus1.actions.githubusercontent.com" + signed,
		"https://api.github.com" + signed,
		signed, // relative
	} {
		t.Run(loc, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			m.handle(api+logURI(2002), func(w http.ResponseWriter, r *http.Request) {
				rateHeaders(w, 50)
				w.Header().Set("Location", loc)
				w.WriteHeader(http.StatusFound)
			})
			rep := m.probe(tRef, DefaultLimits())
			wantStop(t, rep, "incomplete", "log", "redirect_rejected")
			if rep.Log.State != "unavailable" || rep.Log.RedirectHost != "" || rep.Log.APIStatus != 302 || rep.Requests[4].Status != 302 {
				t.Errorf("log %+v request %+v", rep.Log, rep.Requests[4])
			}
			if keys := m.keys(); len(keys) != 5 || keys[4] != api+logURI(2002) {
				t.Errorf("requests %q", keys)
			}
			m.mu.Lock()
			defer m.mu.Unlock()
			for _, d := range m.dialed {
				if d != "api.github.com:443" {
					t.Errorf("dialed %s", d)
				}
			}
			noLeak(t, rep, "pass@", "actions-results", "%zz", "20.60.0.1", "::1")
		})
	}
}

func TestProbeBoundsResponses(t *testing.T) {
	small := func() Limits {
		l := DefaultLimits()
		l.MaxJSONBytes, l.MaxLogBytes = 2048, 1000
		return l
	}
	t.Run("API response over the limit by Content-Length is not read", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), func(w http.ResponseWriter, r *http.Request) {
			rateHeaders(w, 58)
			w.Header().Set("Content-Length", "4096")
			io.WriteString(w, strings.Repeat(" ", 4096))
		})
		rep := m.probe(tRef, small())
		wantStop(t, rep, "stopped", "run", "response_too_large")
		if rep.Requests[1].BodyBytes != 0 {
			t.Errorf("read %d bytes of an oversized response", rep.Requests[1].BodyBytes)
		}
	})
	t.Run("chunked API response over the limit stops one byte past it", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), func(w http.ResponseWriter, r *http.Request) {
			rateHeaders(w, 58)
			chunkedReply(`{"id": 1001, "pad": "`+strings.Repeat("x", 1500), strings.Repeat("x", 1500)+`"}`)(w, r)
		})
		rep := m.probe(tRef, small())
		wantStop(t, rep, "stopped", "run", "response_too_large")
		if rep.Requests[1].BodyBytes != 2049 {
			t.Errorf("read %d bytes; want 2049", rep.Requests[1].BodyBytes)
		}
	})
	t.Run("error body over the limit is not parsed", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), func(w http.ResponseWriter, r *http.Request) {
			rateHeaders(w, 58)
			w.Header().Set("Content-Length", "4096")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, strings.Repeat(" ", 4096))
		})
		rep := m.probe(tRef, small())
		wantStop(t, rep, "stopped", "run", "http_error")
		if rep.Stop.Detail != "HTTP 404" || rep.Requests[1].BodyBytes != 0 {
			t.Errorf("stop %+v body bytes %d", rep.Stop, rep.Requests[1].BodyBytes)
		}
	})
	// Every log starts with the text sentinel, which must never reach the report.
	logCases := []struct {
		name               string
		h2                 bool
		handler            http.HandlerFunc
		state, code        string
		read, counted      int64
		declared           int64 // -1 when absent
		lines              int64
		wantOutcome, stage string
	}{
		{"chunked log over the limit", false, chunkedReply(sentinel+"\n"+strings.Repeat("a\n", 291), strings.Repeat("b\n", 300)),
			"prefix", "log_limit", 1000, 1001, -1, 492, "incomplete", "log_download"},
		{"HTTP/2 log over the limit", true, chunkedReply(sentinel+"\n"+strings.Repeat("a\n", 291), strings.Repeat("b\n", 300)),
			"prefix", "log_limit", 1000, 1001, -1, 492, "incomplete", "log_download"},
		{"log over the limit by Content-Length", false, textReply(sentinel + strings.Repeat("c", 982) + "\n" + strings.Repeat("d", 4000)),
			"prefix", "log_limit", 1000, 1000, 5000, 1, "incomplete", "log_download"},
		{"chunked log of exactly the limit", false, chunkedReply(sentinel+strings.Repeat("e", 583), strings.Repeat("f", 399)+"\n"),
			"complete", "", 1000, 1000, -1, 1, "complete", ""},
		{"HTTP/2 log of exactly the limit", true, chunkedReply(sentinel+strings.Repeat("e", 583), strings.Repeat("f", 399)+"\n"),
			"complete", "", 1000, 1000, -1, 1, "complete", ""},
		{"log ended only by the connection closing", false, unframedReply(sentinel + "\n"),
			"end_unverified", "unframed_body", 18, 18, -1, 1, "incomplete", "log_download"},
	}
	for _, c := range logCases {
		t.Run(c.name, func(t *testing.T) {
			m := startMock(t, c.h2)
			oneFailedJob(m)
			m.logRedirect(2002, c.handler)
			rep := m.probe(tRef, small())
			if c.code == "" {
				if rep.Outcome != "complete" || rep.Stop != nil {
					t.Fatalf("outcome %s stop %+v", rep.Outcome, rep.Stop)
				}
			} else {
				wantStop(t, rep, c.wantOutcome, c.stage, c.code)
			}
			lg := rep.Log
			if lg.State != c.state || lg.BytesRead != c.read || rep.Requests[5].BodyBytes != c.counted || lg.Lines != c.lines {
				t.Errorf("log %+v, counted %d; want state %s read %d counted %d lines %d", lg, rep.Requests[5].BodyBytes, c.state, c.read, c.counted, c.lines)
			}
			if (c.declared < 0) != (lg.DeclaredBytes == nil) || (lg.DeclaredBytes != nil && *lg.DeclaredBytes != c.declared) {
				t.Errorf("declared bytes %v; want %d", lg.DeclaredBytes, c.declared)
			}
			noLeak(t, rep)
		})
	}
}

// unframedReply answers with neither Content-Length nor chunked encoding and
// then closes the connection, as a server whose transfer is cut would.
func unframedReply(text string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n" + text)
		buf.Flush()
	}
}

func TestProbeAggregateByteLimit(t *testing.T) {
	// Measure the API body bytes of the standard scenario, then allow only
	// 100 bytes more, so the log download meets the collection limit.
	measure := newMock(t)
	oneFailedJob(measure)
	measure.logRedirect(2002, textReply("ok\n"))
	full := measure.probe(tRef, DefaultLimits())
	apiBytes := full.Budget.BodyBytes - 3

	t.Run("the log meets the collection limit", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.logRedirect(2002, chunkedReply(strings.Repeat("z", 600)))
		lim := DefaultLimits()
		lim.MaxTotalBytes = apiBytes + 100
		rep := m.probe(tRef, lim)
		wantStop(t, rep, "incomplete", "log_download", "byte_limit")
		if rep.Log.State != "prefix" || rep.Log.BytesRead != 100 || rep.Budget.BodyBytes != lim.MaxTotalBytes+1 {
			t.Errorf("log %+v budget %+v", rep.Log, rep.Budget)
		}
	})
	t.Run("an API response meets the collection limit", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		lim := DefaultLimits()
		lim.MaxTotalBytes = full.Requests[0].BodyBytes + 10
		rep := m.probe(tRef, lim)
		wantStop(t, rep, "stopped", "run", "byte_limit")
		if rep.Requests[1].BodyBytes != 0 {
			t.Errorf("read %d bytes of the run response", rep.Requests[1].BodyBytes)
		}
	})
	t.Run("a spent byte allowance sends no further request", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		lim := DefaultLimits()
		lim.MaxTotalBytes = full.Requests[0].BodyBytes + full.Requests[1].BodyBytes // exactly the first two bodies
		rep := m.probe(tRef, lim)
		wantStop(t, rep, "stopped", "attempt", "byte_limit")
		if len(m.keys()) != 2 || rep.Budget.BodyBytes != lim.MaxTotalBytes {
			t.Errorf("requests %q budget %+v", m.keys(), rep.Budget)
		}
	})
}

func TestProbeRequestLimit(t *testing.T) {
	t.Run("before the jobs", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		lim := DefaultLimits()
		lim.MaxRequests = 3
		rep := m.probe(tRef, lim)
		wantStop(t, rep, "stopped", "jobs", "request_limit")
		if len(m.keys()) != 3 || rep.Budget.Requests != 3 {
			t.Errorf("requests %q budget %+v", m.keys(), rep.Budget)
		}
	})
	t.Run("before the redirected download", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.logRedirect(2002, textReply("ok\n"))
		lim := DefaultLimits()
		lim.MaxRequests = 5
		rep := m.probe(tRef, lim)
		wantStop(t, rep, "incomplete", "log_download", "request_limit")
		if rep.Log.State != "unavailable" || rep.Log.APIStatus != 302 || len(m.keys()) != 5 {
			t.Errorf("log %+v requests %q", rep.Log, m.keys())
		}
	})
}

// The timeout and deadline cases block the first request, so where they stop
// does not depend on how fast the mock's TLS handshakes are.
func TestProbeTimeoutsAndCancellation(t *testing.T) {
	t.Run("per-request timeout", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+"/rate_limit", func(w http.ResponseWriter, r *http.Request) { m.block(r) })
		lim := DefaultLimits()
		lim.RequestTimeout = 200 * time.Millisecond
		rep := m.probe(tRef, lim)
		wantStop(t, rep, "stopped", "allowance", "request_timeout")
		if rep.Requests[0].Error != "request_timeout" || len(m.keys()) != 1 {
			t.Errorf("request record %+v, requests %q", rep.Requests[0], m.keys())
		}
	})
	t.Run("collection deadline", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+"/rate_limit", func(w http.ResponseWriter, r *http.Request) { m.block(r) })
		lim := DefaultLimits()
		lim.Deadline = 200 * time.Millisecond
		wantStop(t, m.probe(tRef, lim), "stopped", "allowance", "deadline_exceeded")
	})
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("per-request timeout while reading the log (HTTP/2 %v)", h2), func(t *testing.T) {
			m := startMock(t, h2)
			oneFailedJob(m)
			m.logRedirect(2002, func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, sentinel+"\n")
				w.(http.Flusher).Flush()
				m.block(r)
			})
			lim := DefaultLimits()
			lim.RequestTimeout = time.Second // only the mock's handshakes must fit in it
			rep := m.probe(tRef, lim)
			wantStop(t, rep, "incomplete", "log_download", "request_timeout")
			if rep.Log.State != "interrupted" || rep.Log.BytesRead != 18 || rep.Log.Lines != 1 {
				t.Errorf("log %+v", rep.Log)
			}
			noLeak(t, rep)
		})
	}
	t.Run("cancelled before the first request", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		rep := probe(ctx, tRef, DefaultLimits(), m.transport(), nil)
		wantStop(t, rep, "stopped", "allowance", "cancelled")
		if len(m.keys()) != 0 {
			t.Errorf("requests %q", m.keys())
		}
	})
	t.Run("cancelled during the log download", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.logRedirect(2002, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, sentinel+"\n")
			w.(http.Flusher).Flush()
			m.block(r)
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		rt := &afterFirstRead{base: m.transport(), host: tLogHost, then: func() error { cancel(); return nil }}
		rep := probe(ctx, tRef, DefaultLimits(), rt, nil)
		wantStop(t, rep, "incomplete", "log_download", "cancelled")
		if rep.Log.State != "interrupted" || rep.Log.BytesRead < 1 || rep.Log.BytesRead > 18 {
			t.Errorf("log %+v", rep.Log)
		}
		noLeak(t, rep)
	})
	t.Run("a read error naming the local address", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.logRedirect(2002, func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, sentinel+"\n")
			w.(http.Flusher).Flush()
			m.block(r) // the next read is the injected reset, never more data or EOF
		})
		reset := &net.OpError{Op: "read", Net: "tcp",
			Source: &net.TCPAddr{IP: net.ParseIP("192.168.1.23"), Port: 52144},
			Addr:   &net.TCPAddr{IP: net.ParseIP("20.60.40.4"), Port: 443}, Err: syscall.ECONNRESET}
		rt := &afterFirstRead{base: m.transport(), host: tLogHost, then: func() error { return reset }}
		rep := probe(context.Background(), tRef, DefaultLimits(), rt, nil)
		wantStop(t, rep, "incomplete", "log_download", "network_error")
		if rep.Stop.Detail != "the connection was reset" || rep.Log.State != "interrupted" {
			t.Errorf("stop %+v log %+v", rep.Stop, rep.Log)
		}
		noLeak(t, rep, "192.168.1.23", "52144", "20.60.40.4")
	})
}

// afterFirstRead wraps the body of every response from host. After the first
// read that returns data it calls then; a non-nil error from then is what
// every later read returns. This makes the interruption point deterministic.
type afterFirstRead struct {
	base http.RoundTripper
	host string
	then func() error
}

func (a *afterFirstRead) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := a.base.RoundTrip(r)
	if err == nil && r.URL.Hostname() == a.host {
		resp.Body = &interruptedBody{ReadCloser: resp.Body, then: a.then}
	}
	return resp, err
}

type interruptedBody struct {
	io.ReadCloser
	then func() error
	done bool
	err  error
}

func (b *interruptedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	n, err := b.ReadCloser.Read(p)
	if n > 0 && !b.done {
		b.done = true
		b.err = b.then()
	}
	return n, err
}

// A 403 that spent the last unit of the allowance carries remaining 0 but is
// not a rate limit; its message decides.
func TestProbeLastUnitIsNotARateLimit(t *testing.T) {
	t.Run("job-log link", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+logURI(2002), jsonReply(0, 403, map[string]any{"message": "Must have admin rights to Repository."}))
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "incomplete", "log", "access_denied")
		if !strings.Contains(rep.Stop.Detail, "Must have admin rights to Repository.") ||
			!strings.Contains(rep.Stop.Detail, "0 requests remaining") || rep.Stop.RateLimitResetAt != "" {
			t.Errorf("stop %+v", rep.Stop)
		}
	})
	t.Run("API route", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), jsonReply(0, 404, map[string]any{"message": "Not Found"}))
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "run", "http_error")
		if !strings.HasPrefix(rep.Stop.Detail, "HTTP 404: Not Found") {
			t.Errorf("stop %+v", rep.Stop)
		}
	})
	t.Run("remaining 0 and no message is still a rate limit", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), func(w http.ResponseWriter, r *http.Request) {
			rateHeaders(w, 0)
			w.WriteHeader(http.StatusForbidden)
		})
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "run", "rate_limited")
		if rep.Stop.RateLimitResetAt != "2026-11-08T01:51:33Z" {
			t.Errorf("stop %+v", rep.Stop)
		}
	})
}

// Strings from GitHub reach the report and the terminal only after
// sanitizing: no control, format, line-separator, variation-selector or
// other default-ignorable character survives anywhere in the report.
func TestProbeSanitizesGitHubStrings(t *testing.T) {
	hostile := "x\x1b]0;title\x07\u202E\u2028\u200B\uFE0F\u0085\u034F\u3164\U000E0041y"
	run := runBody(1, "push", "completed", "failure")
	run["name"], run["head_branch"], run["path"] = hostile, hostile, hostile
	run["created_at"] = hostile
	job := jobBody(2002, 1, hostile, "failure")
	job["labels"] = []string{hostile}
	job["started_at"] = hostile
	job["steps"] = []any{map[string]any{"name": hostile, "number": 2, "status": "completed", "conclusion": "failure"}}
	other := jobBody(2003, 1, hostile, "failure")
	other["conclusion"] = hostile

	for _, c := range []struct {
		name string
		jobs []map[string]any
		ref  RunRef
		log  http.HandlerFunc
	}{
		{"selected job and log error message", []map[string]any{job}, tRef,
			jsonReply(50, 403, map[string]any{"message": hostile})},
		{"choice list and odd conclusions", []map[string]any{job, jobBody(2004, 1, hostile, "failure"), other}, tRef, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			m.standard(1, nil)
			m.handle(api+runURI(), jsonReply(58, 200, run))
			m.handle(api+attemptURI(1), jsonReply(57, 200, run))
			m.handle(api+jobsURI(1, 1), jsonReply(56, 200, jobsBody(c.jobs...)))
			if c.log != nil {
				m.handle(api+logURI(2002), c.log)
			}
			rep := m.probe(c.ref, DefaultLimits())
			if rep.Run == nil || rep.Jobs == nil {
				t.Fatalf("stop %+v", rep.Stop)
			}
			var doc any
			if err := json.Unmarshal([]byte(reportText(t, rep)), &doc); err != nil {
				t.Fatal(err)
			}
			strs := 0
			var walk func(v any)
			walk = func(v any) {
				switch v := v.(type) {
				case string:
					strs++
					for _, r := range v {
						if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' ||
							unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) {
							t.Errorf("report string %q holds U+%04X", v, r)
						}
					}
				case map[string]any:
					for k, x := range v {
						walk(k)
						walk(x)
					}
				case []any:
					for _, x := range v {
						walk(x)
					}
				}
			}
			walk(doc)
			if !strings.Contains(reportText(t, rep), `x\\u{001B}]0;title\\u{0007}\\u{202E}`) {
				t.Errorf("hostile string not escaped visibly: %s", reportText(t, rep))
			}
			if strs < 20 {
				t.Errorf("walked only %d strings", strs)
			}
		})
	}
}

func TestProbeStopsOnRateLimits(t *testing.T) {
	t.Run("primary limit on the run", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), jsonReply(0, 403, map[string]any{"message": "API rate limit exceeded for 203.0.113.9. (But here's the good news: ...)"}))
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "run", "rate_limited")
		if rep.Stop.HTTPStatus != 403 || rep.Stop.RateLimitResetAt != "2026-11-08T01:51:33Z" || len(m.keys()) != 2 {
			t.Errorf("stop %+v requests %q", rep.Stop, m.keys())
		}
		noLeak(t, rep, "203.0.113.9")
	})
	t.Run("secondary limit with retry-after", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+attemptURI(1), func(w http.ResponseWriter, r *http.Request) {
			rateHeaders(w, 40)
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
		})
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "attempt", "rate_limited")
		if rep.Stop.RetryAfterSeconds == nil || *rep.Stop.RetryAfterSeconds != 60 || rep.Requests[2].RetryAfter != "60" || len(m.keys()) != 3 {
			t.Errorf("stop %+v request %+v requests %q", rep.Stop, rep.Requests[2], m.keys())
		}
	})
	t.Run("secondary limit with an HTTP-date retry-after", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), func(w http.ResponseWriter, r *http.Request) {
			rateHeaders(w, 40)
			w.Header().Set("Retry-After", "Sat, 07 Nov 2026 01:00:00 GMT")
			w.WriteHeader(http.StatusForbidden)
		})
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "run", "rate_limited")
		if rep.Stop.RetryAfterSeconds != nil || rep.Requests[1].RetryAfter != "2026-11-07T01:00:00Z" {
			t.Errorf("stop %+v request %+v", rep.Stop, rep.Requests[1])
		}
	})
	t.Run("secondary limit named only in the message", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), jsonReply(40, 403, map[string]any{"message": "You have exceeded a secondary rate limit for 198.51.100.7."}))
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "run", "rate_limited")
		if rep.Stop.Detail != "rate limited: GitHub's message names a rate limit" {
			t.Errorf("detail %q", rep.Stop.Detail)
		}
		noLeak(t, rep, "198.51.100.7")
	})
	t.Run("allowance too low to start", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+"/rate_limit", jsonReply(3, 200, rateLimitBody(3)))
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "allowance", "rate_limit_low")
		if len(m.keys()) != 1 || rep.Allowance.Remaining != 3 || rep.Allowance.Needed != 6 {
			t.Errorf("requests %q allowance %+v", m.keys(), rep.Allowance)
		}
	})
	t.Run("allowance used up by a successful response", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+runURI(), jsonReply(0, 200, runBody(1, "push", "completed", "failure")))
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "stopped", "attempt", "rate_limited")
		if len(m.keys()) != 2 {
			t.Errorf("requests %q", m.keys())
		}
	})
	t.Run("rate limited at the log link", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		m.handle(api+logURI(2002), jsonReply(0, 403, map[string]any{"message": "API rate limit exceeded"}))
		rep := m.probe(tRef, DefaultLimits())
		wantStop(t, rep, "incomplete", "log", "rate_limited")
		if len(m.keys()) != 5 {
			t.Errorf("requests %q", m.keys())
		}
	})
}

func TestProbeRequiresCompletedFailedPush(t *testing.T) {
	cases := [][3]string{
		{"pull_request", "completed", "failure"},
		{"schedule", "completed", "failure"},
		{"push", "in_progress", ""},
		{"push", "completed", "success"},
		{"push", "completed", "cancelled"},
	}
	for _, c := range cases {
		t.Run(strings.Join(c[:], " "), func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			m.handle(api+attemptURI(1), jsonReply(57, 200, runBody(1, c[0], c[1], c[2])))
			rep := m.probe(tRef, DefaultLimits())
			wantStop(t, rep, "stopped", "attempt", "run_not_eligible")
			if rep.Run == nil || rep.Run.Event != c[0] || rep.Run.Status != c[1] || rep.Run.Conclusion != c[2] || len(m.keys()) != 3 {
				t.Errorf("run %+v requests %q", rep.Run, m.keys())
			}
		})
	}
}

func TestProbeRejectsUnexpectedAPIResponses(t *testing.T) {
	repoMoved := func(w http.ResponseWriter, r *http.Request) {
		rateHeaders(w, 58)
		w.Header().Set("Location", "https://api.github.com/repositories/42/actions/runs/1001")
		w.WriteHeader(http.StatusMovedPermanently)
	}
	otherRun := runBody(1, "push", "completed", "failure")
	otherRun["id"] = 1002
	otherRepo := runBody(1, "push", "completed", "failure")
	otherRepo["repository"] = map[string]any{"id": 43, "full_name": "someone/else"}
	badSHA := runBody(1, "push", "completed", "failure")
	badSHA["head_sha"] = "abc123"
	cases := []struct {
		name, route string
		handler     http.HandlerFunc
		stage, code string
	}{
		{"an API redirect", runURI(), repoMoved, "run", "unexpected_redirect"},
		{"malformed JSON", runURI(), func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "{not json") }, "run", "invalid_response"},
		{"another run", runURI(), jsonReply(58, 200, otherRun), "run", "identity_mismatch"},
		{"another repository", attemptURI(1), jsonReply(57, 200, otherRepo), "attempt", "identity_mismatch"},
		{"a malformed head SHA", runURI(), jsonReply(58, 200, badSHA), "run", "invalid_response"},
		{"no total_count", jobsURI(1, 1), jsonReply(56, 200, map[string]any{"jobs": []any{}}), "jobs", "invalid_response"},
		{"a server error", runURI(), jsonReply(58, 502, map[string]any{"message": "Server Error"}), "run", "http_error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			m.handle(api+c.route, c.handler)
			rep := m.probe(tRef, DefaultLimits())
			wantStop(t, rep, "stopped", c.stage, c.code)
			if k := m.keys(); k[len(k)-1] != api+c.route {
				t.Errorf("requests after the stop: %q", k)
			}
		})
	}
}

func TestProbeRejectsInvalidLimits(t *testing.T) {
	m := newMock(t)
	lim := DefaultLimits()
	lim.MaxLogBytes = 0
	wantStop(t, m.probe(tRef, lim), "stopped", "input", "invalid_limits")
	if len(m.keys()) != 0 {
		t.Errorf("requests %q", m.keys())
	}
}
