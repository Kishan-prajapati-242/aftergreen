package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Authenticated mode. The token is an invented sentinel; no test uses
// a real login or runs the real gh.

const tToken = "gho_" + "TOKENSENTINELQwErTyUiOpAsDfGhJkLzXcVbNm" // shares no 12-character piece with any fixture; split so the source holds no token-shaped literal

func tokenSource() *countingSource { return &countingSource{cred: newCredential(tToken)} }

func (m *mockGH) probeAuth(ref RunRef, lim Limits, src credentialSource) *Report {
	return probe(context.Background(), ref, lim, m.transport(), src)
}

// noToken checks, ignoring case, that no 12-character piece of the token is
// in the report. It never prints the report.
func noToken(t *testing.T, rep *Report) {
	t.Helper()
	text := strings.ToLower(reportText(t, rep))
	low := strings.ToLower(tToken)
	for i := 0; i+12 <= len(low); i++ {
		if strings.Contains(text, low[i:i+12]) {
			t.Fatalf("the report holds the token piece starting at %d", i)
		}
	}
}

// tokenOffAPI fails if any request to a host other than api.github.com held a
// piece of the token anywhere: in its URL or in any header.
func tokenOffAPI(t *testing.T, m *mockGH) {
	t.Helper()
	low := strings.ToLower(tToken)
	for _, h := range m.snapshot() {
		if strings.HasPrefix(h.key, api+"/") {
			continue
		}
		var all strings.Builder
		all.WriteString(h.key)
		for name, vs := range h.header {
			all.WriteString(name + ":" + strings.Join(vs, ","))
		}
		text := strings.ToLower(all.String())
		for i := 0; i+12 <= len(low); i++ {
			if strings.Contains(text, low[i:i+12]) {
				t.Fatalf("a request off the API host held the token piece starting at %d", i)
			}
		}
	}
}

// credentialPlacement checks the credential boundary on recorded requests: the
// credential appears on exactly one request, the job-log link on
// api.github.com, and on no metadata request and no download.
func credentialPlacement(hits []hit, token string) error {
	carried := 0
	for _, h := range hits {
		auth := h.header.Get("Authorization")
		path := strings.TrimPrefix(h.key, api)
		isLogLink := strings.HasPrefix(h.key, api+"/") && logRouteRE.MatchString(path)
		switch {
		case auth != "" && !isLogLink:
			return fmt.Errorf("%s carried a credential", h.key)
		case isLogLink && auth != "Bearer "+token:
			return fmt.Errorf("the job-log request did not carry the credential")
		case isLogLink:
			carried++
		}
	}
	if carried != 1 {
		return fmt.Errorf("%d requests carried the credential; want exactly 1", carried)
	}
	return nil
}

// Negative controls: the placement check catches a credential on a metadata
// request, on the download, or missing from the job-log request.
func TestCredentialPlacementCheck(t *testing.T) {
	bearer := http.Header{"Authorization": {"Bearer " + tToken}}
	none := http.Header{}
	good := []hit{{api + "/rate_limit", none}, {api + runURI(), none}, {api + logURI(2002), bearer}, {blobURI, none}}
	if err := credentialPlacement(good, tToken); err != nil {
		t.Fatalf("correct placement rejected: %v", err)
	}
	for name, hits := range map[string][]hit{
		"on a metadata request": {{api + "/rate_limit", bearer}, {api + logURI(2002), bearer}, {blobURI, none}},
		"on the run request":    {{api + runURI(), bearer}, {api + logURI(2002), bearer}},
		"on the download":       {{api + logURI(2002), bearer}, {blobURI, bearer}},
		"missing from the log":  {{api + "/rate_limit", none}, {api + logURI(2002), none}},
	} {
		if credentialPlacement(hits, tToken) == nil {
			t.Errorf("%s: not caught", name)
		}
	}
}

func TestCredentialOnlyOnTheJobLogRequest(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP/2 %v", h2), func(t *testing.T) {
			m := startMock(t, h2)
			oneFailedJob(m)
			m.logRedirect(2002, textReply(sentinel+"\n"))
			src := tokenSource()
			rep := m.probeAuth(tRef, DefaultLimits(), src)
			if rep.Outcome != "complete" || rep.Auth != "test" || src.calls != 1 {
				t.Fatalf("outcome %s auth %q source calls %d stop %+v", rep.Outcome, rep.Auth, src.calls, rep.Stop)
			}
			hits := m.snapshot()
			if len(hits) != 6 || hits[4].key != api+logURI(2002) || hits[5].key != blobURI {
				t.Fatalf("requests %q", m.keys())
			}
			if err := credentialPlacement(hits, tToken); err != nil {
				t.Error(err)
			}
			for i, rq := range rep.Requests {
				if rq.Authenticated != (i == 4) {
					t.Errorf("request %d (%s) recorded authenticated=%v", i+1, rq.Stage, rq.Authenticated)
				}
			}
			for name, v := range hits[5].header {
				if name != "User-Agent" && !(name == "Connection" && v[0] == "close") {
					t.Errorf("the download carried header %s", name)
				}
			}
			if rep.Allowance == nil || rep.Allowance.Needed != 5 {
				t.Errorf("allowance %+v; the unauthenticated requests are run, attempt and 3 job pages", rep.Allowance)
			}
			noToken(t, rep)
			tokenOffAPI(t, m)
			noLeak(t, rep)
		})
	}
}

// No gh run and no authenticated request happen unless one failed job of a
// public run with matching identities was selected.
func TestNoCredentialBeforeTheJobIsSelected(t *testing.T) {
	privateRun := runBody(1, "push", "completed", "failure")
	privateRun["repository"] = map[string]any{"id": 42, "full_name": tOwner + "/" + tRepo, "private": true}
	otherRun := runBody(1, "push", "completed", "failure")
	otherRun["id"] = 1002
	wrongAttempt := runBody(2, "push", "completed", "failure")
	cases := []struct {
		name, route string
		handler     http.HandlerFunc
		stage, code string
	}{
		{"private repository", runURI(), jsonReply(58, 200, privateRun), "run", "repository_not_public"},
		{"another run", runURI(), jsonReply(58, 200, otherRun), "run", "identity_mismatch"},
		{"another attempt", attemptURI(1), jsonReply(57, 200, wrongAttempt), "attempt", "attempt_mismatch"},
		{"not a failed push", attemptURI(1), jsonReply(57, 200, runBody(1, "pull_request", "completed", "failure")), "attempt", "run_not_eligible"},
		{"several failed jobs", jobsURI(1, 1), jsonReply(56, 200, jobsBody(jobBody(2001, 1, "a", "failure"), jobBody(2002, 1, "b", "failure"))), "select", "job_choice_required"},
		{"no failed job", jobsURI(1, 1), jsonReply(56, 200, jobsBody(jobBody(2001, 1, "a", "success"))), "select", "no_failed_job"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			m.handle(api+c.route, c.handler)
			src := tokenSource()
			rep := m.probeAuth(tRef, DefaultLimits(), src)
			wantStop(t, rep, "stopped", c.stage, c.code)
			if src.calls != 0 {
				t.Errorf("gh was asked for the credential")
			}
			for _, h := range m.snapshot() {
				if h.header.Get("Authorization") != "" {
					t.Errorf("%s carried a credential", h.key)
				}
			}
		})
	}
}

// The exported entry point wires the gh source to the job-log request.
func TestProbeWithGHUsesItsSource(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	m.logRedirect(2002, textReply("ok\n"))
	src := tokenSource()
	useEntryPoints(t, m.transport(), src)
	rep := ProbeWithGH(context.Background(), tRef, DefaultLimits())
	if rep.Outcome != "complete" || src.calls != 1 || credentialPlacement(m.snapshot(), tToken) != nil {
		t.Fatalf("outcome %s source calls %d stop %+v placement %v", rep.Outcome, src.calls, rep.Stop, credentialPlacement(m.snapshot(), tToken))
	}
	m2 := newMock(t)
	oneFailedJob(m2)
	m2.logRedirect(2002, textReply("ok\n"))
	useEntryPoints(t, m2.transport(), src)
	if rep := Probe(context.Background(), tRef, DefaultLimits()); rep.Auth != "none" || m2.snapshot()[0].header.Get("Authorization") != "" || src.calls != 1 {
		t.Fatalf("unauthenticated Probe: auth %q source calls %d", rep.Auth, src.calls)
	}
}

func TestAuthenticatedErrorPathsHideToken(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	cases := []struct {
		name               string
		setup              func(m *mockGH)
		rt                 func(m *mockGH) http.RoundTripper
		lim                func(l *Limits)
		outcome, stage, cd string
	}{
		{"log access denied", func(m *mockGH) {
			m.handle(api+logURI(2002), jsonReply(50, 403, map[string]any{"message": "Must have admin rights to Repository."}))
		}, nil, nil, "incomplete", "log", "access_denied"},
		{"message echoing the token", func(m *mockGH) {
			m.handle(api+runURI(), jsonReply(58, 404, map[string]any{"message": "token " + tToken + " is not valid here"}))
		}, nil, nil, "stopped", "run", "http_error"},
		{"redirect carrying the token", func(m *mockGH) {
			m.handle(api+logURI(2002), func(w http.ResponseWriter, r *http.Request) {
				rateHeaders(w, 50)
				w.Header().Set("Location", "https://evil.example/?t="+tToken)
				w.WriteHeader(http.StatusFound)
			})
		}, nil, nil, "incomplete", "log", "redirect_rejected"},
		{"redirect to an allowed host carrying the token", func(m *mockGH) {
			m.handle(api+logURI(2002), func(w http.ResponseWriter, r *http.Request) {
				rateHeaders(w, 50)
				w.Header().Set("Location", "https://"+tLogHost+tLogPath+"?"+tLogSig+"&t="+tToken)
				w.WriteHeader(http.StatusFound)
			})
		}, nil, nil, "incomplete", "log", "redirect_rejected"},
		{"redirect host made of the token", func(m *mockGH) {
			m.handle(api+logURI(2002), func(w http.ResponseWriter, r *http.Request) {
				rateHeaders(w, 50)
				w.Header().Set("Location", "https://"+strings.ToLower(tToken)+".evil.example/x")
				w.WriteHeader(http.StatusFound)
			})
		}, nil, nil, "incomplete", "log", "redirect_rejected"},
		{"credential rejected at the log link", func(m *mockGH) {
			m.handle(api+logURI(2002), jsonReply(50, 401, map[string]any{"message": "Bad credentials"}))
		}, nil, nil, "incomplete", "log", "credential_rejected"},
		{"rate limited", func(m *mockGH) {
			m.handle(api+runURI(), jsonReply(0, 403, map[string]any{"message": "API rate limit exceeded for user " + tToken}))
		}, nil, nil, "stopped", "run", "rate_limited"},
		{"connection reset during the download", func(m *mockGH) {
			m.logRedirect(2002, func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, sentinel+"\n")
				w.(http.Flusher).Flush()
				m.block(r)
			})
		}, func(m *mockGH) http.RoundTripper {
			return &afterFirstRead{base: m.transport(), host: tLogHost, then: func() error { return reset }}
		}, nil, "incomplete", "log_download", "network_error"},
		{"request limit before the download", func(m *mockGH) { m.logRedirect(2002, textReply("ok\n")) },
			nil, func(l *Limits) { l.MaxRequests = 5 }, "incomplete", "log_download", "request_limit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			c.setup(m)
			var rt http.RoundTripper = m.transport()
			if c.rt != nil {
				rt = c.rt(m)
			}
			lim := DefaultLimits()
			if c.lim != nil {
				c.lim(&lim)
			}
			rep := probe(context.Background(), tRef, lim, rt, tokenSource())
			wantStop(t, rep, c.outcome, c.stage, c.cd)
			noToken(t, rep)
			tokenOffAPI(t, m)
			m.mu.Lock()
			defer m.mu.Unlock()
			for _, d := range m.dialed {
				if d != "api.github.com:443" && d != tLogHost+":443" {
					t.Errorf("dialed %s", d)
				}
			}
		})
	}
}

func TestCredentialUnavailableStopsBeforeTheLog(t *testing.T) {
	cases := []struct {
		name   string
		src    *countingSource
		detail string
	}{
		{"fixed reason", &countingSource{err: &credentialError{"gh did not return a github.com credential (it may not be logged in)"}},
			"gh did not return a github.com credential (it may not be logged in)"},
		{"foreign error text", &countingSource{err: errors.New("SOURCE-ERROR-SENTINEL")}, "no usable credential was obtained"},
		{"no token", &countingSource{}, "the credential source returned something that is not a token"},
		{"short token", &countingSource{cred: newCredential("gho_short")}, "the credential source returned something that is not a token"},
		{"token with a space", &countingSource{cred: newCredential("gho_TOKEN SENTINEL0123456789abcdef")}, "the credential source returned something that is not a token"},
		{"token with a newline", &countingSource{cred: newCredential(tToken + "\nX-Injected: 1")}, "the credential source returned something that is not a token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			oneFailedJob(m)
			rep := m.probeAuth(tRef, DefaultLimits(), c.src)
			wantStop(t, rep, "incomplete", "credential", "credential_unavailable")
			want := []string{api + "/rate_limit", api + runURI(), api + attemptURI(1), api + jobsURI(1, 1)}
			if rep.Stop.Detail != c.detail || c.src.calls != 1 || !slices.Equal(m.keys(), want) {
				t.Errorf("stop %+v source calls %d requests %q", rep.Stop, c.src.calls, m.keys())
			}
			for _, h := range m.snapshot() {
				if h.header.Get("Authorization") != "" {
					t.Errorf("%s carried a credential", h.key)
				}
			}
			noLeak(t, rep, "SOURCE-ERROR-SENTINEL", "TOKEN", "X-Injected")
		})
	}
}

// A response that would put part of the token into the report makes the
// probe withhold the report.
func TestReportWithheldWhenTokenEchoed(t *testing.T) {
	for _, c := range []struct {
		name, jobName string
		withheld      bool
	}{
		{"whole token", "build " + tToken, true},
		{"16-character piece", "build " + tToken[6:22], true},
		{"12-character piece", "build " + tToken[20:32], true},
		{"lower-cased token", "build " + strings.ToLower(tToken), true},
		{"11-character piece", "build " + tToken[20:31], false},
		{"unrelated name", "build gho_unrelated", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newMock(t)
			m.standard(1, map[int64][]map[string]any{1: {jobBody(2002, 1, c.jobName, "failure")}})
			m.logRedirect(2002, textReply("ok\n"))
			rep := m.probeAuth(tRef, DefaultLimits(), tokenSource())
			if c.withheld {
				wantStop(t, rep, "stopped", "report", "credential_in_output")
				if rep.Job != nil || rep.Run != nil || len(rep.Requests) != 0 || rep.Budget.Requests != 6 || *rep.Input != tRef {
					t.Errorf("withheld report keeps %s", reportText(t, rep))
				}
				noToken(t, rep)
			} else if rep.Outcome != "complete" {
				t.Errorf("outcome %s stop %+v", rep.Outcome, rep.Stop)
			}
		})
	}
}

// The credential never prints, formats or marshals as its value, alone or
// inside other values, with any verb, including a struct that holds it in an
// unexported field (as the collector does) printed with a verb that makes fmt
// fall back to reflection.
func TestCredentialNeverShowsItsValue(t *testing.T) {
	c := newCredential(tToken)
	holder := struct {
		hidden credential
		Shown  credential
	}{c, c}
	col := newCollector(context.Background(), DefaultLimits(), nil)
	col.cred = c
	var out []string
	for _, v := range []any{c, &c, holder, &holder, []credential{c}, map[string]credential{"k": c}, *col, col, c.secret} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			out = append(out, fmt.Sprintf(verb, v))
		}
		out = append(out, fmt.Sprint(v), fmt.Sprintln(v))
		if b, err := json.Marshal(v); err == nil {
			out = append(out, string(b))
		}
	}
	for _, s := range out {
		if strings.Contains(s, "TOKENSENTINEL") || strings.Contains(s, "QwErTyUiOp") {
			t.Fatalf("formatted credential reveals the token: %s", s)
		}
	}
}

// The real gh lookup: with no gh on PATH, the source fails with a fixed
// reason and runs nothing.
func TestGHCLINotOnPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := ghCLI{}.credential(context.Background())
	var ce *credentialError
	if !errors.As(err, &ce) || ce.reason != "the GitHub CLI (gh) was not found on PATH" {
		t.Fatalf("err %v", err)
	}
}

// fakeGH runs this test binary (TestHelperFakeGH) in place of gh. The
// binary checks the arguments, environment and stdin it was given and
// behaves according to mode. Nothing here is a shell command.
func fakeGH(mode string, ran *string) ghCLI {
	return ghCLI{
		lookPath: func(string) (string, error) { return "/nonexistent/gh", nil },
		command: func(ctx context.Context, name string, args ...string) *exec.Cmd {
			*ran = name
			cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestHelperFakeGH$", "--"}, args...)...)
			cmd.Env = append(os.Environ(), "AFTERGREEN_FAKE_GH="+mode)
			return cmd
		},
		timeout: 3 * time.Second,
	}
}

const fakeGHToken = "gho_" + "FAKEGHSENTINEL0123456789abcdefghijk"

func TestGHCLI(t *testing.T) {
	for _, name := range tokenEnv { // must not reach gh, which would prefer them
		t.Setenv(name, "gho_"+"ENVTOKENSENTINEL0123456789abcdefghij")
	}
	cases := []struct {
		mode   string
		reason string // "" for success
	}{
		{"ok", ""},
		{"crlf", ""},
		{"fail", "gh did not return a github.com credential (it may not be logged in)"},
		{"garbage", "gh printed something that is not a token"},
		{"twolines", "gh printed something that is not a token"},
		{"long", "gh printed more than a token"},
		{"hang", "gh did not answer within its time limit"},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			var ran string
			g := fakeGH(c.mode, &ran)
			if c.mode == "hang" {
				g.timeout = 300 * time.Millisecond
			}
			var cred credential
			var err error
			stderr := captureStderr(t, func() { cred, err = g.credential(context.Background()) })
			if strings.Contains(stderr, "SENTINEL") {
				t.Errorf("gh's output reached this process's stderr")
			}
			if ran != "/nonexistent/gh" {
				t.Errorf("ran %q; want the looked-up path", ran)
			}
			if c.reason == "" {
				if err != nil || cred.token() != fakeGHToken {
					t.Fatalf("err %v, token ok %v", err, cred.token() == fakeGHToken)
				}
				return
			}
			var ce *credentialError
			if !errors.As(err, &ce) || ce.reason != c.reason || cred.usable() {
				t.Fatalf("err %v; want reason %q", err, c.reason)
			}
		})
	}
	if (ghCLI{}).name() != "gh" {
		t.Error("source name")
	}
}

// TestHelperFakeGH is not a test: it is the fake gh run by fakeGH. Run
// directly, without AFTERGREEN_FAKE_GH, it does nothing.
func TestHelperFakeGH(t *testing.T) {
	mode := os.Getenv("AFTERGREEN_FAKE_GH")
	if mode == "" {
		return
	}
	args := os.Args[slices.Index(os.Args, "--")+1:]
	if !slices.Equal(args, []string{"auth", "token", "--hostname", "github.com"}) {
		os.Exit(3)
	}
	if os.Getenv("GH_NO_UPDATE_NOTIFIER") != "1" || os.Getenv("GH_PROMPT_DISABLED") != "1" {
		os.Exit(4)
	}
	for _, name := range tokenEnv {
		if _, set := os.LookupEnv(name); set {
			os.Exit(6) // gh would print this variable instead of its stored login
		}
	}
	if n, _ := os.Stdin.Read(make([]byte, 1)); n != 0 {
		os.Exit(5)
	}
	switch mode {
	case "ok":
		fmt.Print(fakeGHToken + "\n")
	case "crlf":
		fmt.Print(fakeGHToken + "\r\n")
	case "fail":
		fmt.Fprintln(os.Stderr, "no oauth token found STDERR-SENTINEL")
		os.Exit(1)
	case "garbage":
		fmt.Println("not a token STDOUT-SENTINEL")
	case "twolines":
		fmt.Print(fakeGHToken + "\n" + fakeGHToken + "\n")
	case "long":
		fmt.Print(strings.Repeat("a", 5000))
	case "hang":
		time.Sleep(time.Hour)
	}
	os.Exit(0)
}

// Defense in depth: send refuses to mark as an API request, and so to attach
// the credential to, anything but https://api.github.com. Nothing is sent.
func TestSendRefusesCredentialOffAPI(t *testing.T) {
	targets := []*url.URL{{Scheme: "https", Host: "api.github.com", Opaque: "//evil.example/x"}}
	for _, u := range []string{"https://evil.example/x", "http://api.github.com/x", "https://user@api.github.com/x",
		"https://api.github.com:443/x", "https://" + tLogHost + "/x",
		"https://api.github.com/rate_limit", "https://api.github.com" + strings.Split(runURI(), "?")[0],
		"https://api.github.com" + logURI(2002) + "?x=1", "https://api.github.com" + logURI(2002) + "/../../runs"} {
		target, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, target)
	}
	for _, target := range targets {
		u := target.String()
		rt := &countingTransport{t: t, fail: true}
		col := newCollector(context.Background(), DefaultLimits(), rt)
		col.cred = newCredential(tToken)
		x, s := col.send("test", target, "GET /x", true, true)
		if x != nil || s == nil || s.Code != "internal_error" || rt.calls.Load() != 0 || len(col.reqs) != 0 {
			t.Errorf("%s: stop %+v, transport calls %d", u, s, rt.calls.Load())
		}
	}
	// Control: the job-log route itself is the one place the credential goes.
	rt := &countingTransport{t: t}
	col := newCollector(context.Background(), DefaultLimits(), rt)
	col.cred = newCredential(tToken)
	target, _ := url.Parse("https://api.github.com" + logURI(2002))
	if _, s := col.send("log", target, "GET", true, true); s == nil || s.Code != "network_error" || rt.calls.Load() != 1 || !col.reqs[0].Authenticated {
		t.Errorf("job-log route: stop %+v, calls %d", s, rt.calls.Load())
	}
}

// Header values from the server reach the report, through the real probe,
// only in their strict forms.
func TestProbeReportsHeadersOnlyInStrictForms(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	body, _ := json.Marshal(runBody(1, "push", "completed", "failure"))
	m.handle(api+runURI(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "57")
		w.Header().Set("X-RateLimit-Resource", "core 203.0.113.9")
		w.Header().Set("X-GitHub-Api-Version-Selected", "2026-03-10 HEADER-SENTINEL")
		w.Write(body)
	})
	m.handle(api+attemptURI(1), func(w http.ResponseWriter, r *http.Request) {
		rateHeaders(w, 40)
		w.Header().Set("Retry-After", "later, see https://203.0.113.9/HEADER-SENTINEL")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	rep := m.probe(tRef, DefaultLimits())
	wantStop(t, rep, "stopped", "attempt", "rate_limited")
	if rl := rep.Requests[1].RateLimit; rep.Requests[2].RetryAfter != "unrecognized" || rep.Requests[1].APIVersionSelected != "" ||
		rl == nil || rl.Resource != "other" || *rl.Remaining != 57 {
		t.Errorf("requests %s", reportText(t, rep))
	}
	noLeak(t, rep, "HEADER-SENTINEL", "203.0.113.9")

	m2 := newMock(t)
	oneFailedJob(m2)
	m2.logRedirect(2002, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8; sig=SIGNATURE-SENTINEL")
		io.WriteString(w, "ok\n")
	})
	rep = m2.probe(tRef, DefaultLimits())
	if rep.Outcome != "complete" || rep.Log.ContentType != "text/plain; charset=utf-8" {
		t.Errorf("outcome %s content type %q", rep.Outcome, rep.Log.ContentType)
	}
	noLeak(t, rep)
}

// captureStderr runs fn with os.Stderr redirected and returns what was
// written, so a test can show that gh's stderr is discarded, not inherited.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	return <-done
}

// Cancellation or the collection deadline while gh runs is reported as
// such, not as a missing login, and nothing is requested.
type funcSource struct {
	fn func(context.Context) (credential, error)
}

func (f funcSource) name() string { return "test" }

func (f funcSource) credential(ctx context.Context) (credential, error) { return f.fn(ctx) }

// Cancellation or the deadline is reported as such, before any request or
// while gh runs after the metadata was read; the log is never requested.
func TestCredentialSourceInterrupted(t *testing.T) {
	t.Run("cancelled before any request", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		src := tokenSource()
		rt := &countingTransport{t: t, fail: true}
		wantStop(t, probe(ctx, tRef, DefaultLimits(), rt, src), "stopped", "allowance", "cancelled")
		if src.calls != 0 {
			t.Error("gh was asked")
		}
	})
	t.Run("cancelled while gh runs", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		src := funcSource{fn: func(context.Context) (credential, error) {
			cancel()
			return credential{}, errors.New("interrupted")
		}}
		rep := probe(ctx, tRef, DefaultLimits(), m.transport(), src)
		wantStop(t, rep, "incomplete", "credential", "cancelled")
		if len(m.keys()) != 4 {
			t.Errorf("requests %q", m.keys())
		}
	})
	t.Run("deadline while gh runs", func(t *testing.T) {
		m := newMock(t)
		oneFailedJob(m)
		var ran string
		hang := fakeGH("hang", &ran)
		hang.timeout = 10 * time.Second // the collection deadline comes first
		lim := DefaultLimits()
		lim.Deadline = time.Second
		rep := probe(context.Background(), tRef, lim, m.transport(), hang)
		wantStop(t, rep, "incomplete", "credential", "deadline_exceeded")
		if len(m.keys()) != 4 || ran == "" {
			t.Errorf("requests %q, gh ran %q", m.keys(), ran)
		}
	})
}

// Invalid limits stop the probe before the credential source runs.
func TestInvalidLimitsSkipTheCredential(t *testing.T) {
	src := tokenSource()
	lim := DefaultLimits()
	lim.MaxRequests = 0
	rep := probe(context.Background(), tRef, lim, &countingTransport{t: t, fail: true}, src)
	wantStop(t, rep, "stopped", "input", "invalid_limits")
	if src.calls != 0 {
		t.Errorf("the credential source ran %d times", src.calls)
	}
}

// GODEBUG http2debug makes Go log request headers and URLs, so neither mode
// runs: nothing is requested and gh is not asked.
func TestHTTP2DebugLoggingRefused(t *testing.T) {
	for _, v := range []string{"http2debug=1", "http2debug=2", "netdns=go,http2debug=1"} {
		t.Setenv("GODEBUG", v)
		for _, src := range []credentialSource{nil, tokenSource()} {
			rt := &countingTransport{t: t, fail: true}
			rep := probe(context.Background(), tRef, DefaultLimits(), rt, src)
			wantStop(t, rep, "stopped", "input", "unsafe_environment")
			if cs, ok := src.(*countingSource); ok && cs.calls != 0 {
				t.Errorf("GODEBUG %s: the credential source ran", v)
			}
		}
	}
	t.Setenv("GODEBUG", "http2client=0")
	if http2DebugLogging() {
		t.Error("an unrelated GODEBUG setting refused the probe")
	}
}

// The probe reads public repositories only: a run or attempt that says it
// is private, or does not say, stops it before the jobs are listed.
func TestPrivateRepositoryRefused(t *testing.T) {
	repo := func(private any) map[string]any {
		r := map[string]any{"id": 42, "full_name": tOwner + "/" + tRepo}
		if private != nil {
			r["private"] = private
		}
		return r
	}
	cases := []struct {
		name, route, stage string
		private            any
		requests           int
	}{
		{"private run", runURI(), "run", true, 2},
		{"run without the field", runURI(), "run", nil, 2},
		{"private attempt", attemptURI(1), "attempt", true, 3},
	}
	for _, c := range cases {
		for _, src := range []credentialSource{nil, tokenSource()} {
			t.Run(fmt.Sprintf("%s (auth %v)", c.name, src != nil), func(t *testing.T) {
				m := newMock(t)
				oneFailedJob(m)
				body := runBody(1, "push", "completed", "failure")
				body["repository"] = repo(c.private)
				m.handle(api+c.route, jsonReply(57, 200, body))
				rep := probe(context.Background(), tRef, DefaultLimits(), m.transport(), src)
				wantStop(t, rep, "stopped", c.stage, "repository_not_public")
				if len(m.keys()) != c.requests || rep.Jobs != nil || rep.Repository != nil {
					t.Errorf("requests %q jobs %+v repository %+v", m.keys(), rep.Jobs, rep.Repository)
				}
				if cs, ok := src.(*countingSource); ok && cs.calls != 0 {
					t.Error("gh was asked for the credential")
				}
			})
		}
	}
}

// The fail-closed check ignores case, and a withheld report drops even its
// validated input when that holds a piece of the token.
func TestTokenPieces(t *testing.T) {
	for _, c := range []struct {
		text string
		want bool
	}{
		{tToken, true}, {strings.ToLower(tToken), true}, {strings.ToUpper(tToken[10:22]), true},
		{tToken[4:16], true},  // the first 12 characters after the prefix
		{tToken[0:12], false}, // the prefix and only 8 characters of the token's own
		{tToken[3:15], false}, {"unrelated gho_text", false}, {"", false},
	} {
		if got := containsPiece([]byte(c.text), tToken); got != c.want {
			t.Errorf("containsPiece(%d bytes) = %v; want %v", len(c.text), got, c.want)
		}
	}
	// A fine-grained token's prefix alone is not a piece of it.
	pat := "github_pat_" + "TQWERTYUIOPASDFGHJKLZXCVBNM0123456789"
	if containsPiece([]byte("step: Set GITHUB_PAT_TOKEN"), pat) || !containsPiece([]byte("x "+pat[11:23]), pat) {
		t.Error("fine-grained token prefix handling")
	}
	rep := &Report{Report: ReportName, Input: &RunRef{Owner: "octo", Repo: "x" + tToken[4:20], RunID: 1}}
	if w := withheld(rep, tToken); w.Input != nil || revealsToken(w, tToken) {
		t.Errorf("withheld report keeps the input")
	}
	rep.Input = &tRef
	if w := withheld(rep, tToken); w.Input == nil || *w.Input != tRef {
		t.Errorf("withheld report dropped an unrelated input")
	}
}

// GitHub enumeration values that do not look like one are reported as
// "unrecognized", in the run record and in stop details.
func TestEnumerationsAreChecked(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	m.handle(api+attemptURI(1), jsonReply(57, 200, runBody(1, "push 203.0.113.9", "completed\x1b[2J", "failure")))
	rep := m.probe(tRef, DefaultLimits())
	wantStop(t, rep, "stopped", "attempt", "run_not_eligible")
	if rep.Run.Event != "unrecognized" || rep.Run.Status != "unrecognized" || rep.Run.Conclusion != "failure" {
		t.Errorf("run %+v", rep.Run)
	}
	noLeak(t, rep, "203.0.113.9", "[2J")
}
