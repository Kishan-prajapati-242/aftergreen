package github

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

// The exported entry points validate their input themselves, and
// API error details are fixed text.

// countingTransport answers every request with an error and counts them. With
// fail set, any request at all fails the test.
type countingTransport struct {
	t     *testing.T
	fail  bool
	calls atomic.Int32
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	if c.fail {
		c.t.Errorf("a request was sent for invalid input")
	}
	return nil, errors.New("refused by the test transport")
}

// countingSource is a credential source that counts its calls.
type countingSource struct {
	cred  credential
	err   error
	calls int
}

func (s *countingSource) name() string { return "test" }

func (s *countingSource) credential(context.Context) (credential, error) {
	s.calls++
	return s.cred, s.err
}

// useEntryPoints makes Probe and ProbeWithGH use rt and src for this test.
func useEntryPoints(t *testing.T, rt http.RoundTripper, src credentialSource) {
	oldT, oldS := newTransport, newGHSource
	newTransport = func() http.RoundTripper { return rt }
	newGHSource = func() credentialSource { return src }
	t.Cleanup(func() { newTransport, newGHSource = oldT, oldS })
}

func TestRunRefValidate(t *testing.T) {
	for _, r := range []RunRef{
		{Owner: "octo-org", Repo: "demo", RunID: 1},
		{Owner: "A", Repo: "...", RunID: maxID, Attempt: maxID, JobID: maxID},
		{Owner: "a-", Repo: "x.git", RunID: 7, Attempt: 2},
	} {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	for _, r := range invalidRefs() {
		if err := r.Validate(); err == nil {
			t.Errorf("%q accepted", fmt.Sprintf("%+v", r))
		}
	}
}

// invalidRefs puts EVIL into every invalid owner and repository, so a test can
// tell whether the value was echoed.
func invalidRefs() []RunRef {
	ok := RunRef{Owner: "octo-org", Repo: "demo", RunID: 1001}
	var out []RunRef
	for _, o := range []string{
		"", "EVIL/org", "../EVIL", "..", ".", "-EVIL", "EVIL_org", "EVIL" + strings.Repeat("a", 36), "EVIL org",
		"EVIL\x00", "EVIL\n", "EVIL\r\nX-Injected: 1", "EVIL\u202E", "EVIL%2forg", "EVIL?x", "EVIL#x", `EVIL\org`,
		"EVIL\uFF4F", "EVIL;rm", "EVIL:443", "EVIL@host",
	} {
		r := ok
		r.Owner = o
		out = append(out, r)
	}
	for _, p := range []string{
		"", ".", "..", "EVIL/demo", `EVIL\demo`, "../../EVIL", "EVIL?y", "EVIL#y", "EVIL%2e", "EVIL y", "EVIL\ty",
		"EVIL\n", "EVIL" + strings.Repeat("r", 97), "EVIL\u00E9", "EVIL\u2028", "EVIL\x7f",
	} {
		r := ok
		r.Repo = p
		out = append(out, r)
	}
	for _, id := range []int64{0, -1, maxID + 1, math.MaxInt64, math.MinInt64} {
		r := ok
		r.RunID = id
		out = append(out, r)
	}
	for _, id := range []int64{-1, maxID + 1, math.MaxInt64} {
		r := ok
		r.Attempt = id
		out = append(out, r)
		r = ok
		r.JobID = id
		out = append(out, r)
	}
	return out
}

// Invalid input through the exported entry points makes no request, never
// runs the credential source, and is not echoed into the report.
func TestEntryPointsRejectInvalidInput(t *testing.T) {
	for _, r := range invalidRefs() {
		for _, authenticated := range []bool{false, true} {
			rt := &countingTransport{t: t, fail: true}
			src := &countingSource{cred: newCredential(tToken)}
			useEntryPoints(t, rt, src)
			var rep *Report
			if authenticated {
				rep = ProbeWithGH(context.Background(), r, DefaultLimits())
			} else {
				rep = Probe(context.Background(), r, DefaultLimits())
			}
			text := reportText(t, rep)
			if rep.Outcome != "stopped" || rep.Stop == nil || rep.Stop.Stage != "input" || rep.Stop.Code != "invalid_input" ||
				rep.Input != nil || len(rep.Requests) != 0 || rep.Budget.Requests != 0 || rt.calls.Load() != 0 || src.calls != 0 {
				t.Errorf("%q (auth %v): %s; transport calls %d, source calls %d", fmt.Sprintf("%+v", r), authenticated, text, rt.calls.Load(), src.calls)
			}
			if strings.Contains(text, "EVIL") || strings.Contains(text, `"input":`) {
				t.Errorf("%q: the report echoes the input: %s", fmt.Sprintf("%+v", r), text)
			}
		}
	}
}

// Control: valid input through the same entry points does reach the
// transport, so the refusal above is not vacuous.
func TestEntryPointsUseTheirTransport(t *testing.T) {
	rt := &countingTransport{t: t}
	useEntryPoints(t, rt, &countingSource{cred: newCredential(tToken)})
	for _, rep := range []*Report{Probe(context.Background(), tRef, DefaultLimits()), ProbeWithGH(context.Background(), tRef, DefaultLimits())} {
		if rep.Stop == nil || rep.Stop.Stage != "allowance" || rep.Stop.Code != "network_error" || rep.Input == nil || *rep.Input != tRef {
			t.Errorf("stop %+v input %+v", rep.Stop, rep.Input)
		}
	}
	if rt.calls.Load() != 2 {
		t.Errorf("%d transport calls; want 2", rt.calls.Load())
	}
}

// Server messages are examined in memory and never reported. Only the
// status, the stop code and fixed text reach the report.
func TestErrorDetailsNeverEchoServerText(t *testing.T) {
	messages := []string{
		"Forbidden for IP=203.0.113.9",
		"see https://198.51.100.7:8443/x?sig=SIGNATURE-SENTINEL&se=1 for help",
		"link sig=SIGNATURE-SENTINEL-77 expired",
		"\x1b[31mCTRL-SENTINEL\x1b[0m \u202E reversed \u2028 split",
		strings.Repeat("LONG-MESSAGE-SENTINEL ", 5000),
		"Must have admin rights to Repository. Address 203.0.113.9",
		"API rate limit exceeded for IP=203.0.113.9",
		"[2001:db8::1]:443 refused",
		"Requires authentication ",
	}
	sentinels := []string{"203.0.113", "198.51.100", "2001:db8", "IP=", "SIGNATURE-SENTINEL", "sig=", "CTRL-SENTINEL",
		"LONG-MESSAGE", "reversed", "https://", "Address"}
	fixed := regexp.MustCompile(`^HTTP [0-9]{3}( \(GitHub's message is withheld: only known messages are reported\))?$|^rate limited: GitHub's message names a rate limit$`)
	apiCode := map[int]string{401: "authentication_required", 403: "http_error", 404: "http_error", 410: "http_error", 422: "http_error", 500: "http_error"}
	logCode := map[int]string{401: "authentication_required", 403: "access_denied", 404: "not_found", 410: "gone", 422: "http_error", 500: "http_error"}
	for _, msg := range messages {
		for _, status := range []int{401, 403, 404, 410, 422, 500} {
			for _, atLog := range []bool{false, true} {
				name := fmt.Sprintf("%d at log %v: %.30q", status, atLog, msg)
				t.Run(name, func(t *testing.T) {
					m := newMock(t)
					oneFailedJob(m)
					route, stage, outcome, want := runURI(), "run", "stopped", apiCode[status]
					if atLog {
						route, stage, outcome, want = logURI(2002), "log", "incomplete", logCode[status]
					}
					if status == 403 && strings.Contains(strings.ToLower(msg), "rate limit") {
						want = "rate_limited"
					}
					m.handle(api+route, jsonReply(40, status, map[string]any{"message": msg}))
					rep := m.probe(tRef, DefaultLimits())
					wantStop(t, rep, outcome, stage, want)
					if rep.Stop.HTTPStatus != status || !fixed.MatchString(rep.Stop.Detail) {
						t.Errorf("stop %+v", rep.Stop)
					}
					noLeak(t, rep, sentinels...)
				})
			}
		}
	}
}

// Header values reach the report only in strict forms.
func TestHeaderValuesAreChecked(t *testing.T) {
	cases := []struct {
		fn   func(string) string
		in   string
		want string
	}{
		{retryAfterText, "60", "60"},
		{retryAfterText, "Sat, 07 Nov 2026 01:00:00 GMT", "2026-11-07T01:00:00Z"},
		{retryAfterText, "soon, see https://203.0.113.9/", "unrecognized"},
		{retryAfterText, "", ""},
		{contentTypeText, "text/plain; charset=utf-8", "text/plain; charset=utf-8"},
		{contentTypeText, "Text/Plain", "text/plain"},
		{contentTypeText, "Text/Plain; Charset=UTF-8", "text/plain; charset=utf-8"},
		{contentTypeText, "text/plain; charset=\"x\u202E\"", "text/plain; charset=other"},
		{contentTypeText, "text/plain; charset=utf-16le", "text/plain; charset=other"},
		{contentTypeText, "text/plain; charset=utf-8; sig=SECRET", "text/plain; charset=utf-8"},
		{contentTypeText, "text/203.0.113.9", "other"},
		{contentTypeText, "\x1b[31m", "unrecognized"},
		{func(v string) string { return listed(knownResources, v) }, "core", "core"},
		{func(v string) string { return listed(knownResources, v) }, "core 203.0.113.9", "other"},
		{func(v string) string { return listed(knownResources, v) }, "", ""},
		{enumText, "pull_request", "pull_request"},
		{enumText, "", ""},
		{enumText, "failure 203.0.113.9", "unrecognized"},
		{enumText, "Failure", "unrecognized"},
		{func(v string) string { return matching(apiVersionRE, v) }, "2026-03-10", "2026-03-10"},
		{func(v string) string { return matching(apiVersionRE, v) }, "2026-03-10 \x1b", ""},
		{func(v string) string { return matching(protoRE, v) }, "HTTP/2.0", "HTTP/2.0"},
		{func(v string) string { return matching(protoRE, v) }, "HTTP/1.1", "HTTP/1.1"},
		{func(v string) string { return matching(protoRE, v) }, "SPDY/3", ""},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%q -> %q; want %q", c.in, got, c.want)
		}
	}
}
