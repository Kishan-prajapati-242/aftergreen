package github

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// APIVersion is sent as X-GitHub-Api-Version on every API request. It is the
// version the current REST documentation describes for the endpoints used
// here (checked 2026-11-07, America/New_York). Requests without the header
// would get 2022-11-28.
const APIVersion = "2026-03-10"

const (
	apiHost   = "api.github.com"
	userAgent = "aftergreen-probe/0 (read-only)"
)

var (
	errDeadline       = errors.New("collection deadline reached")
	errRequestTimeout = errors.New("per-request timeout reached")
)

// collector performs the budgeted requests of one collection. It calls the
// transport directly rather than through http.Client, so no redirect is ever
// parsed or followed outside fetchLog's policy check. (http.Client parses a
// Location header before any redirect hook runs, and puts an unparsable one,
// signed query included, into its error.)
type collector struct {
	rt    http.RoundTripper
	lim   Limits
	ctx   context.Context // carries the collection deadline and caller cancellation
	reqs  []*Request
	bytes int64 // response body bytes read, all requests
	// An API response reported 0 requests remaining, for requests made without
	// and with the credential; the two count against different allowances.
	exhaustedAnon, exhaustedAuth *RateLimit
	src                          credentialSource // nil unless the probe is authenticated
	cred                         credential       // obtained only after the job is selected
	keepLog                      bool             // Collect: keep the log bytes in memory
	logBuf                       []byte
}

func newCollector(ctx context.Context, lim Limits, rt http.RoundTripper) *collector {
	return &collector{rt: rt, lim: lim, ctx: ctx}
}

// exchange is one sent request whose response body is still open.
type exchange struct {
	stage  string
	target *url.URL
	resp   *http.Response
	ctx    context.Context // the per-request context
	cancel context.CancelFunc
	rec    *Request
}

func (x *exchange) close() {
	x.resp.Body.Close()
	x.cancel()
}

// logRouteRE is the only path the credential is ever sent to: one job's log
// link on api.github.com.
var logRouteRE = regexp.MustCompile(`^/repos/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}/actions/jobs/[1-9][0-9]{0,15}/logs$`)

// send makes one GET within the request, byte and rate-limit budgets. API
// requests must go to https://api.github.com and carry the fixed API headers.
// The credential is attached only when withCred is set, and only to the
// job-log route; every other request, the log download included, carries no
// credential and no cookie.
func (c *collector) send(stage string, target *url.URL, route string, api, withCred bool) (*exchange, *Stop) {
	if code := ctxCode(c.ctx); code != "" {
		return nil, &Stop{Stage: stage, Code: code, Detail: ctxDetail(code)}
	}
	if len(c.reqs) >= c.lim.MaxRequests {
		return nil, &Stop{Stage: stage, Code: "request_limit",
			Detail: fmt.Sprintf("the limit of %d requests per collection was reached", c.lim.MaxRequests)}
	}
	if c.bytes >= c.lim.MaxTotalBytes {
		return nil, &Stop{Stage: stage, Code: "byte_limit",
			Detail: fmt.Sprintf("the limit of %d response bytes per collection was reached", c.lim.MaxTotalBytes)}
	}
	exhausted := c.exhaustedAnon
	if withCred {
		exhausted = c.exhaustedAuth
	}
	if api && exhausted != nil {
		return nil, &Stop{Stage: stage, Code: "rate_limited", RateLimitResetAt: exhausted.ResetAt,
			Detail: "an earlier response reported 0 requests remaining; no further API request was sent"}
	}
	reqCtx, cancel := context.WithTimeoutCause(c.ctx, c.lim.RequestTimeout, errRequestTimeout)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.String(), nil)
	if err != nil {
		cancel()
		return nil, &Stop{Stage: stage, Code: "internal_error", Detail: "the request could not be built"}
	}
	rec := &Request{N: len(c.reqs) + 1, Stage: stage, Route: route, Host: target.Hostname()}
	req.Header.Set("User-Agent", userAgent)
	if api {
		if u := req.URL; u.Scheme != "https" || u.Host != apiHost || u.User != nil || u.Opaque != "" {
			cancel()
			return nil, &Stop{Stage: stage, Code: "internal_error", Detail: "an API request must go to https://api.github.com"}
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", APIVersion)
	}
	if withCred {
		if !api || !logRouteRE.MatchString(req.URL.Path) || req.URL.RawQuery != "" || !c.cred.usable() {
			cancel()
			return nil, &Stop{Stage: stage, Code: "internal_error", Detail: "the credential is sent only on the job-log request"}
		}
		req.Header.Set("Authorization", "Bearer "+c.cred.token())
		rec.Authenticated = true
	}
	c.reqs = append(c.reqs, rec)
	resp, err := c.rt.RoundTrip(req)
	if err != nil {
		s := c.failure(stage, reqCtx, err)
		cancel()
		rec.Error = s.Code
		return nil, s
	}
	rec.Status = resp.StatusCode
	rec.Proto = matching(protoRE, resp.Proto)
	if api {
		rec.RateLimit = parseRateLimit(resp.Header)
		rec.RetryAfter = retryAfterText(resp.Header.Get("Retry-After"))
		rec.APIVersionSelected = matching(apiVersionRE, resp.Header.Get("X-GitHub-Api-Version-Selected"))
		if rl := rec.RateLimit; rl != nil && rl.Remaining != nil && *rl.Remaining == 0 {
			if rec.Authenticated {
				c.exhaustedAuth = rl
			} else {
				c.exhaustedAnon = rl
			}
		}
	}
	return &exchange{stage: stage, target: target, resp: resp, ctx: reqCtx, cancel: cancel, rec: rec}, nil
}

// failure classifies a transport or body-read error into a fixed category.
// Cancellation and timeouts are read from the request's context. The error's
// own text is never reported: Go's transport errors can contain the local
// address and port, a URL, or bytes the server sent.
func (c *collector) failure(stage string, reqCtx context.Context, err error) *Stop {
	if code := ctxCode(reqCtx); code != "" {
		return &Stop{Stage: stage, Code: code, Detail: ctxDetail(code)}
	}
	var (
		dnsErr  *net.DNSError
		netErr  net.Error
		verify  *tls.CertificateVerificationError
		record  tls.RecordHeaderError
		alert   tls.AlertError
		unknown x509.UnknownAuthorityError
		host    x509.HostnameError
		invalid x509.CertificateInvalidError
	)
	s := &Stop{Stage: stage, Code: "network_error"}
	switch {
	case errors.Is(err, errNonPublicAddress):
		s.Code, s.Detail = "non_public_address", "the destination did not resolve to a public address; the connection was refused"
	case errors.Is(err, errPortNotAllowed):
		s.Code, s.Detail = "port_not_allowed", "the destination port is not 443; the connection was refused"
	case errors.As(err, &dnsErr):
		s.Detail = "the host name could not be resolved"
	case errors.As(err, &netErr) && netErr.Timeout():
		s.Code, s.Detail = "network_timeout", "connecting, the TLS handshake or a read timed out"
	case errors.Is(err, syscall.ECONNREFUSED):
		s.Detail = "the connection was refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		s.Detail = "the connection was reset"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		s.Detail = "the connection closed before the response was complete"
	case errors.As(err, &verify), errors.As(err, &record), errors.As(err, &alert),
		errors.As(err, &unknown), errors.As(err, &host), errors.As(err, &invalid):
		s.Detail = "the TLS handshake or certificate verification failed"
	default:
		s.Detail = "the connection failed (the transport's error text is withheld because it can contain addresses or URLs)"
	}
	return s
}

func ctxCode(ctx context.Context) string {
	if ctx.Err() == nil {
		return ""
	}
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, errRequestTimeout):
		return "request_timeout"
	case errors.Is(cause, errDeadline), errors.Is(cause, context.DeadlineExceeded):
		return "deadline_exceeded"
	}
	return "cancelled"
}

func ctxDetail(code string) string {
	switch code {
	case "request_timeout":
		return "the per-request timeout expired"
	case "deadline_exceeded":
		return "the collection deadline expired"
	}
	return "the collection was cancelled"
}

// limitFor returns the byte limit for one body: perResponse, or the
// collection's remaining allowance when that is smaller (aggregate = true).
func (c *collector) limitFor(perResponse int64) (limit int64, aggregate bool) {
	if remaining := c.lim.MaxTotalBytes - c.bytes; remaining < perResponse {
		return remaining, true
	}
	return perResponse, false
}

// readBody passes at most limit bytes of the body to sink. To tell a body of
// exactly limit bytes from a longer one it reads one byte more, unless
// Content-Length already shows the body is longer. Every byte read is
// counted against the collection, so the collection total can exceed its
// limit by that one byte, after which the collection stops.
func (c *collector) readBody(x *exchange, limit int64, sink func([]byte)) (got int64, over bool, err error) {
	want := limit + 1
	if x.resp.ContentLength > limit {
		over, want = true, limit
	}
	buf := make([]byte, 32<<10)
	var read int64
	for read < want {
		b := buf
		if rest := want - read; rest < int64(len(b)) {
			b = b[:rest]
		}
		n, rerr := x.resp.Body.Read(b)
		if n > 0 {
			read += int64(n)
			c.bytes += int64(n)
			x.rec.BodyBytes += int64(n)
			keep := int64(n)
			if got+keep > limit {
				keep, over = limit-got, true
			}
			if keep > 0 {
				sink(b[:keep])
				got += keep
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return got, over, rerr
		}
	}
	return got, over, nil
}

func identityEncoding(h http.Header) bool {
	e := h.Get("Content-Encoding")
	return e == "" || strings.EqualFold(e, "identity")
}

// getJSON fetches one fixed API route and decodes a 200 response into out.
// A body over the JSON limit is never parsed, not even in part.
func (c *collector) getJSON(stage, path string, q url.Values, out any) *Stop {
	u := &url.URL{Scheme: "https", Host: apiHost, Path: path, RawQuery: q.Encode()}
	x, s := c.send(stage, u, "GET "+u.RequestURI(), true, false)
	if s != nil {
		return s
	}
	defer x.close()
	switch code := x.resp.StatusCode; {
	case code == http.StatusOK:
		return c.readJSON(x, out)
	case code >= 300 && code < 400:
		return &Stop{Stage: stage, Code: "unexpected_redirect", HTTPStatus: code,
			Detail: "API redirects are not followed; a moved or renamed repository answers this way"}
	}
	return c.errorStop(x, func(status int) string {
		if status == http.StatusUnauthorized {
			return unauthorizedCode(x.rec.Authenticated)
		}
		return "http_error"
	})
}

// unauthorizedCode names a 401: the credential was refused, or the request
// needs one.
func unauthorizedCode(authenticated bool) string {
	if authenticated {
		return "credential_rejected"
	}
	return "authentication_required"
}

func (c *collector) readJSON(x *exchange, out any) *Stop {
	if !identityEncoding(x.resp.Header) {
		return &Stop{Stage: x.stage, Code: "invalid_response", Detail: "the response has a content encoding that was not requested"}
	}
	limit, aggregate := c.limitFor(c.lim.MaxJSONBytes)
	if x.resp.ContentLength > limit {
		return tooLarge(x.stage, aggregate, limit)
	}
	var body bytes.Buffer
	_, over, err := c.readBody(x, limit, func(b []byte) { body.Write(b) })
	if err != nil {
		return c.failure(x.stage, x.ctx, err)
	}
	if over {
		return tooLarge(x.stage, aggregate, limit)
	}
	if err := json.Unmarshal(body.Bytes(), out); err != nil {
		return &Stop{Stage: x.stage, Code: "invalid_response", Detail: "the response is not the expected JSON"}
	}
	return nil
}

func tooLarge(stage string, aggregate bool, limit int64) *Stop {
	if aggregate {
		return &Stop{Stage: stage, Code: "byte_limit",
			Detail: fmt.Sprintf("the response is larger than the %d bytes left in the collection's byte limit; it was not parsed", limit)}
	}
	return &Stop{Stage: stage, Code: "response_too_large",
		Detail: fmt.Sprintf("the response is larger than the %d-byte API response limit; it was not parsed", limit)}
}

// errorStop classifies a 4xx or 5xx API response. It reads the bounded
// message first, because a 403 that spent the last unit of the allowance
// carries x-ratelimit-remaining 0 without being a rate limit. Rate limiting
// is recognized by status 429, by a message that names a rate limit, by
// retry-after, or by remaining 0 with no message. It stops the collection
// and is never retried. Other statuses get the code chosen by codeFor. Every
// detail is fixed text: the server's message is examined in memory and never
// reported, unless it is exactly one of knownMessages.
func (c *collector) errorStop(x *exchange, codeFor func(status int) string) *Stop {
	status := x.resp.StatusCode
	m := c.errorMessage(x)
	rl := x.rec.RateLimit
	noneLeft := rl != nil && rl.Remaining != nil && *rl.Remaining == 0
	retryAfter := x.resp.Header.Get("Retry-After")
	s := &Stop{Stage: x.stage, HTTPStatus: status, Detail: m.detail}
	if status == http.StatusForbidden || status == http.StatusTooManyRequests {
		if status == http.StatusTooManyRequests || m.namesRateLimit || retryAfter != "" || (noneLeft && !m.present) {
			s.Code = "rate_limited"
			if secs, ok := retryAfterSeconds(retryAfter); ok {
				s.RetryAfterSeconds = &secs
			}
			switch {
			case noneLeft:
				s.RateLimitResetAt = rl.ResetAt
				s.Detail = "primary rate limit: 0 requests remaining until the reset time"
			case retryAfter != "":
				s.Detail = "secondary rate limit: retry-after given"
			case m.namesRateLimit:
				s.Detail = "rate limited: GitHub's message names a rate limit"
			default:
				s.Detail = "HTTP 429 Too Many Requests"
			}
			return s
		}
	}
	s.Code = codeFor(status)
	if noneLeft {
		s.Detail += "; this response also reported 0 requests remaining, so no further API request is sent"
	}
	return s
}

// knownMessages are GitHub error messages the report may name. A message is
// named only when it equals a key exactly, and then the report prints this
// package's constant, not the server's text.
var knownMessages = map[string]string{
	"Bad credentials":                       "Bad credentials",
	"Must have admin rights to Repository.": "Must have admin rights to Repository.",
	"Not Found":                             "Not Found",
	"Requires authentication":               "Requires authentication",
}

// apiMessage is what errorMessage learned from an error body.
type apiMessage struct {
	detail         string // fixed text: "HTTP <status>", optionally with a known message
	present        bool   // the body held a non-empty "message"
	namesRateLimit bool   // that message names a rate limit
}

// errorMessage reads a bounded error body only to classify it.
func (c *collector) errorMessage(x *exchange) apiMessage {
	m := apiMessage{detail: "HTTP " + strconv.Itoa(x.resp.StatusCode)}
	if !identityEncoding(x.resp.Header) {
		return m
	}
	limit, _ := c.limitFor(c.lim.MaxJSONBytes)
	if x.resp.ContentLength > limit {
		return m
	}
	var body bytes.Buffer
	if _, over, err := c.readBody(x, limit, func(b []byte) { body.Write(b) }); err != nil || over {
		return m
	}
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body.Bytes(), &e) != nil || e.Message == "" {
		return m
	}
	m.present = true
	m.namesRateLimit = strings.Contains(strings.ToLower(e.Message), "rate limit")
	if known, ok := knownMessages[e.Message]; ok {
		m.detail += ": " + known
	} else {
		m.detail += " (GitHub's message is withheld: only known messages are reported)"
	}
	return m
}

// Header values reach the report only in these strict forms or from these
// fixed lists.
var (
	protoRE      = regexp.MustCompile(`^HTTP/[0-9](\.[0-9])?$`)
	apiVersionRE = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	enumRE       = regexp.MustCompile(`^[a-z][a-z_]{0,31}$`)

	// The rate-limit resources GET /rate_limit documents.
	knownResources = map[string]bool{"core": true, "search": true, "graphql": true, "integration_manifest": true,
		"source_import": true, "code_scanning_upload": true, "code_scanning_autofix": true,
		"actions_runner_registration": true, "scim": true, "dependency_snapshots": true, "dependency_sbom": true,
		"audit_log": true, "audit_log_streaming": true, "code_search": true}
	knownMediaTypes = map[string]bool{"text/plain": true, "application/octet-stream": true, "application/json": true,
		"application/xml": true, "text/html": true}
	knownCharsets = map[string]bool{"utf-8": true, "us-ascii": true, "iso-8859-1": true}
)

// listed returns v when known lists it, "other" when it does not, and "" for
// an empty value.
func listed(known map[string]bool, v string) string {
	switch {
	case v == "":
		return ""
	case known[v]:
		return v
	}
	return "other"
}

// enumText reports a GitHub enumeration value (event, status, conclusion)
// when it has an enumeration's shape, and "unrecognized" otherwise.
func enumText(v string) string {
	if v == "" || enumRE.MatchString(v) {
		return v
	}
	return "unrecognized"
}

// matching returns v when it matches re, and "" otherwise.
func matching(re *regexp.Regexp, v string) string {
	if re.MatchString(v) {
		return v
	}
	return ""
}

// retryAfterText reports a Retry-After value as delay seconds or as an RFC
// 3339 time, or "unrecognized".
func retryAfterText(v string) string {
	if v == "" {
		return ""
	}
	if n, ok := retryAfterSeconds(v); ok {
		return strconv.FormatInt(n, 10)
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	return "unrecognized"
}

// contentTypeText reports a Content-Type as a listed media type with its
// charset, if any, also from a list; an unlisted media type or charset is
// reported as "other", and an unparsable value as "unrecognized".
func contentTypeText(v string) string {
	if v == "" {
		return ""
	}
	mt, params, err := mime.ParseMediaType(v)
	if err != nil {
		return "unrecognized"
	}
	if !knownMediaTypes[mt] {
		return "other"
	}
	switch cs := strings.ToLower(params["charset"]); {
	case cs == "":
		return mt
	case knownCharsets[cs]:
		return mt + "; charset=" + cs
	}
	return mt + "; charset=other"
}

func parseRateLimit(h http.Header) *RateLimit {
	num := func(name string) *int64 {
		v := h.Get(name)
		if v == "" {
			return nil
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil
		}
		return &n
	}
	rl := &RateLimit{
		Limit:     num("X-RateLimit-Limit"),
		Remaining: num("X-RateLimit-Remaining"),
		Used:      num("X-RateLimit-Used"),
		Reset:     num("X-RateLimit-Reset"),
		Resource:  listed(knownResources, h.Get("X-RateLimit-Resource")),
	}
	if rl.Limit == nil && rl.Remaining == nil && rl.Used == nil && rl.Reset == nil && rl.Resource == "" {
		return nil
	}
	if rl.Reset != nil {
		rl.ResetAt = epochText(*rl.Reset)
	}
	return rl
}

func epochText(sec int64) string {
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// retryAfterSeconds parses a delay-seconds Retry-After value.
func retryAfterSeconds(v string) (int64, bool) {
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
