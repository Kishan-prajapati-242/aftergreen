package github

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ReportName identifies the probe report. The report is not an evidence
// bundle; CollectBundle builds those (contracts/bundle-v1.md).
const ReportName = "aftergreen.github-probe (metadata only, not an evidence bundle)"

// Report is the probe's output. It holds metadata and measurements for one
// run attempt and one job. It never contains log text, a signed URL, a
// credential or source file content. Every string that came from GitHub has
// either been passed through safeText or matched a strict pattern (the
// redirect host, the head SHA), so the report is safe to print to a terminal.
// It is not HTML-escaped.
type Report struct {
	Report         string      `json:"report"`
	EvidenceBundle bool        `json:"evidence_bundle"`
	StartedAt      string      `json:"started_at"` // UTC, from this computer's clock
	Auth           string      `json:"auth"`       // "none", or the credential source ("gh")
	Outcome        string      `json:"outcome"`    // complete, incomplete (job selected, log not fully read) or stopped
	Stop           *Stop       `json:"stop,omitempty"`
	APIVersion     string      `json:"api_version"`
	Input          *RunRef     `json:"input,omitempty"` // set only after the input passed RunRef.Validate
	Allowance      *Allowance  `json:"allowance,omitempty"`
	Repository     *Repository `json:"repository,omitempty"`
	Run            *RunInfo    `json:"run,omitempty"`
	Jobs           *JobsInfo   `json:"jobs,omitempty"`
	Job            *JobInfo    `json:"job,omitempty"`
	Log            *LogInfo    `json:"log,omitempty"`
	Requests       []*Request  `json:"requests"`
	Budget         Budget      `json:"budget"`
	Uncertainty    []string    `json:"uncertainty"`
}

// Stop says where and why the probe stopped, or why the log is incomplete.
type Stop struct {
	Stage             string `json:"stage"`
	Code              string `json:"code"`
	Detail            string `json:"detail,omitempty"`
	HTTPStatus        int    `json:"http_status,omitempty"`
	RetryAfterSeconds *int64 `json:"retry_after_seconds,omitempty"`
	RateLimitResetAt  string `json:"rate_limit_reset_at,omitempty"`
}

// Allowance is the core REST allowance reported by GET /rate_limit before
// any counted request, and the most core requests this probe could need.
type Allowance struct {
	Limit     int64  `json:"limit"`
	Remaining int64  `json:"remaining"`
	Used      int64  `json:"used"`
	ResetAt   string `json:"reset_at"`
	Needed    int64  `json:"needed"`
}

// Repository is the run's repository. The probe stops unless both the run
// and the attempt response state private: false.
type Repository struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

// RunInfo is the run as the attempt endpoint describes the selected attempt.
// HeadSHA is run metadata: it does not establish what a job checked out.
type RunInfo struct {
	ID            int64  `json:"id"`
	Attempt       int64  `json:"attempt"`
	LatestAttempt int64  `json:"latest_attempt"`
	RunNumber     int64  `json:"run_number"`
	Event         string `json:"event"`
	Status        string `json:"status"`
	Conclusion    string `json:"conclusion"`
	HeadBranch    string `json:"head_branch"`
	HeadSHA       string `json:"head_sha"`
	WorkflowID    int64  `json:"workflow_id"`
	WorkflowPath  string `json:"workflow_path"`
	WorkflowName  string `json:"workflow_name"`
	CreatedAt     string `json:"created_at"`
	RunStartedAt  string `json:"run_started_at"`
	UpdatedAt     string `json:"updated_at"`
}

// JobsInfo summarizes the attempt's job list.
type JobsInfo struct {
	TotalCount  int64          `json:"total_count"`
	Listed      int            `json:"listed"`
	Pages       int            `json:"pages"`
	Complete    bool           `json:"complete"`
	Conclusions map[string]int `json:"conclusions"`
	FailedCount int            `json:"failed_count"`
	Failed      []JobChoice    `json:"failed"` // conclusion "failure", API order, at most 50
}

type JobChoice struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type JobInfo struct {
	ID          int64    `json:"id"`
	Name        string   `json:"name"`
	RunAttempt  *int64   `json:"run_attempt"`
	Status      string   `json:"status"`
	Conclusion  string   `json:"conclusion"`
	StartedAt   string   `json:"started_at"`
	CompletedAt string   `json:"completed_at"`
	HeadSHA     string   `json:"head_sha"`
	Labels      []string `json:"labels"`
	FailedSteps []Step   `json:"failed_steps"`
}

type Step struct {
	Number int64  `json:"number"`
	Name   string `json:"name"`
}

// LogInfo describes the job-log download. State is complete, prefix (reading
// stopped at a byte limit), interrupted (the transfer ended early),
// end_unverified (the body ended with the connection, so completeness cannot
// be shown) or unavailable (no log bytes were obtained). Lines counts the bytes read by
// the rules of contracts/bundle-v0.md section 4; SHA256 covers the same
// bytes. Only the redirect's host is recorded, never its path or query.
type LogInfo struct {
	State          string `json:"state"`
	APIStatus      int    `json:"api_status,omitempty"`
	RedirectHost   string `json:"redirect_host,omitempty"`
	DownloadStatus int    `json:"download_status,omitempty"`
	ContentType    string `json:"content_type,omitempty"`
	DeclaredBytes  *int64 `json:"declared_bytes,omitempty"`
	BytesRead      int64  `json:"bytes_read"`
	Lines          int64  `json:"lines"`
	SHA256         string `json:"sha256,omitempty"`
}

// Request records one HTTP request. Route is the fixed API route; for the
// redirected download only the host is recorded.
type Request struct {
	N                  int        `json:"n"`
	Stage              string     `json:"stage"`
	Route              string     `json:"route"`
	Host               string     `json:"host"`
	Status             int        `json:"status,omitempty"`
	Proto              string     `json:"proto,omitempty"`
	Authenticated      bool       `json:"authenticated"` // the credential was attached; only ever to api.github.com
	BodyBytes          int64      `json:"body_bytes"`
	RateLimit          *RateLimit `json:"rate_limit,omitempty"`
	RetryAfter         string     `json:"retry_after,omitempty"`
	APIVersionSelected string     `json:"api_version_selected,omitempty"`
	Error              string     `json:"error,omitempty"`
}

// RateLimit holds the x-ratelimit-* response headers that were present.
type RateLimit struct {
	Limit     *int64 `json:"limit,omitempty"`
	Remaining *int64 `json:"remaining,omitempty"`
	Used      *int64 `json:"used,omitempty"`
	Reset     *int64 `json:"reset,omitempty"`
	ResetAt   string `json:"reset_at,omitempty"`
	Resource  string `json:"resource,omitempty"`
}

type Budget struct {
	Requests         int   `json:"requests"`
	MaxRequests      int   `json:"max_requests"`
	BodyBytes        int64 `json:"body_bytes"`
	MaxBodyBytes     int64 `json:"max_body_bytes"`
	MaxJSONBytes     int64 `json:"max_json_bytes"`
	MaxLogBytes      int64 `json:"max_log_bytes"`
	RequestTimeoutMS int64 `json:"request_timeout_ms"`
	DeadlineMS       int64 `json:"deadline_ms"`
	ElapsedMS        int64 `json:"elapsed_ms"`
}

// safeText makes an untrusted string safe to print. Control and format
// characters, line and paragraph separators, variation selectors and other
// default-ignorable characters become visible \u{XXXX} escapes, invalid UTF-8
// becomes U+FFFD, and the result is cut after max bytes with a marker. A
// literal "\u{...}" or "[cut]" in the input looks the same as an escape.
func safeText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		var piece string
		switch {
		case r == utf8.RuneError:
			piece = "\uFFFD"
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' ||
			unicode.Is(unicode.Variation_Selector, r) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
			piece = fmt.Sprintf(`\u{%04X}`, r)
		default:
			piece = string(r)
		}
		if b.Len()+len(piece) > max {
			b.WriteString("[cut]")
			break
		}
		b.WriteString(piece)
	}
	return b.String()
}

// lineCounter counts lines as contracts/bundle-v0.md section 4 does: split on
// LF, a final LF does not start another line, and empty text has 0 lines.
type lineCounter struct {
	lf   int64
	last byte
	seen bool
}

func (l *lineCounter) write(p []byte) {
	if len(p) == 0 {
		return
	}
	l.lf += int64(bytes.Count(p, []byte{'\n'}))
	l.last = p[len(p)-1]
	l.seen = true
}

func (l *lineCounter) lines() int64 {
	if l.seen && l.last != '\n' {
		return l.lf + 1
	}
	return l.lf
}
