package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var shaRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

// API response shapes: only the fields the probe reads. Unknown fields are
// ignored because the API adds fields over time.

type rateLimitDoc struct {
	Resources struct {
		Core *struct {
			Limit     int64 `json:"limit"`
			Remaining int64 `json:"remaining"`
			Reset     int64 `json:"reset"`
			Used      int64 `json:"used"`
		} `json:"core"`
	} `json:"resources"`
}

type repoDoc struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Private  *bool  `json:"private"` // required in the run schema (API version 2026-03-10)
}

type runDoc struct {
	ID             int64    `json:"id"`
	Name           *string  `json:"name"`
	HeadBranch     *string  `json:"head_branch"`
	HeadSHA        string   `json:"head_sha"`
	Path           string   `json:"path"`
	RunNumber      int64    `json:"run_number"`
	RunAttempt     int64    `json:"run_attempt"`
	Event          string   `json:"event"`
	Status         *string  `json:"status"`
	Conclusion     *string  `json:"conclusion"`
	WorkflowID     int64    `json:"workflow_id"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
	RunStartedAt   string   `json:"run_started_at"`
	Repository     repoDoc  `json:"repository"`
	HeadRepository *repoDoc `json:"head_repository"`
}

type jobsDoc struct {
	TotalCount *int64   `json:"total_count"`
	Jobs       []jobDoc `json:"jobs"`
}

type jobDoc struct {
	ID          int64     `json:"id"`
	RunID       int64     `json:"run_id"`
	RunAttempt  *int64    `json:"run_attempt"`
	HeadSHA     string    `json:"head_sha"`
	Status      string    `json:"status"`
	Conclusion  *string   `json:"conclusion"`
	Name        string    `json:"name"`
	StartedAt   *string   `json:"started_at"`
	CompletedAt *string   `json:"completed_at"`
	Labels      []string  `json:"labels"`
	Steps       []stepDoc `json:"steps"`
}

type stepDoc struct {
	Name       string  `json:"name"`
	Number     int64   `json:"number"`
	Conclusion *string `json:"conclusion"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// Probe runs one bounded, unauthenticated, read-only probe of ref against
// api.github.com and returns its report. It validates ref first: invalid
// input makes no request and is not echoed. It stops at the first rate limit,
// budget limit, error or ambiguity, and never retries a request.
func Probe(ctx context.Context, ref RunRef, lim Limits) *Report {
	return probe(ctx, ref, lim, newTransport(), nil)
}

// ProbeWithGH is Probe with the github.com login stored by the GitHub CLI
// (see ghCLI) for the job-log request only. Run, attempt and job metadata are
// read without a credential. gh is run only after the repository is shown to
// be public, the run, attempt and job identities match, and one failed job is
// selected; invalid, private or mismatched input never runs gh. If no
// credential is usable, the probe stops with credential_unavailable before
// the job-log request. The credential is attached only to the job-log
// request on api.github.com, never to a metadata request or the log
// download, and never appears in the report.
func ProbeWithGH(ctx context.Context, ref RunRef, lim Limits) *Report {
	return probe(ctx, ref, lim, newTransport(), newGHSource())
}

// The exported entry points build their transport and credential source
// through these, so that tests of those entry points can replace both and no
// test can reach the network or run gh through them.
var (
	newTransport = func() http.RoundTripper { return NewTransport() }
	newGHSource  = func() credentialSource { return ghCLI{} }
)

func probe(parent context.Context, ref RunRef, lim Limits, rt http.RoundTripper, src credentialSource) *Report {
	rep, _ := probeWith(parent, ref, lim, rt, src, false)
	return rep
}

func probeWith(parent context.Context, ref RunRef, lim Limits, rt http.RoundTripper, src credentialSource, keep bool) (*Report, *evidence) {
	start := time.Now()
	rep := &Report{Report: ReportName, StartedAt: start.UTC().Format(time.RFC3339), Auth: "none", APIVersion: APIVersion,
		Requests: []*Request{}, Uncertainty: []string{}}
	if src != nil {
		rep.Auth = src.name()
	}
	ctx, cancel := context.WithTimeoutCause(parent, lim.Deadline, errDeadline)
	defer cancel()
	c := newCollector(ctx, lim, rt)
	c.keepLog = keep
	var ev *evidence
	var stop *Stop
	if err := ref.Validate(); err != nil {
		stop = &Stop{Stage: "input", Code: "invalid_input", Detail: err.Error()}
	} else {
		rep.Input = &ref
		switch err := lim.check(); {
		case err != nil:
			stop = &Stop{Stage: "input", Code: "invalid_limits", Detail: err.Error()}
		case http2DebugLogging():
			stop = &Stop{Stage: "input", Code: "unsafe_environment",
				Detail: "GODEBUG turns on Go's HTTP/2 debug logging, which prints request headers and URLs; unset http2debug to run the probe"}
		}
		if stop == nil {
			c.src = src
			ev, stop = c.run(ref, rep)
		}
	}
	rep.Stop = stop
	switch {
	case stop == nil:
		rep.Outcome = "complete"
	case rep.Job != nil:
		rep.Outcome = "incomplete"
	default:
		rep.Outcome = "stopped"
	}
	rep.Requests = append(rep.Requests, c.reqs...)
	rep.Budget = Budget{
		Requests: len(c.reqs), MaxRequests: lim.MaxRequests,
		BodyBytes: c.bytes, MaxBodyBytes: lim.MaxTotalBytes,
		MaxJSONBytes: lim.MaxJSONBytes, MaxLogBytes: lim.MaxLogBytes,
		RequestTimeoutMS: lim.RequestTimeout.Milliseconds(), DeadlineMS: lim.Deadline.Milliseconds(),
		ElapsedMS: time.Since(start).Milliseconds(),
	}
	if ev != nil {
		ev.Log.Bytes = c.logBuf
		if c.cred.usable() {
			token := c.cred.token()
			ev.credCheck = func(b []byte) bool { return containsPiece(b, token) }
		}
	}
	if c.cred.usable() && revealsToken(rep, c.cred.token()) {
		return withheld(rep, c.cred.token()), nil
	}
	return rep, ev
}

// godebugAtStart is GODEBUG as it was when the process started, which is when
// Go's HTTP/2 code read it.
var godebugAtStart = os.Getenv("GODEBUG")

// http2DebugLogging reports whether GODEBUG turns on Go's HTTP/2 debug
// logging, now or at process start. That logging prints every request header
// (the credential included), request paths (the signed log URL included) and
// response headers through package log. The test mirrors Go's own.
func http2DebugLogging() bool {
	for _, v := range []string{godebugAtStart, os.Getenv("GODEBUG")} {
		if strings.Contains(v, "http2debug=1") || strings.Contains(v, "http2debug=2") {
			return true
		}
	}
	return false
}

// authenticate obtains the credential once. A failure is reported with a
// fixed reason; text from the source is never shown.
func (c *collector) authenticate(src credentialSource) *Stop {
	cred, err := src.credential(c.ctx)
	if code := ctxCode(c.ctx); code != "" { // cancelled or out of time while the source ran
		return &Stop{Stage: "credential", Code: code, Detail: ctxDetail(code)}
	}
	if err == nil && !cred.usable() {
		err = &credentialError{"the credential source returned something that is not a token"}
	}
	if err != nil {
		detail := "no usable credential was obtained"
		var ce *credentialError
		if errors.As(err, &ce) {
			detail = ce.reason
		}
		return &Stop{Stage: "credential", Code: "credential_unavailable", Detail: detail}
	}
	c.cred = cred
	return nil
}

// tokenPiece is the length of the token pieces the fail-closed checks look
// for. Tokens are random, so a 12-character piece in unrelated text is not a
// practical false positive.
const tokenPiece = 12

// tokenPrefixes are the fixed, public prefixes of GitHub token formats.
var tokenPrefixes = []string{"github_pat_", "gho_", "ghp_", "ghu_", "ghs_", "ghr_"}

// containsPiece reports whether s holds any tokenPiece-character piece of
// token, ignoring case (a lower-cased token is still exposed). Pieces come
// only from the part after a known prefix, so text that merely mentions a
// prefix, such as a step named "Set GITHUB_PAT_TOKEN", is not taken for the
// token.
func containsPiece(s []byte, token string) bool {
	ls, lt := bytes.ToLower(s), strings.ToLower(token)
	for _, p := range tokenPrefixes {
		if strings.HasPrefix(lt, p) {
			lt = lt[len(p):]
			break
		}
	}
	for i := 0; i+tokenPiece <= len(lt); i++ {
		if bytes.Contains(ls, []byte(lt[i:i+tokenPiece])) {
			return true
		}
	}
	return false
}

// revealsToken reports whether the marshalled report holds a piece of the
// token. GitHub is not expected to echo a token, but the report fails closed
// if a response ever did.
func revealsToken(rep *Report, token string) bool {
	b, err := json.Marshal(rep)
	return err != nil || containsPiece(b, token)
}

// withheld replaces a report that would reveal the credential with one that
// keeps only fixed text, the validated input and counts. The input is
// dropped too if it holds a piece of the token.
func withheld(rep *Report, token string) *Report {
	w := &Report{
		Report: rep.Report, StartedAt: rep.StartedAt, Auth: rep.Auth, APIVersion: rep.APIVersion, Input: rep.Input,
		Outcome: "stopped", Budget: rep.Budget, Requests: []*Request{},
		Stop: &Stop{Stage: "report", Code: "credential_in_output",
			Detail: "a response would have put part of the credential into this report, so the report was withheld"},
		Uncertainty: []string{"Everything the probe learned was withheld with the report."},
	}
	if revealsToken(w, token) {
		w.Input = nil
	}
	return w
}

// run makes the collection's requests. It returns evidence once one failed
// job of a public run is selected, whatever happens to the log after that.
func (c *collector) run(ref RunRef, rep *Report) (*evidence, *Stop) {
	note := func(format string, a ...any) {
		rep.Uncertainty = append(rep.Uncertainty, fmt.Sprintf(format, a...))
	}

	// 1. The core allowance. GitHub documents that GET /rate_limit does not
	// count against the primary rate limit.
	var rl rateLimitDoc
	if s := c.getJSON("allowance", "/rate_limit", nil, &rl); s != nil {
		return nil, s
	}
	core := rl.Resources.Core
	if core == nil {
		return nil, &Stop{Stage: "allowance", Code: "invalid_response", Detail: "resources.core is missing"}
	}
	// The requests made without a credential: run, attempt, job pages, and
	// the job-log link unless that is authenticated (it then counts against
	// the login's allowance, which this probe does not query).
	need := int64(2 + c.lim.MaxJobPages)
	if c.src == nil {
		need++
	}
	rep.Allowance = &Allowance{Limit: core.Limit, Remaining: core.Remaining, Used: core.Used, ResetAt: epochText(core.Reset), Needed: need}
	if core.Remaining < need {
		return nil, &Stop{Stage: "allowance", Code: "rate_limit_low", RateLimitResetAt: epochText(core.Reset),
			Detail: fmt.Sprintf("%d core requests remain and this probe may need %d; nothing else was requested", core.Remaining, need)}
	}

	// 2. The run, which the API describes as of its latest attempt.
	base := fmt.Sprintf("/repos/%s/%s/actions/runs/%d", ref.Owner, ref.Repo, ref.RunID)
	noPRs := url.Values{"exclude_pull_requests": {"true"}}
	var latest runDoc
	if s := c.getJSON("run", base, noPRs, &latest); s != nil {
		return nil, s
	}
	if s := checkRun("run", ref, &latest); s != nil {
		return nil, s
	}
	attempt := ref.Attempt
	switch {
	case attempt == 0:
		attempt = latest.RunAttempt
		note("The URL named no attempt, so the latest attempt at probe time (%d) was used.", attempt)
	case attempt > latest.RunAttempt:
		return nil, &Stop{Stage: "run", Code: "attempt_not_found",
			Detail: fmt.Sprintf("attempt %d was requested but the run's latest attempt is %d", attempt, latest.RunAttempt)}
	case attempt < latest.RunAttempt:
		note("Attempt %d is not the run's latest attempt (%d).", attempt, latest.RunAttempt)
	}

	// 3. The selected attempt.
	var at runDoc
	if s := c.getJSON("attempt", fmt.Sprintf("%s/attempts/%d", base, attempt), noPRs, &at); s != nil {
		return nil, s
	}
	if s := checkRun("attempt", ref, &at); s != nil {
		return nil, s
	}
	if at.RunAttempt != attempt {
		return nil, &Stop{Stage: "attempt", Code: "attempt_mismatch",
			Detail: fmt.Sprintf("attempt %d was requested but the response describes attempt %d", attempt, at.RunAttempt)}
	}
	rep.Repository = &Repository{ID: at.Repository.ID, FullName: safeText(at.Repository.FullName, 140), Private: *at.Repository.Private}
	rep.Run = runInfo(&at, latest.RunAttempt)
	note("head_sha is run metadata. This probe did not establish which commit any job checked out.")
	checkTimes(note, "The attempt", at.CreatedAt, at.RunStartedAt, at.UpdatedAt)
	if at.HeadRepository != nil && at.HeadRepository.ID != at.Repository.ID {
		note("The attempt's head_repository differs from its repository.")
	}
	if at.Event != "push" || str(at.Status) != "completed" || str(at.Conclusion) != "failure" {
		return nil, &Stop{Stage: "attempt", Code: "run_not_eligible",
			Detail: fmt.Sprintf("event %q, status %q, conclusion %q; a completed push run with conclusion failure is required",
				rep.Run.Event, rep.Run.Status, rep.Run.Conclusion)}
	}

	// 4. The jobs of this attempt, from the attempt-specific route.
	jobs, info, s := c.listJobs(base, ref.RunID, attempt, note)
	rep.Jobs = info
	if s != nil {
		return nil, s
	}

	// 5. One failed job, never a guess among several.
	job, s := selectJob(jobs, info, ref.JobID)
	if s != nil {
		return nil, s
	}
	rep.Job = jobInfo(job)
	checkTimes(note, "The selected job", str(job.StartedAt), str(job.CompletedAt))
	if job.HeadSHA != at.HeadSHA {
		note("The selected job's head_sha differs from the run's head_sha.")
	}
	ev := evidenceOf(&at, job)

	// 6. Only now, with a public run, matching identities and one failed job,
	// is the credential obtained (authenticated mode). It is attached only to
	// the job-log request.
	if c.src != nil {
		if s := c.authenticate(c.src); s != nil {
			ev.Log = logResult{MissingReason: "not_collected", Authentication: "none"}
			return ev, s
		}
	}

	// 7. Its log: counted, then discarded, or kept in memory for Collect.
	lg, s := c.fetchLog(ref, job.ID)
	rep.Log = lg
	ev.Log = logEvidence(lg, s, c.cred.usable())
	if lg.BytesRead > 0 && !c.keepLog {
		note("The log text was hashed and counted, then discarded. It was not stored, printed or inspected.")
	}
	if lg.State == "prefix" || lg.State == "interrupted" || lg.State == "end_unverified" {
		note("The log is not known to be complete. bytes_read, lines and sha256 cover only the bytes read; the last line may be partial.")
	}
	return ev, s
}

func checkRun(stage string, ref RunRef, d *runDoc) *Stop {
	switch {
	case d.ID != ref.RunID:
		return &Stop{Stage: stage, Code: "identity_mismatch", Detail: fmt.Sprintf("the response describes run %d, not run %d", d.ID, ref.RunID)}
	case d.Repository.ID < 1 || !strings.EqualFold(d.Repository.FullName, ref.Owner+"/"+ref.Repo):
		return &Stop{Stage: stage, Code: "identity_mismatch", Detail: "the response describes a different repository"}
	case d.Repository.Private == nil || *d.Repository.Private:
		return &Stop{Stage: stage, Code: "repository_not_public",
			Detail: "the response does not state that the repository is public; this probe reads public repositories only"}
	case d.RunAttempt < 1:
		return &Stop{Stage: stage, Code: "invalid_response", Detail: "run_attempt is missing"}
	case !shaRE.MatchString(d.HeadSHA):
		return &Stop{Stage: stage, Code: "invalid_response", Detail: "head_sha is not 40 lowercase hexadecimal characters"}
	}
	return nil
}

func checkTimes(note func(string, ...any), what string, values ...string) {
	for _, v := range values {
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			note("%s has a missing or non-RFC 3339 timestamp.", what)
			return
		}
	}
}

func runInfo(d *runDoc, latest int64) *RunInfo {
	return &RunInfo{
		ID: d.ID, Attempt: d.RunAttempt, LatestAttempt: latest, RunNumber: d.RunNumber,
		Event: enumText(d.Event), Status: enumText(str(d.Status)), Conclusion: enumText(str(d.Conclusion)),
		HeadBranch: safeText(str(d.HeadBranch), 255), HeadSHA: d.HeadSHA,
		WorkflowID: d.WorkflowID, WorkflowPath: safeText(d.Path, 255), WorkflowName: safeText(str(d.Name), 200),
		CreatedAt: safeText(d.CreatedAt, 40), RunStartedAt: safeText(d.RunStartedAt, 40), UpdatedAt: safeText(d.UpdatedAt, 40),
	}
}

// listJobs lists the jobs of one attempt, up to MaxJobPages pages of 100. A
// job from another run or attempt stops the probe: those jobs are not this
// attempt's evidence.
func (c *collector) listJobs(base string, runID, attempt int64, note func(string, ...any)) ([]jobDoc, *JobsInfo, *Stop) {
	route := fmt.Sprintf("%s/attempts/%d/jobs", base, attempt)
	var jobs []jobDoc
	var total int64
	seen := map[int64]bool{}
	pages, missingAttempt := 0, false
	for page := 1; page <= c.lim.MaxJobPages; page++ {
		var doc jobsDoc
		q := url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if s := c.getJSON("jobs", route, q, &doc); s != nil {
			return nil, nil, s
		}
		pages = page
		switch {
		case doc.TotalCount == nil || *doc.TotalCount < 0:
			return nil, nil, &Stop{Stage: "jobs", Code: "invalid_response", Detail: "total_count is missing"}
		case page == 1:
			total = *doc.TotalCount
		case *doc.TotalCount != total:
			return nil, nil, &Stop{Stage: "jobs", Code: "invalid_response", Detail: "total_count changed between pages"}
		}
		for _, j := range doc.Jobs {
			switch {
			case j.ID < 1:
				return nil, nil, &Stop{Stage: "jobs", Code: "invalid_response", Detail: "a job has no id"}
			case j.RunID != runID:
				return nil, nil, &Stop{Stage: "jobs", Code: "attempt_mismatch",
					Detail: fmt.Sprintf("job %d belongs to run %d, not run %d", j.ID, j.RunID, runID)}
			case j.RunAttempt != nil && *j.RunAttempt != attempt:
				return nil, nil, &Stop{Stage: "jobs", Code: "attempt_mismatch",
					Detail: fmt.Sprintf("job %d belongs to attempt %d, not attempt %d", j.ID, *j.RunAttempt, attempt)}
			}
			if j.RunAttempt == nil {
				missingAttempt = true
			}
			if !seen[j.ID] {
				seen[j.ID] = true
				jobs = append(jobs, j)
			}
		}
		if int64(len(jobs)) >= total || len(doc.Jobs) == 0 {
			break
		}
	}
	if missingAttempt {
		note("Some jobs did not state run_attempt; for them the attempt-specific route is the only attempt evidence.")
	}
	info := &JobsInfo{TotalCount: total, Listed: len(jobs), Pages: pages, Complete: int64(len(jobs)) == total,
		Conclusions: map[string]int{}, Failed: []JobChoice{}}
	for _, j := range jobs {
		k := str(j.Conclusion)
		if j.Conclusion == nil {
			k = "null"
		}
		info.Conclusions[enumText(k)]++
		if str(j.Conclusion) == "failure" {
			info.FailedCount++
			if len(info.Failed) < 50 {
				info.Failed = append(info.Failed, JobChoice{ID: j.ID, Name: safeText(j.Name, 200)})
			}
		}
	}
	return jobs, info, nil
}

func selectJob(jobs []jobDoc, info *JobsInfo, want int64) (*jobDoc, *Stop) {
	if want != 0 {
		for i := range jobs {
			if jobs[i].ID != want {
				continue
			}
			if c := str(jobs[i].Conclusion); c != "failure" {
				return nil, &Stop{Stage: "select", Code: "job_not_failed",
					Detail: fmt.Sprintf("job %d has conclusion %q; a failed job is required", want, enumText(c))}
			}
			return &jobs[i], nil
		}
		if !info.Complete {
			return nil, &Stop{Stage: "select", Code: "job_list_incomplete",
				Detail: fmt.Sprintf("job %d is not among the %d of %d jobs listed", want, info.Listed, info.TotalCount)}
		}
		return nil, &Stop{Stage: "select", Code: "job_not_in_attempt", Detail: fmt.Sprintf("job %d is not a job of this attempt", want)}
	}
	if !info.Complete {
		return nil, &Stop{Stage: "select", Code: "job_list_incomplete",
			Detail: fmt.Sprintf("only %d of %d jobs were listed, so the failed jobs may be incomplete; name one with -job", info.Listed, info.TotalCount)}
	}
	var failed []*jobDoc
	for i := range jobs {
		if str(jobs[i].Conclusion) == "failure" {
			failed = append(failed, &jobs[i])
		}
	}
	switch len(failed) {
	case 0:
		return nil, &Stop{Stage: "select", Code: "no_failed_job", Detail: "no job of this attempt has conclusion failure"}
	case 1:
		return failed[0], nil
	}
	return nil, &Stop{Stage: "select", Code: "job_choice_required",
		Detail: fmt.Sprintf("%d jobs failed; choose one from jobs.failed and pass its id with -job", len(failed))}
}

func jobInfo(j *jobDoc) *JobInfo {
	ji := &JobInfo{
		ID: j.ID, Name: safeText(j.Name, 200), RunAttempt: j.RunAttempt,
		Status: enumText(j.Status), Conclusion: enumText(str(j.Conclusion)),
		StartedAt: safeText(str(j.StartedAt), 40), CompletedAt: safeText(str(j.CompletedAt), 40),
		HeadSHA: safeText(j.HeadSHA, 40), Labels: []string{}, FailedSteps: []Step{},
	}
	for i, l := range j.Labels {
		if i == 10 {
			break
		}
		ji.Labels = append(ji.Labels, safeText(l, 64))
	}
	for _, st := range j.Steps {
		if str(st.Conclusion) == "failure" && len(ji.FailedSteps) < 10 {
			ji.FailedSteps = append(ji.FailedSteps, Step{Number: st.Number, Name: safeText(st.Name, 200)})
		}
	}
	return ji
}

// fetchLog asks the documented job-log endpoint for its redirect, checks the
// destination against the allowed-host policy, and downloads at most the
// log limit with a fresh request that carries no API header. The text is
// hashed and line-counted, then discarded. The redirect URL is never stored.
func (c *collector) fetchLog(ref RunRef, jobID int64) (*LogInfo, *Stop) {
	lg := &LogInfo{State: "unavailable"}
	u := &url.URL{Scheme: "https", Host: apiHost, Path: fmt.Sprintf("/repos/%s/%s/actions/jobs/%d/logs", ref.Owner, ref.Repo, jobID)}
	x, s := c.send("log", u, "GET "+u.RequestURI(), true, c.cred.usable())
	if s != nil {
		return lg, s
	}
	lg.APIStatus = x.resp.StatusCode
	if x.resp.StatusCode != http.StatusFound {
		defer x.close()
		return lg, c.logLinkError(x)
	}
	location := x.resp.Header.Get("Location")
	x.close() // the redirect's own body is not read
	if c.cred.usable() && containsPiece([]byte(location), c.cred.token()) {
		return lg, &Stop{Stage: "log", Code: "redirect_rejected", HTTPStatus: http.StatusFound,
			Detail: "the redirect URL contains part of the credential; it was not followed"}
	}
	target, err := checkLogRedirect(location)
	if err != nil {
		s := &Stop{Stage: "log", Code: "redirect_rejected", HTTPStatus: http.StatusFound, Detail: err.Error() + "; it was not followed"}
		var re *redirectError
		if errors.As(err, &re) && re.Host != "" {
			s.Detail += " (host " + re.Host + ")"
		}
		return lg, s
	}
	lg.RedirectHost = strings.ToLower(target.Hostname())
	d, s := c.send("log_download", target, "GET [job-log redirect destination; path and query not recorded]", false, false)
	if s != nil {
		return lg, s
	}
	defer d.close()
	lg.DownloadStatus = d.resp.StatusCode
	switch code := d.resp.StatusCode; {
	case code >= 300 && code < 400:
		return lg, &Stop{Stage: "log_download", Code: "redirect_limit", HTTPStatus: code,
			Detail: "the download redirected again; only one redirect is followed"}
	case code != http.StatusOK:
		return lg, &Stop{Stage: "log_download", Code: "download_failed", HTTPStatus: code,
			Detail: "the log download did not answer 200 (an expired link answers this way); its body was not read"}
	}
	if !identityEncoding(d.resp.Header) {
		return lg, &Stop{Stage: "log_download", Code: "unexpected_encoding",
			Detail: "the log has a content encoding that was not requested; it was not read"}
	}
	lg.ContentType = contentTypeText(d.resp.Header.Get("Content-Type"))
	if cl := d.resp.ContentLength; cl >= 0 {
		lg.DeclaredBytes = &cl
	}
	limit, aggregate := c.limitFor(c.lim.MaxLogBytes)
	h := sha256.New()
	var lines lineCounter
	got, over, err := c.readBody(d, limit, func(b []byte) {
		h.Write(b)
		lines.write(b)
		if c.keepLog {
			c.logBuf = append(c.logBuf, b...) // bounded by the log limit; memory only
		}
	})
	lg.BytesRead, lg.Lines = got, lines.lines()
	if got > 0 || (err == nil && !over) {
		lg.SHA256 = hex.EncodeToString(h.Sum(nil))
	}
	// An HTTP/1 body with neither Content-Length nor chunked encoding ends when
	// the connection closes, so a cut connection looks like the end of the log.
	framed := d.resp.ContentLength >= 0 || d.resp.ProtoMajor >= 2 || slices.Contains(d.resp.TransferEncoding, "chunked")
	switch {
	case err != nil:
		if got > 0 {
			lg.State = "interrupted"
		}
		return lg, c.failure("log_download", d.ctx, err)
	case over && aggregate:
		lg.State = "prefix"
		return lg, &Stop{Stage: "log_download", Code: "byte_limit",
			Detail: fmt.Sprintf("reading stopped after %d bytes, the rest of the collection's byte limit", limit)}
	case over:
		lg.State = "prefix"
		return lg, &Stop{Stage: "log_download", Code: "log_limit",
			Detail: fmt.Sprintf("reading stopped at the %d-byte log limit", limit)}
	case !framed:
		lg.State = "end_unverified"
		return lg, &Stop{Stage: "log_download", Code: "unframed_body",
			Detail: "the download had no Content-Length or chunked encoding, so the end of the log cannot be told from a closed connection; it is not reported as complete"}
	}
	lg.State = "complete"
	return lg, nil
}

// logLinkError classifies a job-log endpoint response other than 302. Its
// body is read only for an error status, and only to the JSON limit.
func (c *collector) logLinkError(x *exchange) *Stop {
	if code := x.resp.StatusCode; code < 400 {
		return &Stop{Stage: "log", Code: "unexpected_status", HTTPStatus: code,
			Detail: "the documented response is 302 with a Location header"}
	}
	return c.errorStop(x, func(status int) string {
		switch status {
		case http.StatusUnauthorized:
			return unauthorizedCode(x.rec.Authenticated)
		case http.StatusForbidden:
			return "access_denied"
		case http.StatusNotFound:
			return "not_found"
		case http.StatusGone:
			return "gone"
		}
		return "http_error"
	})
}
