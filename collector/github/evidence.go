package github

import "aftergreen/collector/logbundle"

// evidence is what one collection established, in the form the API returned
// it, for building an evidence bundle (see CollectBundle). It exists only
// once one failed job of a public run was selected. The log bytes are held in
// memory and never leave this package except into logbundle.Build.
type evidence struct {
	RepoID           int64
	FullName         string
	Public           bool // the run and the attempt response both stated "private": false
	WorkflowID       int64
	WorkflowPath     string
	RunID            int64
	RunAttempt       int64
	AttemptStartedAt string // the attempt response's run_started_at
	Event            string
	Branch           string
	HeadSHA          string // run metadata; it does not establish what the job checked out
	JobID            int64
	JobName          string
	JobConclusion    string
	JobStartedAt     string
	JobCompletedAt   string
	JobLabels        []string
	Log              logResult

	credCheck func([]byte) bool // set when a credential was used
}

// logResult describes the job-log request and what it returned.
type logResult struct {
	Obtained       bool   // bytes were received from the log download
	Extent         string // when Obtained: complete, prefix (a byte limit) or partial (ended early, or end unverifiable)
	MissingReason  string // when not Obtained: a bundle v1 missing_reason
	Authentication string // how the job-log request was made: "none" or "gh_cli"
	Bytes          []byte // the bytes received; memory only, CollectBundle only
	ReceivedBytes  int64
	SHA256         string // of the bytes received
}

// reveals reports whether b holds a 12-character piece of the credential
// used for this collection, in any letter case. It is false when no
// credential was used.
func (e *evidence) reveals(b []byte) bool {
	return e.credCheck != nil && e.credCheck(b)
}

// input is the evidence in the form the bundle producer takes. The log bytes
// are shared, not copied.
func (e *evidence) input() logbundle.Input {
	return logbundle.Input{
		RepoID: e.RepoID, FullName: e.FullName, Public: e.Public,
		WorkflowID: e.WorkflowID, WorkflowPath: e.WorkflowPath,
		RunID: e.RunID, RunAttempt: e.RunAttempt, AttemptStartedAt: e.AttemptStartedAt,
		Event: e.Event, Branch: e.Branch, HeadSHA: e.HeadSHA,
		JobID: e.JobID, JobName: e.JobName, JobConclusion: e.JobConclusion,
		JobStartedAt: e.JobStartedAt, JobCompletedAt: e.JobCompletedAt,
		JobLabels: append([]string(nil), e.JobLabels...),
		Log: logbundle.Log{
			Obtained: e.Log.Obtained, Extent: e.Log.Extent, MissingReason: e.Log.MissingReason,
			Authentication: e.Log.Authentication, Bytes: e.Log.Bytes,
			ReceivedBytes: e.Log.ReceivedBytes, SHA256: e.Log.SHA256,
		},
	}
}

func evidenceOf(at *runDoc, job *jobDoc) *evidence {
	return &evidence{
		RepoID:           at.Repository.ID,
		FullName:         at.Repository.FullName,
		Public:           at.Repository.Private != nil && !*at.Repository.Private,
		WorkflowID:       at.WorkflowID,
		WorkflowPath:     at.Path,
		RunID:            at.ID,
		RunAttempt:       at.RunAttempt,
		AttemptStartedAt: at.RunStartedAt,
		Event:            at.Event,
		Branch:           str(at.HeadBranch),
		HeadSHA:          at.HeadSHA,
		JobID:            job.ID,
		JobName:          job.Name,
		JobConclusion:    str(job.Conclusion),
		JobStartedAt:     str(job.StartedAt),
		JobCompletedAt:   str(job.CompletedAt),
		JobLabels:        append([]string(nil), job.Labels...),
	}
}

// logEvidence maps the job-log outcome to bundle terms.
func logEvidence(lg *LogInfo, s *Stop, authenticated bool) logResult {
	le := logResult{Authentication: "none", ReceivedBytes: lg.BytesRead, SHA256: lg.SHA256}
	if authenticated {
		le.Authentication = "gh_cli"
	}
	switch lg.State {
	case "complete":
		le.Obtained, le.Extent = true, "complete"
		return le
	case "prefix":
		le.Obtained, le.Extent = true, "prefix"
		return le
	case "interrupted", "end_unverified":
		le.Obtained, le.Extent = true, "partial"
		return le
	}
	le.ReceivedBytes, le.SHA256 = 0, ""
	le.MissingReason = "transfer_failed"
	if s != nil {
		switch s.Code {
		case "access_denied", "authentication_required", "credential_rejected":
			le.MissingReason = "access_denied"
		case "not_found":
			le.MissingReason = "not_found"
		case "gone":
			le.MissingReason = "expired"
		case "rate_limited", "request_limit", "byte_limit", "log_limit":
			le.MissingReason = "limit_reached"
		case "redirect_rejected":
			le.MissingReason = "redirect_rejected"
		}
	}
	return le
}
