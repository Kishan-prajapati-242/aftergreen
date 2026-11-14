package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"aftergreen/collector/logbundle"
	"aftergreen/contracts/bundle"
)

// AuditResult is the outcome of CollectAudit. It holds counts, hashes and
// line numbers only: no log text, signed URL or credential.
type AuditResult struct {
	Collection AuditCollection  `json:"collection"`
	Current    *logbundle.Audit `json:"current_selection"`
	Saved      *SavedAudit      `json:"saved_bundle,omitempty"`
}

// AuditCollection is what the collection did, without any name or path from
// the run.
type AuditCollection struct {
	Outcome  string         `json:"outcome"`
	Stop     *AuditStop     `json:"stop,omitempty"`
	Requests []AuditRequest `json:"requests"`
	Log      *AuditLog      `json:"log,omitempty"`
}

// AuditStop is where and why the collection stopped.
type AuditStop struct {
	Stage string `json:"stage"`
	Code  string `json:"code"`
}

// AuditRequest is one request: its stage, host, status and whether it
// carried the credential.
type AuditRequest struct {
	Stage         string `json:"stage"`
	Host          string `json:"host"`
	Status        int    `json:"status,omitempty"`
	Authenticated bool   `json:"authenticated"`
	BodyBytes     int64  `json:"body_bytes"`
}

// AuditLog describes the bytes held in memory.
type AuditLog struct {
	Obtained      bool   `json:"obtained"`
	Extent        string `json:"extent,omitempty"`
	MissingReason string `json:"missing_reason,omitempty"`
	Bytes         int64  `json:"bytes"`
	Lines         int64  `json:"lines"`
	SHA256        string `json:"sha256,omitempty"`
}

// SavedAudit compares a saved bundle's selection with the log just
// collected. Compared is false, with a Reason, unless the log bytes are the
// bytes the saved bundle was built from. The reasons:
//   - collection_stopped: no failed job was selected, or the report was
//     withheld, so there is nothing to audit;
//   - log_not_obtained: a job was selected but no log bytes were obtained:
//     the request failed, or the credential could not be had, so the log
//     was not requested;
//   - log_differs: the log bytes are not the saved bundle's (byte count, hash or line count);
//   - saved_log_missing: the saved bundle has no job log;
//   - saved_bundle_invalid: the saved bundle could not be read.
type SavedAudit struct {
	Compared       bool             `json:"compared"`
	Reason         string           `json:"reason,omitempty"`
	EvidenceSHA256 string           `json:"evidence_sha256,omitempty"`
	SameSelection  *bool            `json:"same_selection_as_current,omitempty"`
	Selection      *logbundle.Audit `json:"selection,omitempty"`
}

// ErrSavedMismatch means a saved bundle is not a bundle of the job a run
// reference names.
var ErrSavedMismatch = errors.New("the saved bundle is not a bundle of the given repository, run attempt and job; with a saved bundle, the run URL must name its attempt and -job its job")

// CheckSaved checks, without any request, that saved is an accepted bundle
// v1 of the job ref names: the same repository (owner and name compared
// without regard to case, as GitHub does), run, attempt and job. ref must
// name the attempt and the job, so that a collection cannot reach another
// attempt or job than the saved one.
func CheckSaved(ref RunRef, saved []byte) error {
	if v := bundle.ValidateV1(saved); !v.Accepted() {
		return fmt.Errorf("the saved bundle is not an accepted bundle v1 (%s)", v.Code)
	}
	var d struct {
		Runs []struct {
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
			RunID      int64 `json:"run_id"`
			RunAttempt int64 `json:"run_attempt"`
			Job        struct {
				ID int64 `json:"id"`
			} `json:"job"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(saved, &d); err != nil || len(d.Runs) != 1 {
		return ErrSavedMismatch
	}
	r := d.Runs[0]
	if ref.Attempt == 0 || ref.JobID == 0 || !strings.EqualFold(r.Repository.FullName, ref.Owner+"/"+ref.Repo) ||
		r.RunID != ref.RunID || r.RunAttempt != ref.Attempt || r.Job.ID != ref.JobID {
		return ErrSavedMismatch
	}
	return nil
}

// CollectAudit makes the requests of CollectBundle and audits, in memory,
// which lines matching the inspector's known patterns the current producer
// would include (logbundle.Audit). With a saved bundle, which CheckSaved
// must accept before any request is made, it also audits that bundle's
// selection, but only if the log bytes received are the bytes the saved
// bundle was built from. Nothing is written, and the result holds no
// reference to the log bytes, which stay in memory only until they are
// garbage collected.
func CollectAudit(ctx context.Context, ref RunRef, lim Limits, auth string, saved []byte) (*AuditResult, error) {
	var src credentialSource
	switch auth {
	case "none":
	case "gh":
		src = newGHSource()
	default:
		return nil, errors.New(`auth must be "none" or "gh"`)
	}
	return collectAudit(ctx, ref, lim, newTransport(), src, saved)
}

func collectAudit(ctx context.Context, ref RunRef, lim Limits, rt http.RoundTripper, src credentialSource, saved []byte) (*AuditResult, error) {
	if saved != nil {
		if err := CheckSaved(ref, saved); err != nil {
			return nil, err // before any request
		}
	}
	rep, ev := probeWith(ctx, ref, lim, rt, src, true)
	if ev == nil {
		res := &AuditResult{Collection: auditCollection(rep)}
		if saved != nil {
			res.Saved = &SavedAudit{Reason: "collection_stopped"}
		}
		return res, fmt.Errorf("%w: no failed job of a public push run was selected, or the report was withheld", logbundle.ErrIncomplete)
	}
	res, err := auditOf(rep, ev, saved)
	ev.Log.Bytes = nil // the result holds no reference to the log bytes
	// As for a bundle, a result that holds a piece of the credential is
	// withheld. It holds counts, fixed names, hosts, hashes and line numbers
	// only, so this is a second line of defense.
	if out, mErr := json.Marshal(res); mErr != nil || ev.reveals(out) {
		return &AuditResult{Collection: AuditCollection{Outcome: rep.Outcome, Requests: []AuditRequest{}}}, ErrCredentialInAudit
	}
	return res, err
}

// ErrCredentialInAudit means an audit result would hold part of the
// credential, so it was withheld.
var ErrCredentialInAudit = errors.New("the audit would hold part of the credential, so it was withheld")

// auditOf audits the collected log: the current selection and, if saved is
// given, the saved bundle's.
func auditOf(rep *Report, ev *evidence, saved []byte) (*AuditResult, error) {
	res := &AuditResult{Collection: auditCollection(rep)}
	if saved != nil {
		res.Saved = &SavedAudit{}
	}
	res.Collection.Log = &AuditLog{Obtained: ev.Log.Obtained, Extent: ev.Log.Extent, MissingReason: ev.Log.MissingReason,
		Bytes: ev.Log.ReceivedBytes, SHA256: ev.Log.SHA256}
	if rep.Log != nil {
		res.Collection.Log.Lines = rep.Log.Lines
	}
	if !ev.Log.Obtained {
		if res.Saved != nil {
			res.Saved.Reason = "log_not_obtained"
		}
		return res, fmt.Errorf("the job log was not obtained (%s)", ev.Log.MissingReason)
	}
	raw, sum, err := logbundle.Build(ev.input(), logbundle.Options{EvidenceClass: "collected_public", Tool: "aftergreen-audit",
		APIVersion: APIVersion, CreatedAt: time.Now(), Audit: true})
	if err != nil {
		return res, err
	}
	res.Current = sum.Audit
	if saved == nil {
		return res, nil
	}
	a, err := logbundle.AuditBundle(ev.Log.Bytes, saved)
	switch {
	case errors.Is(err, logbundle.ErrLogMismatch):
		res.Saved.Reason = "log_differs"
	case errors.Is(err, logbundle.ErrSavedLogMissing):
		res.Saved.Reason = "saved_log_missing"
	case err != nil:
		res.Saved.Reason = "saved_bundle_invalid"
	default:
		same, err := logbundle.SameSelection(raw, saved)
		if err != nil {
			res.Saved.Reason = "saved_bundle_invalid"
			break
		}
		res.Saved = &SavedAudit{Compared: true, EvidenceSHA256: bundle.ValidateV1(saved).EvidenceSHA256, SameSelection: &same, Selection: a}
	}
	return res, nil
}

func auditCollection(rep *Report) AuditCollection {
	c := AuditCollection{Outcome: rep.Outcome, Requests: []AuditRequest{}}
	if rep.Stop != nil {
		c.Stop = &AuditStop{Stage: rep.Stop.Stage, Code: rep.Stop.Code}
	}
	for _, r := range rep.Requests {
		c.Requests = append(c.Requests, AuditRequest{Stage: r.Stage, Host: r.Host, Status: r.Status, Authenticated: r.Authenticated, BodyBytes: r.BodyBytes})
	}
	return c
}
