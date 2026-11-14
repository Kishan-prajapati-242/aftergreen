package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"testing"

	"aftergreen/collector/logbundle"
	"aftergreen/contracts/bundle"
)

// tSavedRef names the golden bundle's job: with a saved bundle, the run
// reference must name the attempt and the job.
var tSavedRef = RunRef{Owner: tOwner, Repo: tRepo, RunID: tRun, Attempt: 1, JobID: 2002}

func auditPattern(t *testing.T, a *logbundle.Audit, name string) logbundle.PatternAudit {
	t.Helper()
	for _, p := range a.Patterns {
		if p.Pattern == name {
			return p
		}
	}
	t.Fatalf("no pattern %s", name)
	return logbundle.PatternAudit{}
}

// The whole audit path offline. The golden bundle was built from the same
// fixture log, so it is compared, and its selection is the current one.
func TestCollectAuditOffline(t *testing.T) {
	m := newMockH2(t)
	oneFailedJob(m)
	m.logRedirect(2002, textReply(fixtureLog()))
	saved, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	src := tokenSource()
	res, err := collectAudit(context.Background(), tSavedRef, DefaultLimits(), m.transport(), src, saved)
	if err != nil || src.calls != 1 {
		t.Fatalf("err %v, source calls %d", err, src.calls)
	}
	if err := credentialPlacement(m.snapshot(), tToken); err != nil {
		t.Fatal(err)
	}
	if len(res.Collection.Requests) != 6 || res.Collection.Log == nil || !res.Collection.Log.Obtained || res.Collection.Log.Lines != 82 {
		t.Fatalf("collection %+v", res.Collection)
	}
	if res.Saved == nil || !res.Saved.Compared || res.Saved.SameSelection == nil || !*res.Saved.SameSelection ||
		res.Saved.Selection.Scope != logbundle.SavedAuditScope || res.Current.Scope != logbundle.AuditScope ||
		!reflect.DeepEqual(res.Saved.Selection.Patterns, res.Current.Patterns) {
		t.Fatalf("saved %+v", res.Saved)
	}
	for name, want := range map[string][3]int{"gha_error": {1, 1, 0}, "error_line": {1, 1, 0}, "failed_count": {1, 1, 0},
		"nonzero_exit": {1, 1, 0}, "step_header": {2, 1, 1}} {
		p := auditPattern(t, res.Current, name)
		if p.Lines != want[0] || p.Included != want[1] || p.Omitted["outside_selected_span"] != want[2] {
			t.Errorf("%s: %+v", name, p)
		}
	}
	out, _ := json.Marshal(res)
	for _, s := range append(fixtureSentinels, tLogHost+"/", "Run npm test", "fixture.spec", "Expected", "ok 1") {
		if bytes.Contains(out, []byte(s)) {
			t.Errorf("the audit holds %q", s)
		}
	}
	if containsPiece(out, tToken) {
		t.Error("the audit holds a piece of the credential")
	}
}

// A saved bundle built from other bytes is not compared.
func TestCollectAuditSavedLogDiffers(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	m.logRedirect(2002, textReply("Error: a different log\n"))
	saved, _ := os.ReadFile(goldenPath)
	res, err := collectAudit(context.Background(), tSavedRef, DefaultLimits(), m.transport(), nil, saved)
	if err != nil || res.Current == nil || res.Saved == nil || res.Saved.Compared || res.Saved.Reason != "log_differs" || res.Saved.Selection != nil {
		t.Fatalf("err %v, saved %+v", err, res.Saved)
	}
}

// A saved bundle is checked before any request: it must be an accepted
// bundle v1 of the repository, run, attempt and job the reference names.
func TestCollectAuditChecksSavedFirst(t *testing.T) {
	saved, _ := os.ReadFile(goldenPath)
	for name, c := range map[string]struct {
		ref   RunRef
		saved []byte
	}{
		"not a bundle":  {tSavedRef, []byte("{}")},
		"no attempt":    {RunRef{Owner: tOwner, Repo: tRepo, RunID: tRun, JobID: 2002}, saved},
		"no job":        {RunRef{Owner: tOwner, Repo: tRepo, RunID: tRun, Attempt: 1}, saved},
		"other job":     {RunRef{Owner: tOwner, Repo: tRepo, RunID: tRun, Attempt: 1, JobID: 2001}, saved},
		"other attempt": {RunRef{Owner: tOwner, Repo: tRepo, RunID: tRun, Attempt: 2, JobID: 2002}, saved},
		"other run":     {RunRef{Owner: tOwner, Repo: tRepo, RunID: tRun + 1, Attempt: 1, JobID: 2002}, saved},
		"other repo":    {RunRef{Owner: tOwner, Repo: "other", RunID: tRun, Attempt: 1, JobID: 2002}, saved},
	} {
		ct := &countingTransport{t: t, fail: true}
		src := tokenSource()
		res, err := collectAudit(context.Background(), c.ref, DefaultLimits(), ct, src, c.saved)
		if err == nil || res != nil || ct.calls.Load() != 0 || src.calls != 0 {
			t.Errorf("%s: err %v, result %v, %d requests", name, err, res != nil, ct.calls.Load())
		}
		if name != "not a bundle" && !errors.Is(err, ErrSavedMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := CheckSaved(RunRef{Owner: "PROBE-TEST", Repo: "Fixture", RunID: tRun, Attempt: 1, JobID: 2002}, saved); err != nil {
		t.Errorf("owner and repository are compared without regard to case: %v", err)
	}
}

func newMockWithLog(t *testing.T, log string) *mockGH {
	m := newMock(t)
	oneFailedJob(m)
	m.logRedirect(2002, textReply(log))
	return m
}

func TestCollectAuditLogMissing(t *testing.T) {
	m := newMock(t)
	oneFailedJob(m)
	m.handle(api+logURI(2002), jsonReply(55, http.StatusForbidden, map[string]any{"message": "denied"}))
	saved, _ := os.ReadFile(goldenPath)
	res, err := collectAudit(context.Background(), tSavedRef, DefaultLimits(), m.transport(), nil, saved)
	if err == nil || res.Current != nil || res.Saved == nil || res.Saved.Compared || res.Saved.Reason != "log_not_obtained" ||
		res.Collection.Log == nil || res.Collection.Log.Obtained || res.Collection.Log.MissingReason != "access_denied" {
		t.Fatalf("err %v, result %+v", err, res)
	}
}

// Every state in which a saved bundle is not compared has its reason.
func TestCollectAuditNotComparedReasons(t *testing.T) {
	golden, _ := os.ReadFile(goldenPath)

	m := newMock(t) // the named job did not fail: the collection stops
	m.standard(1, map[int64][]map[string]any{1: {jobBody(2002, 1, "test", "success")}})
	res, err := collectAudit(context.Background(), tSavedRef, DefaultLimits(), m.transport(), nil, golden)
	if err == nil || res.Saved == nil || res.Saved.Reason != "collection_stopped" || res.Current != nil {
		t.Errorf("stopped: err %v, result %+v", err, res)
	}

	// A saved bundle of the same job whose job log is missing.
	var d struct {
		Sources []json.RawMessage `json:"sources"`
	}
	if err := json.Unmarshal(golden, &d); err != nil {
		t.Fatal(err)
	}
	var job json.RawMessage
	for _, s := range d.Sources {
		if bytes.Contains(s, []byte(`"kind":"job_log"`)) {
			job = s
		}
	}
	missing := bytes.Replace(golden, job, []byte(`{"id":"failed.job_log","kind":"job_log","run_role":"failed","status":"missing","missing_reason":"access_denied"}`), 1)
	digest, v := bundle.DigestV1(missing)
	if digest == "" {
		t.Fatalf("the edited bundle is rejected: %s at %s", v.Code, v.Pointer)
	}
	k := bytes.Index(missing, []byte(`"evidence_sha256":"`)) + len(`"evidence_sha256":"`)
	missing = append(append(append([]byte{}, missing[:k]...), digest...), missing[k+64:]...)
	res, err = collectAudit(context.Background(), tSavedRef, DefaultLimits(), newMockWithLog(t, fixtureLog()).transport(), nil, missing)
	if err != nil || res.Current == nil || res.Saved == nil || res.Saved.Compared || res.Saved.Reason != "saved_log_missing" {
		t.Errorf("saved log missing: err %v, saved %+v", err, res.Saved)
	}
}

// An audit that would hold a piece of the credential is withheld, as a
// bundle would be. Only the audit's own field names can hold this token.
func TestCollectAuditWithheldIfItRevealsTheCredential(t *testing.T) {
	m := newMockWithLog(t, fixtureLog())
	src := &countingSource{cred: newCredential("gho_" + "hidden_by_inline_redaction")}
	res, err := collectAudit(context.Background(), tRef, DefaultLimits(), m.transport(), src, nil)
	if !errors.Is(err, ErrCredentialInAudit) || res == nil || res.Current != nil || res.Collection.Log != nil || src.calls != 1 {
		t.Fatalf("err %v, result %+v, %d credential calls", err, res, src.calls)
	}
}

func TestCollectAuditEntryPoint(t *testing.T) {
	ct := &countingTransport{t: t, fail: true}
	src := tokenSource()
	useEntryPoints(t, ct, src)
	if res, err := CollectAudit(context.Background(), tRef, DefaultLimits(), "token", nil); err == nil || res != nil {
		t.Error("auth \"token\" accepted")
	}
	for _, ref := range invalidRefs() {
		res, err := CollectAudit(context.Background(), ref, DefaultLimits(), "gh", nil)
		if !errors.Is(err, logbundle.ErrIncomplete) || res.Current != nil {
			t.Errorf("invalid ref %+v: err %v", ref, err)
		}
	}
	if ct.calls.Load() != 0 || src.calls != 0 {
		t.Errorf("%d requests and %d credential calls for invalid input", ct.calls.Load(), src.calls)
	}
}
