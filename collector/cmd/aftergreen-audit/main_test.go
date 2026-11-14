package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aftergreen/collector/github"
	"aftergreen/collector/logbundle"
)

const runURL = "https://github.com/probe-test/fixture/actions/runs/1001"

// savedURL and savedJob name the saved bundle's attempt and job.
const savedURL, savedJob = runURL + "/attempts/1", "2002"

type fake struct {
	calls int
	auth  string
	saved []byte
	res   *github.AuditResult
	err   error
}

func (f *fake) audit(_ context.Context, _ github.RunRef, _ github.Limits, auth string, saved []byte) (*github.AuditResult, error) {
	f.calls, f.auth, f.saved = f.calls+1, auth, saved
	return f.res, f.err
}

func runCmd(f *fake, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, f.audit)
	return code, out.String(), errb.String()
}

func someAudit() *logbundle.Audit {
	return &logbundle.Audit{Schema: logbundle.AuditSchema, Scope: logbundle.AuditScope, LineCount: 3}
}

func TestArgumentsAreCheckedBeforeAnyRequest(t *testing.T) {
	saved := "../../../contracts/cases-v1/valid-producer-fixture.json"
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte("{}"), 0o600)
	for name, args := range map[string][]string{
		"no URL":                  {},
		"bad auth":                {"-auth", "token", runURL},
		"bad URL":                 {"https://github.com/o/r/actions/runs/1?x=1"},
		"bad job":                 {"-job", "0", runURL},
		"missing saved":           {"-saved", "/nonexistent/bundle.json", runURL},
		"invalid saved":           {"-saved", bad, runURL},
		"saved, no job":           {"-saved", saved, savedURL},
		"saved, no attempt":       {"-saved", saved, "-job", savedJob, runURL},
		"saved, other job":        {"-saved", saved, "-job", "2001", savedURL},
		"saved, other attempt":    {"-saved", saved, "-job", savedJob, runURL + "/attempts/2"},
		"saved, other repository": {"-saved", saved, "-job", savedJob, "https://github.com/probe-test/other/actions/runs/1001/attempts/1"},
	} {
		f := &fake{}
		if code, out, _ := runCmd(f, args...); code != 2 || f.calls != 0 || out != "" {
			t.Errorf("%s: exit %d, %d calls, stdout %q", name, code, f.calls, out)
		}
	}
}

func TestOutputAndExitCodes(t *testing.T) {
	saved := "../../../contracts/cases-v1/valid-producer-fixture.json"
	yes := true
	for name, c := range map[string]struct {
		f    *fake
		args []string
		code int
	}{
		"audit":            {&fake{res: &github.AuditResult{Current: someAudit()}}, []string{"-auth", "gh", runURL}, 0},
		"compared":         {&fake{res: &github.AuditResult{Current: someAudit(), Saved: &github.SavedAudit{Compared: true, SameSelection: &yes, Selection: someAudit()}}}, []string{"-saved", saved, "-job", savedJob, savedURL}, 0},
		"not compared":     {&fake{res: &github.AuditResult{Current: someAudit(), Saved: &github.SavedAudit{Reason: "log_differs"}}}, []string{"-saved", saved, "-job", savedJob, savedURL}, 3},
		"collection fails": {&fake{res: &github.AuditResult{}, err: errors.New("incomplete: no failed job was selected")}, []string{runURL}, 1},
	} {
		code, out, _ := runCmd(c.f, c.args...)
		if code != c.code || !strings.Contains(out, `"audit": "aftergreen.selection-audit.v0"`) || !strings.Contains(out, "known patterns only") {
			t.Errorf("%s: exit %d, output %s", name, code, out)
		}
		if strings.Contains(strings.Join(c.args, " "), "-saved") && len(c.f.saved) == 0 {
			t.Errorf("%s: the saved bundle was not passed", name)
		}
	}
}
