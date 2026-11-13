package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aftergreen/collector/github"
	"aftergreen/collector/logbundle"
)

// Offline: the collection is replaced by a fake that builds a simulated
// bundle from an invented log.

const runURL = "https://github.com/probe-test/fixture/actions/runs/1001"

var created = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func fakeBundle(t *testing.T, log string, obtained bool) ([]byte, *logbundle.Summary) {
	t.Helper()
	sum := sha256.Sum256([]byte(log))
	in := logbundle.Input{
		RepoID: 42, FullName: "probe-test/fixture", Public: true, WorkflowID: 99, WorkflowPath: ".github/workflows/ci.yml",
		RunID: 1001, RunAttempt: 1, AttemptStartedAt: "2026-11-01T10:00:00Z", Event: "push", Branch: "main",
		HeadSHA: "0123456789abcdef0123456789abcdef01234567", JobID: 2002, JobName: "test", JobConclusion: "failure",
		JobStartedAt: "2026-11-01T10:01:00Z", JobCompletedAt: "2026-11-01T10:05:00Z", JobLabels: []string{"ubuntu-latest"},
		Log: logbundle.Log{Obtained: true, Extent: "complete", Authentication: "none", Bytes: []byte(log),
			ReceivedBytes: int64(len(log)), SHA256: hex.EncodeToString(sum[:])},
	}
	if !obtained {
		in.Log = logbundle.Log{MissingReason: "access_denied", Authentication: "none"}
	}
	raw, s, err := logbundle.Build(in, logbundle.Options{EvidenceClass: "simulated", Tool: "aftergreen-collect", APIVersion: "2026-03-10", CreatedAt: created})
	if err != nil {
		t.Fatal(err)
	}
	return raw, s
}

type fake struct {
	calls int
	ref   github.RunRef
	auth  string
	raw   []byte
	sum   *logbundle.Summary
	err   error
	hook  func()
}

func (f *fake) collect(_ context.Context, ref github.RunRef, _ github.Limits, auth string, c time.Time) (*github.Report, []byte, *logbundle.Summary, error) {
	f.calls, f.ref, f.auth = f.calls+1, ref, auth
	if f.hook != nil {
		f.hook()
	}
	return &github.Report{Report: github.ReportName, Outcome: "complete"}, f.raw, f.sum, f.err
}

func runCmd(t *testing.T, f *fake, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb, f.collect, func() time.Time { return created })
	return code, out.String(), errb.String()
}

func TestArgumentsAreCheckedBeforeAnyRequest(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "exists.json")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"no out":         {runURL},
		"no URL":         {"-out", filepath.Join(dir, "a.json")},
		"bad auth":       {"-auth", "token", "-out", filepath.Join(dir, "a.json"), runURL},
		"bad URL":        {"-out", filepath.Join(dir, "a.json"), "https://github.com/o/r/actions/runs/1?x=1"},
		"bad job":        {"-job", "0", "-out", filepath.Join(dir, "a.json"), runURL},
		"out exists":     {"-out", existing, runURL},
		"no such dir":    {"-out", filepath.Join(dir, "missing", "a.json"), runURL},
		"two URLs":       {"-out", filepath.Join(dir, "a.json"), runURL, runURL},
		"unknown option": {"-x", "-out", filepath.Join(dir, "a.json"), runURL},
	} {
		f := &fake{}
		if code, out, _ := runCmd(t, f, args...); code != 2 || f.calls != 0 || out != "" {
			t.Errorf("%s: exit %d, %d collections, stdout %q", name, code, f.calls, out)
		}
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep" {
		t.Error("an existing file was changed")
	}
}

func TestWritesANewPrivateFile(t *testing.T) {
	raw, sum := fakeBundle(t, "Error: LOG-TEXT-SENTINEL\n##[error]Process completed with exit code 1.\n", true)
	f := &fake{raw: raw, sum: sum}
	path := filepath.Join(t.TempDir(), "bundle.json")
	code, out, _ := runCmd(t, f, "-auth", "gh", "-job", "2002", "-out", path, runURL)
	if code != 0 || f.calls != 1 || f.auth != "gh" || f.ref.JobID != 2002 || f.ref.RunID != 1001 {
		t.Fatalf("exit %d, calls %d, auth %q, ref %+v", code, f.calls, f.auth, f.ref)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("file content differs: %v", err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm()&0o077 != 0 {
		t.Errorf("mode %v; want no group or other access", st.Mode().Perm())
	}
	var o output
	if err := json.Unmarshal([]byte(out), &o); err != nil || o.Outcome != "written" || o.Bundle != path || o.Summary.EvidenceSHA256 != sum.EvidenceSHA256 {
		t.Fatalf("output %s (%v)", out, err)
	}
	if strings.Contains(out, "LOG-TEXT-SENTINEL") || strings.Contains(out, "exit code 1") {
		t.Error("stdout holds log text")
	}
}

func TestMissingLogIsWrittenWithExit3(t *testing.T) {
	raw, sum := fakeBundle(t, "", false)
	path := filepath.Join(t.TempDir(), "bundle.json")
	if code, out, _ := runCmd(t, &fake{raw: raw, sum: sum}, "-out", path, runURL); code != 3 || !strings.Contains(out, `"status": "missing"`) {
		t.Errorf("exit %d, output %s", code, out)
	}
}

func TestNothingWrittenOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	f := &fake{err: errors.New("incomplete: the repository was not shown to be public")}
	code, out, errText := runCmd(t, f, "-out", path, runURL)
	if code != 1 || !strings.Contains(out, `"outcome": "not_written"`) || !strings.Contains(errText, "no bundle was written") {
		t.Errorf("exit %d, stdout %s, stderr %s", code, out, errText)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("a file was created")
	}
}

// A file that appears while the collection runs is never overwritten.
func TestFileCreatedMeanwhileIsKept(t *testing.T) {
	raw, sum := fakeBundle(t, "Error: x\n", true)
	path := filepath.Join(t.TempDir(), "bundle.json")
	f := &fake{raw: raw, sum: sum, hook: func() { os.WriteFile(path, []byte("other"), 0o600) }}
	if code, out, _ := runCmd(t, f, "-out", path, runURL); code != 1 || !strings.Contains(out, "could not be created") {
		t.Errorf("exit %d, output %s", code, out)
	}
	if b, _ := os.ReadFile(path); string(b) != "other" {
		t.Error("the file that appeared was overwritten")
	}
}

// When the omission reasons cannot be listed exactly, nothing is written.
func TestRangeLimitWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json")
	code, out, errText := runCmd(t, &fake{err: logbundle.ErrRangeLimit}, "-out", path, runURL)
	if code != 1 || !strings.Contains(out, `"outcome": "not_written"`) || !strings.Contains(out, "501 omitted ranges") || !strings.Contains(errText, "no bundle was written") {
		t.Errorf("exit %d, stdout %s, stderr %s", code, out, errText)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("a file was created")
	}
}
