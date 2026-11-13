package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"

	"aftergreen/collector/github"
)

// These tests use a fake probe; nothing here touches the network or runs gh.

const runURL = "https://github.com/octo-org/demo/actions/runs/1001"

func TestInvalidArgumentsRequestNothing(t *testing.T) {
	for _, args := range [][]string{
		{},
		{runURL, runURL},
		{"http://github.com/octo-org/demo/actions/runs/1001"},
		{"https://github.com/octo-org/demo/actions/runs/1001/job/7"},
		{"-job", "0", runURL},
		{"-job", "abc", runURL},
		{"-job", "-5", runURL},
		{runURL, "-job", "7"}, // flags must come before the URL
		{"-token", "x", runURL},
		{"-auth", "token", runURL},
		{"-auth", "GH", runURL},
		{"-auth", "", runURL},
		{"-auth", "gh,none", runURL},
		{"-auth", "gh", "https://github.com/octo-org/../actions/runs/1001"},
	} {
		called := false
		fake := func(context.Context, github.RunRef, github.Limits, string) *github.Report {
			called = true
			return &github.Report{Outcome: "complete"}
		}
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut, fake); code != 2 || called || out.Len() != 0 {
			t.Errorf("args %q: exit %d, probe called %v, stdout %q", args, code, called, out.String())
		}
	}
}

func TestArgumentsReachTheProbe(t *testing.T) {
	for _, c := range []struct {
		args []string
		auth string
	}{
		{[]string{"-job", "2002", runURL + "/attempts/2"}, "none"},
		{[]string{"-auth", "none", "-job", "2002", runURL + "/attempts/2"}, "none"},
		{[]string{"-auth", "gh", "-job", "2002", runURL + "/attempts/2"}, "gh"},
		{[]string{"-auth=gh", "-job=2002", runURL + "/attempts/2"}, "gh"},
	} {
		var got github.RunRef
		var lim github.Limits
		var auth string
		fake := func(_ context.Context, ref github.RunRef, l github.Limits, a string) *github.Report {
			got, lim, auth = ref, l, a
			return &github.Report{Outcome: "complete"}
		}
		var out, errOut bytes.Buffer
		code := run(context.Background(), c.args, &out, &errOut, fake)
		want := github.RunRef{Owner: "octo-org", Repo: "demo", RunID: 1001, Attempt: 2, JobID: 2002}
		if code != 0 || got != want || lim != github.DefaultLimits() || auth != c.auth {
			t.Fatalf("args %q: exit %d, ref %+v, limits %+v, auth %q; want 0, %+v, defaults, %q", c.args, code, got, lim, auth, want, c.auth)
		}
		var rep github.Report
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil || rep.Outcome != "complete" {
			t.Fatalf("stdout is not the report: %v %q", err, out.String())
		}
	}
}

func TestStoppedProbeListsChoices(t *testing.T) {
	fake := func(context.Context, github.RunRef, github.Limits, string) *github.Report {
		return &github.Report{
			Outcome: "stopped",
			Stop:    &github.Stop{Stage: "select", Code: "job_choice_required", Detail: "2 jobs failed"},
			Jobs: &github.JobsInfo{FailedCount: 3,
				Failed: []github.JobChoice{{ID: 11, Name: "lint"}, {ID: 12, Name: "test (20)"}}},
		}
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{runURL}, &out, &errOut, fake); code != 1 {
		t.Fatalf("exit %d; want 1", code)
	}
	for _, want := range []string{"job_choice_required at select", "-job 11  lint", "-job 12  test (20)", "(showing 2 of 3 failed jobs)"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr %q lacks %q", errOut.String(), want)
		}
	}
	if !strings.Contains(out.String(), `"outcome": "stopped"`) {
		t.Errorf("stdout %q", out.String())
	}
}

// defaultProbe maps each -auth value to its entry point. An invalid RunRef
// stops both before any transport use or gh run. The context is already
// cancelled and PATH holds no gh, so even a broken validation (as a mutation
// test might make) could send no request and run no gh; it would stop with
// another code and fail this test.
func TestDefaultProbeSelectsTheEntryPoint(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, auth := range []string{"none", "gh"} {
		rep := defaultProbe(ctx, github.RunRef{}, github.DefaultLimits(), auth)
		if rep.Auth != auth || rep.Stop == nil || rep.Stop.Code != "invalid_input" || len(rep.Requests) != 0 {
			t.Errorf("-auth %s: auth %q stop %+v requests %d", auth, rep.Auth, rep.Stop, len(rep.Requests))
		}
	}
}

// run discards package log's output, which Go's HTTP/2 code could use to
// print request headers.
func TestRunDiscardsPackageLog(t *testing.T) {
	old := log.Writer()
	t.Cleanup(func() { log.SetOutput(old) })
	var out, errOut bytes.Buffer
	run(context.Background(), []string{}, &out, &errOut, nil)
	if log.Writer() != io.Discard {
		t.Fatal("package log still writes somewhere")
	}
}
