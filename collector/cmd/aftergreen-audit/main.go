// Command aftergreen-audit makes one bounded, read-only collection of a
// failed job's log, as aftergreen-collect does, and prints a selection audit
// as JSON. For each fixed pattern of contracts/inspection-v0.md section 3, it
// says how many lines of the whole log held in memory match, and how many
// of them the producer's selection includes; omitted ones are counted by
// reason, with at most 20 line numbers per list. It writes no file and prints
// no log text, signed URL or credential.
//
//	aftergreen-audit [-auth none|gh] [-job JOB_ID] [-saved BUNDLE.json] RUN_URL
//
// With -saved it also audits that bundle's selection, but only when the
// collected log bytes are the bytes the bundle was built from (byte count,
// SHA-256 and line count). The saved bundle must be a bundle of the job
// collected: the run URL must name its attempt (/attempts/N) and -job its
// job. That is checked before any request.
//
// The counts measure coverage of these known patterns only: not diagnosis
// accuracy, and not recall of all relevant evidence.
//
// Exit status: 0 for an audit (and, with -saved, a comparison); 3 when a
// saved bundle was given but not compared; 1 when no audit was produced;
// 2 for invalid arguments (nothing was requested).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"aftergreen/collector/github"
	"aftergreen/collector/logbundle"
	"aftergreen/contracts/bundle"
)

type auditFunc func(ctx context.Context, ref github.RunRef, lim github.Limits, auth string, saved []byte) (*github.AuditResult, error)

type output struct {
	Audit string `json:"audit"`
	Scope string `json:"scope"`
	*github.AuditResult
	Error string `json:"error,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, github.CollectAudit)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, audit auditFunc) int {
	log.SetOutput(io.Discard) // nothing may reach stderr through package log (Go's HTTP/2 code)
	fl := flag.NewFlagSet("aftergreen-audit", flag.ContinueOnError)
	fl.SetOutput(stderr)
	auth := fl.String("auth", "none", `"none" (unauthenticated) or "gh" (the GitHub CLI's github.com login, for the job-log request only)`)
	job := fl.String("job", "", "ID of the failed job to select (needed when several jobs failed)")
	savedPath := fl.String("saved", "", "a saved bundle of the same job, to audit against the collected log")
	fl.Usage = func() {
		fmt.Fprintln(stderr, "usage: aftergreen-audit [-auth none|gh] [-job JOB_ID] [-saved BUNDLE.json] https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return 2
	}
	if *auth != "none" && *auth != "gh" {
		fmt.Fprintln(stderr, `aftergreen-audit: -auth must be "none" or "gh"`)
		return 2
	}
	ref, err := github.ParseRunURL(fl.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "aftergreen-audit: invalid run URL:", err)
		return 2
	}
	if *job != "" {
		if ref.JobID, err = github.ParseID(*job); err != nil {
			fmt.Fprintln(stderr, "aftergreen-audit: invalid -job:", err)
			return 2
		}
	}
	var saved []byte
	if *savedPath != "" {
		// Checked before any request: a saved bundle that cannot be compared
		// is no reason to collect.
		if saved, err = readBounded(*savedPath, bundle.MaxInputBytes+1); err != nil {
			fmt.Fprintln(stderr, "aftergreen-audit: cannot read the saved bundle")
			return 2
		}
		if v := bundle.ValidateV1(saved); !v.Accepted() {
			fmt.Fprintln(stderr, "aftergreen-audit: the saved bundle is not an accepted bundle v1:", v.Code)
			return 2
		}
		if err := github.CheckSaved(ref, saved); err != nil {
			fmt.Fprintln(stderr, "aftergreen-audit:", err)
			return 2
		}
	}

	res, err := audit(ctx, ref, github.DefaultLimits(), *auth, saved)
	o := output{Audit: logbundle.AuditSchema, Scope: logbundle.AuditScope, AuditResult: res}
	code := 0
	switch {
	case err != nil:
		o.Error, code = err.Error(), 1
	case res == nil || res.Current == nil:
		o.Error, code = "no audit was produced", 1
	case saved != nil && (res.Saved == nil || !res.Saved.Compared):
		code = 3
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(o); err != nil {
		fmt.Fprintln(stderr, "aftergreen-audit:", err)
		return 1
	}
	return code
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
