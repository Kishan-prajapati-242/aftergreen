// Command aftergreen-probe makes one bounded, read-only probe of a public
// GitHub Actions run and prints a metadata report as JSON on stdout. It never
// prints or stores log text, signed URLs or credentials, and it writes no
// evidence bundle.
//
//	aftergreen-probe [-auth none|gh] [-job JOB_ID] https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]
//
// By default the probe is unauthenticated. With -auth gh it uses the
// github.com login stored by the GitHub CLI for the job-log request only.
// Run, attempt and job metadata are still read without a credential; only
// after the repository is shown to be public, the identities match and one
// failed job is selected does it run `gh auth token --hostname github.com` as
// a child process with captured output, with GH_TOKEN, GITHUB_TOKEN,
// GH_ENTERPRISE_TOKEN and GITHUB_ENTERPRISE_TOKEN removed from gh's
// environment. The token is sent only on the job-log request to
// api.github.com, never on the log download. If gh is missing or not logged
// in, it stops with credential_unavailable before the job-log request. It
// never installs gh or starts a login. Either mode refuses to run when GODEBUG turns on Go's
// HTTP/2 debug logging, and package log's output is discarded.
//
// Exit status: 0 when the selected job's log was read completely within the
// limits, 1 when the probe stopped or the log is incomplete, 2 for invalid
// arguments (nothing was requested).
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
)

// probeFunc runs the probe. auth is "none" or "gh".
type probeFunc func(ctx context.Context, ref github.RunRef, lim github.Limits, auth string) *github.Report

func defaultProbe(ctx context.Context, ref github.RunRef, lim github.Limits, auth string) *github.Report {
	if auth == "gh" {
		return github.ProbeWithGH(ctx, ref, lim)
	}
	return github.Probe(ctx, ref, lim)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, defaultProbe)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, probe probeFunc) int {
	// Go's HTTP/2 code can log request headers and URLs through package log;
	// this command never uses package log, so nothing may reach stderr that way.
	log.SetOutput(io.Discard)
	fs := flag.NewFlagSet("aftergreen-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	auth := fs.String("auth", "none", `"none" (unauthenticated) or "gh" (the github.com login stored by the GitHub CLI)`)
	job := fs.String("job", "", "ID of the failed job to select (needed when several jobs failed)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: aftergreen-probe [-auth none|gh] [-job JOB_ID] https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	if *auth != "none" && *auth != "gh" {
		fmt.Fprintln(stderr, `aftergreen-probe: -auth must be "none" or "gh"`)
		return 2
	}
	ref, err := github.ParseRunURL(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "aftergreen-probe: invalid run URL:", err)
		return 2
	}
	if *job != "" {
		if ref.JobID, err = github.ParseID(*job); err != nil {
			fmt.Fprintln(stderr, "aftergreen-probe: invalid -job:", err)
			return 2
		}
	}
	rep := probe(ctx, ref, github.DefaultLimits(), *auth)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // terminal output: the probe made every string terminal-safe, not HTML-safe
	if err := enc.Encode(rep); err != nil {
		fmt.Fprintln(stderr, "aftergreen-probe:", err)
		return 1
	}
	if rep.Outcome == "complete" {
		return 0
	}
	if rep.Stop != nil {
		fmt.Fprintf(stderr, "aftergreen-probe: %s at %s: %s\n", rep.Stop.Code, rep.Stop.Stage, rep.Stop.Detail)
		if rep.Stop.Code == "job_choice_required" && rep.Jobs != nil {
			fmt.Fprintln(stderr, "failed jobs (rerun with one of these):")
			for _, j := range rep.Jobs.Failed {
				fmt.Fprintf(stderr, "  -job %d  %s\n", j.ID, j.Name)
			}
			if n := rep.Jobs.FailedCount; n > len(rep.Jobs.Failed) {
				fmt.Fprintf(stderr, "  (showing %d of %d failed jobs)\n", len(rep.Jobs.Failed), n)
			}
		}
	}
	return 1
}
