// Command aftergreen-collect makes one bounded, read-only collection of one
// failed job of a public GitHub Actions push run and writes it to a new file
// as an evidence bundle v1 (contracts/bundle-v1.md). On stdout it prints a
// JSON summary: counts, digests and the collection report, never log text,
// signed URLs or credentials.
//
//	aftergreen-collect [-auth none|gh] [-job JOB_ID] -out FILE https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]
//
// Run, attempt and job metadata are always requested without a credential.
// With -auth gh, the github.com login stored by the GitHub CLI is read (by
// running `gh auth token --hostname github.com` with captured output) only
// after the run is shown to be public and one failed job is selected, and it
// is sent only on the job-log request to api.github.com. The log download
// itself is unauthenticated. The log is held in memory, numbered, cleaned,
// redacted and selected by package logbundle; the raw log and the signed
// download URL are never written or printed. Rule-based redaction cannot
// find every secret; see docs/collector.md.
//
// FILE must not exist. It is created with mode 0600 and written only after the
// bundle passed v1 validation and a check that it holds no piece of the
// credential.
//
// Exit status: 0 when the bundle was written with a complete job log, 3 when
// it was written but its job log is missing or incomplete, 1 when no bundle
// was written, 2 for invalid arguments (nothing was requested). No bundle is
// written when the collection stops, when the metadata does not fit the
// contract, or when at none of the line budgets tried does a selection of the
// log's lines list every omission reason exactly within both 501 omitted
// ranges and the bundle size limit (logbundle.ErrRangeLimit).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"aftergreen/collector/github"
	"aftergreen/collector/logbundle"
)

// collectFunc collects and builds one bundle; github.CollectBundle in production.
type collectFunc func(ctx context.Context, ref github.RunRef, lim github.Limits, auth string, created time.Time) (*github.Report, []byte, *logbundle.Summary, error)

// output is what the command prints.
type output struct {
	Outcome    string             `json:"outcome"`          // "written" or "not_written"
	Bundle     string             `json:"bundle,omitempty"` // the file written
	Reason     string             `json:"reason,omitempty"` // why nothing was written
	Summary    *logbundle.Summary `json:"summary,omitempty"`
	Collection *github.Report     `json:"collection"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, github.CollectBundle, time.Now)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, collect collectFunc, now func() time.Time) int {
	log.SetOutput(io.Discard) // nothing may reach stderr through package log (Go's HTTP/2 code)
	fl := flag.NewFlagSet("aftergreen-collect", flag.ContinueOnError)
	fl.SetOutput(stderr)
	auth := fl.String("auth", "none", `"none" (unauthenticated) or "gh" (the GitHub CLI's github.com login, for the job-log request only)`)
	job := fl.String("job", "", "ID of the failed job to select (needed when several jobs failed)")
	out := fl.String("out", "", "path of the bundle file to create; it must not exist")
	fl.Usage = func() {
		fmt.Fprintln(stderr, "usage: aftergreen-collect [-auth none|gh] [-job JOB_ID] -out FILE https://github.com/OWNER/REPO/actions/runs/RUN_ID[/attempts/N]")
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 || *out == "" {
		fl.Usage()
		return 2
	}
	if *auth != "none" && *auth != "gh" {
		fmt.Fprintln(stderr, `aftergreen-collect: -auth must be "none" or "gh"`)
		return 2
	}
	ref, err := github.ParseRunURL(fl.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "aftergreen-collect: invalid run URL:", err)
		return 2
	}
	if *job != "" {
		if ref.JobID, err = github.ParseID(*job); err != nil {
			fmt.Fprintln(stderr, "aftergreen-collect: invalid -job:", err)
			return 2
		}
	}
	// Checked before any request; the file is still created exclusively below.
	if _, err := os.Lstat(*out); !errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintln(stderr, "aftergreen-collect: -out must name a file that does not exist")
		return 2
	}
	if st, err := os.Stat(filepath.Dir(*out)); err != nil || !st.IsDir() {
		fmt.Fprintln(stderr, "aftergreen-collect: the directory for -out does not exist")
		return 2
	}

	rep, raw, sum, err := collect(ctx, ref, github.DefaultLimits(), *auth, now())
	o := output{Outcome: "not_written", Collection: rep}
	code := 1
	switch {
	case err != nil:
		o.Reason = err.Error()
	default:
		if werr := writeNew(*out, raw); werr != nil {
			o.Reason = werr.Error()
			break
		}
		o.Outcome, o.Bundle, o.Summary = "written", *out, sum
		code = 3
		if sum.JobLog.Status == "present" && sum.JobLog.Extent == "complete" {
			code = 0
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // terminal output: every string is already terminal-safe or fixed text
	if err := enc.Encode(o); err != nil {
		fmt.Fprintln(stderr, "aftergreen-collect:", err)
		return 1
	}
	if o.Outcome != "written" {
		fmt.Fprintln(stderr, "aftergreen-collect: no bundle was written:", o.Reason)
	}
	return code
}

// writeNew creates path, which must not exist, with mode 0600 and writes b.
// A partly written file is removed.
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("the output file could not be created (it may exist now)")
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(path)
		return errors.New("the output file could not be written; it was removed")
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return errors.New("the output file could not be closed; it was removed")
	}
	return nil
}
