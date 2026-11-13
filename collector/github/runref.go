// Package github is a bounded, read-only client for one public GitHub
// Actions run. It resolves one run attempt, lists that attempt's jobs,
// selects one failed job, and downloads that job's log within fixed limits.
//
// Probe and ProbeWithGH count and hash the log, then discard it.
// CollectBundle keeps it in memory and builds an evidence bundle v1 from it
// with package logbundle; it writes nothing to disk.
//
// Run, attempt and job metadata are always requested without a credential.
// In gh mode (ProbeWithGH, CollectBundle with auth "gh") the GitHub CLI's
// stored github.com token is obtained only after the repository is shown to
// be public, the identities match and one failed job is selected, and it is
// sent only on the job-log request to api.github.com, never on the log
// download. Nothing fetches a URL supplied by the user or follows a redirect
// outside the host policy. Every entry point stops at the first response
// that does not state that the repository is public, and reports none of
// that response's content. Standard library only, besides this module's packages.
package github

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// RunRef names one GitHub Actions run and, optionally, one attempt and one
// job. Attempt and JobID are zero when not given.
type RunRef struct {
	Owner   string `json:"owner"`
	Repo    string `json:"repo"`
	RunID   int64  `json:"run_id"`
	Attempt int64  `json:"attempt,omitempty"`
	JobID   int64  `json:"job_id,omitempty"`
}

// maxID is 2^53 - 1, the largest integer bundle v0 accepts.
const maxID = 1<<53 - 1

const runURLPrefix = "https://github.com/"

var (
	// The owner and repository patterns of bundle v0's repository.full_name.
	ownerRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	repoRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	idRE    = regexp.MustCompile(`^[1-9][0-9]{0,15}$`)
)

// ParseRunURL accepts exactly
//
//	https://github.com/OWNER/REPO/actions/runs/RUN_ID
//	https://github.com/OWNER/REPO/actions/runs/RUN_ID/attempts/ATTEMPT
//
// in printable ASCII, with a lowercase scheme and host and no user
// information, port, query, fragment, percent-encoding or trailing slash.
// The URL is only parsed, never fetched: API routes are built from its parts.
func ParseRunURL(raw string) (RunRef, error) {
	if len(raw) > 300 {
		return RunRef{}, errors.New("URL is longer than 300 bytes")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] > '~' {
			return RunRef{}, errors.New("URL must be printable ASCII with no spaces")
		}
	}
	if strings.ContainsAny(raw, `?#%\`) {
		return RunRef{}, errors.New("URL must not contain a query, fragment, percent-encoding or backslash")
	}
	if !strings.HasPrefix(raw, runURLPrefix) {
		return RunRef{}, errors.New("URL must start with https://github.com/ (HTTPS, host github.com, no user information or port)")
	}
	seg := strings.Split(raw[len(runURLPrefix):], "/")
	if (len(seg) != 5 && len(seg) != 7) || seg[2] != "actions" || seg[3] != "runs" || (len(seg) == 7 && seg[5] != "attempts") {
		return RunRef{}, errors.New("path must be /OWNER/REPO/actions/runs/RUN_ID, optionally followed by /attempts/ATTEMPT")
	}
	ref := RunRef{Owner: seg[0], Repo: seg[1]}
	var err error
	if ref.RunID, err = ParseID(seg[4]); err != nil {
		return RunRef{}, fmt.Errorf("run ID %w", err)
	}
	if len(seg) == 7 {
		if ref.Attempt, err = ParseID(seg[6]); err != nil {
			return RunRef{}, fmt.Errorf("attempt %w", err)
		}
	}
	if err := ref.Validate(); err != nil {
		return RunRef{}, err
	}
	return ref, nil
}

// Validate checks r as ParseRunURL would. Owner and Repo must match bundle
// v0's repository.full_name patterns, and Repo must not be "." or "..".
// RunID must be from 1 to 2^53 - 1. Attempt and JobID must be 0 (not given)
// or in that range. The error names the field, never its value. Probe and
// ProbeWithGH call it before anything is requested or reported, so a caller
// that builds a RunRef itself cannot reach an API route or the report with an
// unchecked value.
func (r RunRef) Validate() error {
	switch {
	case !ownerRE.MatchString(r.Owner):
		return errors.New("owner is not a valid GitHub account name")
	case !repoRE.MatchString(r.Repo) || r.Repo == "." || r.Repo == "..":
		return errors.New("repository name is not valid")
	case r.RunID < 1 || r.RunID > maxID:
		return errors.New("run ID must be from 1 to 2^53-1")
	case r.Attempt < 0 || r.Attempt > maxID:
		return errors.New("attempt must be 0 (not given) or from 1 to 2^53-1")
	case r.JobID < 0 || r.JobID > maxID:
		return errors.New("job ID must be 0 (not given) or from 1 to 2^53-1")
	}
	return nil
}

// ParseID accepts a decimal integer from 1 to 2^53 - 1, with no sign and no
// leading zero.
func ParseID(s string) (int64, error) {
	if !idRE.MatchString(s) {
		return 0, errors.New("must be a decimal integer from 1 to 2^53-1, with no sign or leading zero")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxID {
		return 0, errors.New("must be at most 2^53-1")
	}
	return n, nil
}
