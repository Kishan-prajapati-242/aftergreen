// Package markers holds the fixed line patterns of contracts/inspection-v0.md
// section 3. The inspector and the collector's selection audit both use it,
// so both classify a line the same way. A match is a fact about the text,
// not an explanation of anything.
package markers

import (
	"regexp"
	"strconv"
	"strings"
)

// Names lists the error-marker names in contract order.
var Names = []string{"gha_error", "npm_error", "go_test_fail", "pytest_failed", "python_traceback",
	"go_panic", "error_line", "timeout", "failed_count"}

var (
	timestampRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z `)
	errorLineRE   = regexp.MustCompile(`^[A-Za-z]*Error: `)
	timeoutRE     = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])(?:TimeoutError|Timed out|timed out)(?:[^A-Za-z0-9_]|$)`)
	failedCountRE = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])[1-9][0-9]* failed(?:[^A-Za-z0-9_]|$)`)
	exitRE        = regexp.MustCompile(`Process completed with exit code ([1-9][0-9]{0,9})(?:[^0-9]|$)`)
)

// Body is the line text without one leading GitHub Actions timestamp.
func Body(text string) string {
	if loc := timestampRE.FindStringIndex(text); loc != nil {
		return text[loc[1]:]
	}
	return text
}

// ErrorMarkers returns the names of the error markers the body matches, in
// contract order.
func ErrorMarkers(body string) []string {
	un := strings.TrimLeft(body, " \t")
	var out []string
	add := func(ok bool, name string) {
		if ok {
			out = append(out, name)
		}
	}
	add(strings.Contains(body, "##[error]"), "gha_error")
	add(strings.HasPrefix(body, "npm ERR!") || body == "npm error" || strings.HasPrefix(body, "npm error "), "npm_error")
	add(strings.HasPrefix(un, "--- FAIL: ") || body == "FAIL" || strings.HasPrefix(body, "FAIL ") || strings.HasPrefix(body, "FAIL\t"), "go_test_fail")
	add(strings.HasPrefix(body, "FAILED "), "pytest_failed")
	add(strings.HasPrefix(un, "Traceback (most recent call last):"), "python_traceback")
	add(strings.HasPrefix(body, "panic: "), "go_panic")
	add(errorLineRE.MatchString(un), "error_line")
	add(timeoutRE.MatchString(body), "timeout")
	add(failedCountRE.MatchString(body), "failed_count")
	return out
}

// ExitCode returns the first non-zero exit code the body reports with
// "Process completed with exit code N".
func ExitCode(body string) (int64, bool) {
	m := exitRE.FindStringSubmatch(body)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64) // at most 10 digits: always fits
	return n, err == nil
}

// StepHeader reports whether the body has the shape of a runner step header.
// Any process can print a line of that shape.
func StepHeader(body string) bool { return strings.HasPrefix(body, "##[group]Run ") }
