// Command aftergreen-validate checks one bundle file against contract v0 or
// v1 and prints one JSON line: the contract checked, whether the bundle was
// accepted, and either its evidence digest or the error code and JSON Pointer
// of the first failed check. It prints nothing else from the file; the
// pointer is shown in printable ASCII, at most 256 bytes.
//
//	aftergreen-validate -schema v0|v1 FILE
//
// contracts/ts/validate.ts prints the same line for the same file.
//
// Exit status: 0 accepted, 1 rejected, 2 invalid arguments or an unreadable
// file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"aftergreen/contracts/bundle"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type output struct {
	Contract       string `json:"contract"`
	Accepted       bool   `json:"accepted"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
	Code           string `json:"code,omitempty"`
	Pointer        string `json:"pointer,omitempty"`
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aftergreen-validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	schema := fs.String("schema", "", `the contract to check: "v0" or "v1"`)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: aftergreen-validate -schema v0|v1 FILE")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || (*schema != "v0" && *schema != "v1") {
		fs.Usage()
		return 2
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "aftergreen-validate: cannot open the file")
		return 2
	}
	defer f.Close()
	// One byte past the limit is enough for the validator to report input_too_large.
	raw, err := io.ReadAll(io.LimitReader(f, bundle.MaxInputBytes+1))
	if err != nil {
		fmt.Fprintln(stderr, "aftergreen-validate: cannot read the file")
		return 2
	}
	o := output{Contract: bundle.SchemaVersion}
	var r bundle.Result
	if *schema == "v1" {
		o.Contract, r = bundle.SchemaVersionV1, bundle.ValidateV1(raw)
	} else {
		r = bundle.Validate(raw)
	}
	o.Accepted, o.EvidenceSHA256, o.Code, o.Pointer = r.Accepted(), r.EvidenceSHA256, r.Code, printable(r.Pointer)
	// Like JSON.stringify in validate.ts: no HTML escaping of <, > and &, so
	// both commands print the same bytes. The pointer is printable ASCII.
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(o) // plain strings: cannot fail; Encode ends the line
	if o.Accepted {
		return 0
	}
	return 1
}

// printable keeps printable ASCII, replaces anything else with '?', and
// truncates to 256 bytes: a pointer can hold member names from the file.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 256 {
			break
		}
		if r < 0x20 || r > 0x7e {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
