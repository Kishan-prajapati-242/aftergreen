// Command aftergreen-inspect prints the inspection (contracts/inspection-v0.md)
// of one bundle v1 as JSON: fixed observation kinds, counts, citations by
// original line number, and limitations. It copies no text from the bundle,
// states no cause, and makes no network request.
//
//	aftergreen-inspect BUNDLE.json
//	aftergreen-inspect -verify RESULT.json BUNDLE.json
//
// With -verify it checks an inspection against its bundle, re-deriving every
// observation, and prints the problems it finds.
//
// Exit status: 0 for a result, or for a result that verifies; 1 for a bundle
// that bundle v1 validation rejects, or a result with problems; 2 for invalid
// arguments or an unreadable file.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"aftergreen/collector/inspect"
	"aftergreen/contracts/bundle"
)

// parseResult reads a result document. Tests replace it to see whether it is
// reached.
var parseResult = inspect.ParseResult

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("aftergreen-inspect", flag.ContinueOnError)
	fl.SetOutput(stderr)
	verify := fl.String("verify", "", "an inspection result to check against the bundle")
	fl.Usage = func() {
		fmt.Fprintln(stderr, "usage: aftergreen-inspect [-verify RESULT.json] BUNDLE.json")
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if fl.NArg() != 1 {
		fl.Usage()
		return 2
	}
	raw, err := readBounded(fl.Arg(0), bundle.MaxInputBytes+1)
	if err != nil {
		fmt.Fprintln(stderr, "aftergreen-inspect: cannot read the bundle")
		return 2
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if *verify == "" {
		r, err := inspect.Inspect(raw)
		var ie *inspect.InputError
		if errors.As(err, &ie) {
			// Only the validator's fixed code: its pointer can hold member
			// names from the file. aftergreen-validate prints the location.
			enc.Encode(map[string]any{"schema": inspect.Schema, "bundle_accepted": false, "code": ie.Code})
			return 1
		}
		if err != nil {
			fmt.Fprintln(stderr, "aftergreen-inspect: the bundle could not be inspected")
			return 1
		}
		enc.Encode(r)
		return 0
	}
	resRaw, err := readBounded(*verify, inspect.MaxResultBytes+1)
	if err != nil {
		fmt.Fprintln(stderr, "aftergreen-inspect: cannot read the result")
		return 2
	}
	r, err := (*inspect.Result)(nil), inspect.ErrResultInvalid
	if len(resRaw) <= inspect.MaxResultBytes { // the size is checked before any parsing
		r, err = parseResult(resRaw)
	}
	var problems []inspect.Problem
	if err != nil {
		problems = []inspect.Problem{{Code: "result_invalid", Observation: -1, Detail: "the result is not an inspection v0 document"}}
	} else {
		problems = inspect.Verify(raw, r)
	}
	if problems == nil {
		problems = []inspect.Problem{}
	}
	enc.Encode(map[string]any{"schema": inspect.Schema, "verified": len(problems) == 0, "problems": problems})
	if len(problems) > 0 {
		return 1
	}
	return 0
}

// readBounded reads at most limit bytes. Callers pass one byte more than they
// accept, so a longer file is still seen to be too long: the bundle validator
// reports a bundle as too large, and -verify reports a result as
// result_invalid.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}
