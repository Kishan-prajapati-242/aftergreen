// Command aftergreen-compare prints the comparison result
// (contracts/comparison-v0.md) of one v0 evidence bundle as JSON on stdout.
// It reads only the named file and makes no network request.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"aftergreen/collector/compare"
	"aftergreen/contracts/bundle"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: aftergreen-compare BUNDLE.json")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	// Read one byte past the limit so the validator can report input_too_large
	// without the whole file being loaded.
	raw, err := io.ReadAll(io.LimitReader(f, bundle.MaxInputBytes+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	res, err := compare.Compare(raw)
	if err != nil {
		// A pointer can hold member names from the file, so it is printed
		// quoted in ASCII, and the informational detail is not printed.
		var be *compare.BundleError
		if errors.As(err, &be) {
			fmt.Fprintf(os.Stderr, "aftergreen-compare: bundle rejected: %s at %s\n", be.Code, strconv.QuoteToASCII(be.Pointer))
		} else {
			fmt.Fprintln(os.Stderr, "aftergreen-compare: the accepted bundle could not be decoded")
		}
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(res); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
