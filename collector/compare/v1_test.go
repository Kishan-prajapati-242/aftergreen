package compare

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"aftergreen/contracts/bundle"
)

var digestRE = regexp.MustCompile(`"evidence_sha256":\s*"([0-9a-f])`)

// Comparison v0 refuses bundle v1 by name, and still compares v0.

func TestCompareRefusesBundleV1(t *testing.T) {
	for _, name := range []string{"valid-collected-job-log.json", "valid-simulated-log-missing.json", "valid-producer-fixture.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "cases-v1", name))
		if err != nil {
			t.Fatal(err)
		}
		res, err := Compare(raw)
		var be *BundleError
		if res != nil || !errors.As(err, &be) || be.Code != CodeUnsupportedSchema || be.Pointer != "/schema" {
			t.Errorf("%s: Compare gave %v, %v; want unsupported_schema at /schema", name, res, err)
		}
		if p := Verify(raw, &Result{}); len(p) != 1 || p[0].Code != CodeUnsupportedSchema || p[0].Observation != -1 {
			t.Errorf("%s: Verify gave %+v", name, p)
		}
		// A v1 bundle that fails only its digest check is not refused by
		// name, and is still no v0 bundle.
		m := digestRE.FindSubmatchIndex(raw)
		if m == nil {
			t.Fatalf("%s: no evidence_sha256", name)
		}
		broken := append([]byte(nil), raw...)
		broken[m[2]] = '0' // the digest's first hex digit, changed
		if raw[m[2]] == '0' {
			broken[m[2]] = '1'
		}
		if v := bundle.ValidateV1(broken); v.Code != bundle.CodeDigestMismatch {
			t.Fatalf("%s altered: ValidateV1 gave %q, want digest_mismatch", name, v.Code)
		}
		if res, err := Compare(broken); res != nil || !errors.As(err, &be) || be.Code != bundle.CodeUnknownField || be.Pointer != "/collection" {
			t.Errorf("%s altered: Compare gave %v, %v; want unknown_field at /collection from v0 validation", name, res, err)
		}
	}
}

func TestCompareStillAcceptsBundleV0(t *testing.T) {
	for _, name := range []string{"valid-simulated-stale-lockfile.json", "valid-missing-baseline-log.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "contracts", "cases", name))
		if err != nil {
			t.Fatal(err)
		}
		res, err := Compare(raw)
		if err != nil || res == nil {
			t.Fatalf("%s: Compare = %v, %v", name, res, err)
		}
		if p := Verify(raw, res); p != nil {
			t.Errorf("%s: Verify = %+v", name, p)
		}
	}
}
