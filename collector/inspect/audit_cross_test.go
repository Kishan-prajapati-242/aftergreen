package inspect

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"strings"
	"testing"

	"aftergreen/collector/logbundle"
)

// The producer's selection audit and the inspector classify included lines
// the same way: for one bundle, the audit's included count of each pattern
// equals the inspector's count.
func TestAuditAgreesWithInspector(t *testing.T) {
	opt := logbundle.Options{EvidenceClass: "simulated", Tool: "aftergreen-collect", APIVersion: "2026-03-10", CreatedAt: caseCreated, Audit: true}
	check := func(name string, in logbundle.Input) {
		raw, sum, err := logbundle.Build(in, opt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		res, err := Inspect(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if sum.Audit == nil {
			if res.JobLog.Status == "present" {
				t.Fatalf("%s: no audit for a present log", name)
			}
			return
		}
		for _, p := range sum.Audit.Patterns {
			want := res.Counts.ErrorMarker[p.Pattern]
			switch p.Pattern {
			case "nonzero_exit":
				want = res.Counts.NonzeroExit
			case "step_header":
				want = res.Counts.StepHeader
			}
			if p.Included != want {
				t.Errorf("%s: %s included %d by the audit, %d by the inspector", name, p.Pattern, p.Included, want)
			}
		}
	}
	for _, c := range synthCases() {
		check(c.name, caseInput(c))
	}
	frags := []string{"\n", "\n", " ", "x", "Error: ", "##[error]", "##[group]Run ", "npm error ", "--- FAIL: ", "FAIL", "FAILED ",
		"panic: ", "timed out", "2 failed", "Process completed with exit code ", "1", "-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----", "token=abc", strings.Repeat("z", 2100), "2026-11-01T10:00:00.0000000Z "}
	r := rand.New(rand.NewPCG(9, 1))
	for iter := 0; iter < 300; iter++ {
		var b strings.Builder
		for n := r.IntN(400); n > 0; n-- {
			b.WriteString(frags[r.IntN(len(frags))])
		}
		log := []byte(b.String())
		sum := sha256.Sum256(log)
		in := caseInput(synthCase{name: "random"})
		in.Log = logbundle.Log{Obtained: true, Extent: "complete", Authentication: "none", Bytes: log, ReceivedBytes: int64(len(log)), SHA256: hex.EncodeToString(sum[:])}
		check("random", in)
	}
}
