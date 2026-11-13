package bundle

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The shared v1 conformance cases in contracts/cases-v1/manifest.json, built
// with the same input rules as v0's. The TypeScript suite reads the same file
// and must agree on acceptance, code, pointer and digest.

const casesDirV1 = "../../cases-v1"

type manifestV1 struct {
	Schema   string     `json:"schema"`
	Contract string     `json:"contract"`
	Cases    []testCase `json:"cases"`
}

func loadManifestV1(t *testing.T) manifestV1 {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(casesDirV1, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m manifestV1
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if m.Schema != "aftergreen.bundle-cases.v1" || m.Contract != SchemaVersionV1 {
		t.Fatalf("unexpected manifest schema %q / contract %q", m.Schema, m.Contract)
	}
	return m
}

func TestConformanceCasesV1(t *testing.T) {
	m := loadManifestV1(t)
	expected := map[string]bool{}
	seen := map[string]bool{}
	for _, c := range m.Cases {
		if seen[c.ID] {
			t.Fatalf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true
		switch c.Expect.Result {
		case "accept":
			if c.Expect.Code != "" || c.Expect.Pointer != "" || len(c.Expect.EvidenceSHA256) != 64 {
				t.Fatalf("%s: an accept case needs only evidence_sha256", c.ID)
			}
		case "reject":
			if !contains(Codes, c.Expect.Code) || c.Expect.EvidenceSHA256 != "" {
				t.Fatalf("%s: unknown expected code %q or stray digest", c.ID, c.Expect.Code)
			}
			expected[c.Expect.Code] = true
		default:
			t.Fatalf("%s: unknown expected result %q", c.ID, c.Expect.Result)
		}
		t.Run(c.ID, func(t *testing.T) {
			raw := buildInputFrom(t, casesDirV1, c.Input)
			got := ValidateV1(raw)
			if c.Expect.Result == "accept" {
				if !got.Accepted() {
					t.Fatalf("rejected with %s at %q (%s); want accept", got.Code, got.Pointer, got.Detail)
				}
				if got.EvidenceSHA256 != c.Expect.EvidenceSHA256 {
					t.Fatalf("digest %s; want %s", got.EvidenceSHA256, c.Expect.EvidenceSHA256)
				}
				if d, r := DigestV1(raw); d != got.EvidenceSHA256 || !r.Accepted() {
					t.Fatalf("DigestV1 %s (%s); want %s", d, r.Code, got.EvidenceSHA256)
				}
				return
			}
			if got.Accepted() {
				t.Fatalf("accepted with digest %s; want %s at %q", got.EvidenceSHA256, c.Expect.Code, c.Expect.Pointer)
			}
			if got.Code != c.Expect.Code || got.Pointer != c.Expect.Pointer {
				t.Fatalf("got %s at %q (%s); want %s at %q", got.Code, got.Pointer, got.Detail, c.Expect.Code, c.Expect.Pointer)
			}
		})
	}
	for _, code := range Codes {
		if !expected[code] {
			t.Errorf("no v1 case expects error code %s", code)
		}
	}
}

// Negative control: v1 is not v0. Every accepted v1 case is rejected by the
// v0 validator, and no v0 case is accepted by the v1 validator.
func TestVersionsDoNotAcceptEachOther(t *testing.T) {
	for _, c := range loadManifestV1(t).Cases {
		if c.Expect.Result != "accept" {
			continue
		}
		if r := Validate(buildInputFrom(t, casesDirV1, c.Input)); r.Accepted() || r.Code != CodeUnknownField || r.Pointer != "/collection" {
			t.Errorf("%s: v0 validator gave %q at %q; want unknown_field at /collection", c.ID, r.Code, r.Pointer)
		}
	}
	for _, c := range loadManifest(t).Cases {
		if c.Expect.Result != "accept" {
			continue
		}
		if r := ValidateV1(buildInput(t, c.Input)); r.Accepted() {
			t.Errorf("%s: a v0 bundle was accepted as v1", c.ID)
		}
	}
}

// FuzzValidateV1 checks that no input makes ValidateV1 panic. Without -fuzz
// it runs the seeds.
func FuzzValidateV1(f *testing.F) {
	for _, name := range []string{"valid-collected-job-log.json", "valid-simulated-log-missing.json"} {
		data, err := os.ReadFile(filepath.Join(casesDirV1, name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := ValidateV1(data)
		if r.Accepted() {
			if !reDigest.MatchString(r.EvidenceSHA256) {
				t.Fatalf("accepted without a valid digest: %q", r.EvidenceSHA256)
			}
		} else if !contains(Codes, r.Code) {
			t.Fatalf("unknown code %q", r.Code)
		}
	})
}
