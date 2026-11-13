package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shared conformance cases in contracts/cases/manifest.json. The
// TypeScript suite in contracts/ts reads the same file and must agree.

const casesDir = "../../cases"

type manifest struct {
	Schema   string     `json:"schema"`
	Contract string     `json:"contract"`
	Cases    []testCase `json:"cases"`
	Vectors  []vector   `json:"canonical_vectors"`
}

type testCase struct {
	ID     string `json:"id"`
	Note   string `json:"note"`
	Input  input  `json:"input"`
	Expect expect `json:"expect"`
}

type input struct {
	File       string      `json:"file"`
	Base       string      `json:"base"`
	Raw        *string     `json:"raw"`
	RawHex     *string     `json:"raw_hex"`
	Replace    []replaceOp `json:"replace"`
	PadToBytes *int        `json:"pad_to_bytes"`
}

type replaceOp struct {
	Find       string  `json:"find"`
	With       *string `json:"with"`
	WithHex    *string `json:"with_hex"`
	WithRepeat *repeat `json:"with_repeat"`
}

type repeat struct {
	Item      string `json:"item"`
	Count     int    `json:"count"`
	Separator string `json:"separator"`
}

type expect struct {
	Result         string `json:"result"`
	Code           string `json:"code"`
	Pointer        string `json:"pointer"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}

type vector struct {
	ID           string `json:"id"`
	JSON         string `json:"json"`
	CanonicalHex string `json:"canonical_hex"`
	SHA256       string `json:"sha256"`
}

func loadManifest(t *testing.T) manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(casesDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m manifest
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if m.Schema != "aftergreen.bundle-cases.v0" || m.Contract != SchemaVersion {
		t.Fatalf("unexpected manifest schema %q / contract %q", m.Schema, m.Contract)
	}
	return m
}

func readCase(t *testing.T, name string) []byte { return readCaseFrom(t, casesDir, name) }

func readCaseFrom(t *testing.T, dir, name string) []byte {
	t.Helper()
	if strings.ContainsAny(name, `/\`) {
		t.Fatalf("case file %q must be a plain file name", name)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// buildInput follows contracts/README.md exactly; the TypeScript harness
// implements the same rules.
func buildInput(t *testing.T, in input) []byte { return buildInputFrom(t, casesDir, in) }

func buildInputFrom(t *testing.T, dir string, in input) []byte {
	t.Helper()
	forms := 0
	for _, set := range []bool{in.File != "", in.Base != "", in.Raw != nil, in.RawHex != nil} {
		if set {
			forms++
		}
	}
	if forms != 1 {
		t.Fatalf("input needs exactly one of file, base, raw, raw_hex")
	}
	if in.Base == "" && (len(in.Replace) > 0 || in.PadToBytes != nil) {
		t.Fatalf("replace and pad_to_bytes are only allowed with base")
	}
	var data []byte
	switch {
	case in.File != "":
		data = readCaseFrom(t, dir, in.File)
	case in.Base != "":
		data = readCaseFrom(t, dir, in.Base)
	case in.Raw != nil:
		data = []byte(*in.Raw)
	default:
		b, err := hex.DecodeString(*in.RawHex)
		if err != nil {
			t.Fatal(err)
		}
		data = b
	}
	for _, op := range in.Replace {
		data = applyReplace(t, data, op)
	}
	if in.PadToBytes != nil {
		n := *in.PadToBytes
		if len(data) > n {
			t.Fatalf("input is already %d bytes, more than pad_to_bytes %d", len(data), n)
		}
		data = append(data, bytes.Repeat([]byte{' '}, n-len(data))...)
	}
	return data
}

func applyReplace(t *testing.T, data []byte, op replaceOp) []byte {
	t.Helper()
	find := []byte(op.Find)
	if n := bytes.Count(data, find); n != 1 || len(find) == 0 {
		t.Fatalf("replace: find occurs %d times: %.60q", n, op.Find)
	}
	var with []byte
	forms := 0
	if op.With != nil {
		with = []byte(*op.With)
		forms++
	}
	if op.WithHex != nil {
		b, err := hex.DecodeString(*op.WithHex)
		if err != nil {
			t.Fatal(err)
		}
		with = b
		forms++
	}
	if op.WithRepeat != nil {
		parts := make([]string, op.WithRepeat.Count)
		for i := range parts {
			parts[i] = op.WithRepeat.Item
		}
		with = []byte(strings.Join(parts, op.WithRepeat.Separator))
		forms++
	}
	if forms != 1 {
		t.Fatalf("replace needs exactly one of with, with_hex, with_repeat")
	}
	return bytes.Replace(data, find, with, 1)
}

func TestConformanceCases(t *testing.T) {
	m := loadManifest(t)
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
			got := Validate(buildInput(t, c.Input))
			if c.Expect.Result == "accept" {
				if !got.Accepted() {
					t.Fatalf("rejected with %s at %q (%s); want accept", got.Code, got.Pointer, got.Detail)
				}
				if got.EvidenceSHA256 != c.Expect.EvidenceSHA256 {
					t.Fatalf("digest %s; want %s", got.EvidenceSHA256, c.Expect.EvidenceSHA256)
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
			t.Errorf("no case expects error code %s", code)
		}
	}
}

func TestCanonicalVectors(t *testing.T) {
	m := loadManifest(t)
	if len(m.Vectors) == 0 {
		t.Fatal("no canonical vectors")
	}
	for _, v := range m.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			parsed, f := parseStrict([]byte(v.JSON))
			if f != nil {
				t.Fatalf("parse: %s: %s", f.code, f.detail)
			}
			enc, err := canonicalEncode(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(enc); got != v.CanonicalHex {
				t.Fatalf("encoding %s; want %s", got, v.CanonicalHex)
			}
			sum := sha256.Sum256(enc)
			if got := hex.EncodeToString(sum[:]); got != v.SHA256 {
				t.Fatalf("sha256 %s; want %s", got, v.SHA256)
			}
		})
	}
}

// FuzzValidate checks that no input makes Validate panic and that accepted
// bundles always carry a well-formed digest. Without -fuzz it runs the seeds.
func FuzzValidate(f *testing.F) {
	for _, name := range []string{"valid-simulated-stale-lockfile.json", "valid-missing-baseline-log.json"} {
		data, err := os.ReadFile(filepath.Join(casesDir, name))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"a":"\ud800"}`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		r := Validate(data)
		if r.Accepted() {
			if !reDigest.MatchString(r.EvidenceSHA256) {
				t.Fatalf("accepted without a valid digest: %q", r.EvidenceSHA256)
			}
		} else if !contains(Codes, r.Code) {
			t.Fatalf("unknown code %q", r.Code)
		}
	})
}
