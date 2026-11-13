package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validate(t *testing.T, args ...string) (int, output, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	var o output
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &o); err != nil || strings.Count(out.String(), "\n") != 1 {
			t.Fatalf("output %q is not one JSON line", out.String())
		}
	}
	return code, o, errb.String()
}

func TestValidateCases(t *testing.T) {
	cases := filepath.Join("..", "..", "..")
	for _, c := range []struct {
		schema, file string
		code         int
		accepted     bool
		errCode      string
	}{
		{"v1", "cases-v1/valid-producer-fixture.json", 0, true, ""},
		{"v1", "cases-v1/valid-collected-job-log.json", 0, true, ""},
		{"v0", "cases-v1/valid-collected-job-log.json", 1, false, "unknown_field"},
		{"v0", "cases/valid-simulated-stale-lockfile.json", 0, true, ""},
		{"v1", "cases/valid-simulated-stale-lockfile.json", 1, false, "schema_violation"},
	} {
		code, o, _ := validate(t, "-schema", c.schema, filepath.Join(cases, c.file))
		if code != c.code || o.Accepted != c.accepted || o.Code != c.errCode || (c.accepted && len(o.EvidenceSHA256) != 64) {
			t.Errorf("%s %s: exit %d, %+v", c.schema, c.file, code, o)
		}
	}
}

func TestValidateArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"x.json"}, {"-schema", "v2", "x.json"}, {"-schema", "v1"}, {"-schema", "v1", "a", "b"}, {"-schema", "v1", "/nonexistent/bundle.json"}} {
		if code, o, _ := validate(t, args...); code != 2 || o.Contract != "" {
			t.Errorf("%q: exit %d, output %+v", args, code, o)
		}
	}
}

func TestValidateOversizeAndPointer(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, bytes.Repeat([]byte(" "), 200000), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, o, _ := validate(t, "-schema", "v1", big); code != 1 || o.Code != "input_too_large" {
		t.Errorf("oversize: exit %d, %+v", code, o)
	}
	odd := filepath.Join(dir, "odd.json")
	if err := os.WriteFile(odd, []byte("{\"schema\":\"aftergreen.bundle.v1\",\"\\u001b[2J\\u202e\":1}"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, o, _ := validate(t, "-schema", "v1", odd)
	if code != 1 || o.Code != "unknown_field" || o.Pointer != "/?[2J?" {
		t.Errorf("odd member name: exit %d, %+v", code, o)
	}
}

// The exact bytes, which contracts/ts/validate.test.ts checks too.
func TestValidateRawLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "html.json")
	if err := os.WriteFile(path, []byte(`{"<a&b>":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	run([]string{"-schema", "v1", path}, &out, &errb)
	if want := `{"contract":"aftergreen.bundle.v1","accepted":false,"code":"unknown_field","pointer":"/<a&b>"}` + "\n"; out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}
