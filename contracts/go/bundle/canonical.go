package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
)

// Section 7: the evidence digest.

const digestTag = "aftergreen.bundle.evidence.v0\n"

var evidenceMembers = []string{"schema", "evidence_class", "runs", "sources"}

// canonicalEncode returns the length-prefixed canonical encoding of v.
// Booleans and null have no encoding; checkBundle rejects them first.
func canonicalEncode(v *value) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeValue(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeValue(buf *bytes.Buffer, v *value) error {
	switch v.kind {
	case kindObject:
		members := append([]member(nil), v.members...)
		sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })
		buf.WriteByte('d')
		for _, m := range members {
			encodeString(buf, m.name)
			if err := encodeValue(buf, m.value); err != nil {
				return err
			}
		}
		buf.WriteByte('e')
	case kindArray:
		buf.WriteByte('l')
		for _, item := range v.items {
			if err := encodeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte('e')
	case kindString:
		encodeString(buf, v.str)
	case kindNumber:
		buf.WriteByte('i')
		buf.WriteString(v.num)
		buf.WriteByte('e')
	default:
		return fmt.Errorf("%s values have no canonical encoding", v.kind)
	}
	return nil
}

func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('s')
	buf.WriteString(strconv.Itoa(len(s)))
	buf.WriteByte(':')
	buf.WriteString(s)
}

// evidenceDigest hashes the evidence members of a bundle that has passed
// checkBundle. case_id, created_at, redaction and evidence_sha256 are excluded.
func evidenceDigest(root *value) string { return evidenceDigestFor(root, digestTag, evidenceMembers) }

// evidenceDigestFor hashes tag followed by the canonical encoding of the
// members of root named in members.
func evidenceDigestFor(root *value, tag string, members []string) string {
	e := &value{kind: kindObject}
	for _, m := range root.members {
		if contains(members, m.name) {
			e.members = append(e.members, m)
		}
	}
	enc, err := canonicalEncode(e)
	if err != nil {
		// Unreachable: checkBundle rejects every boolean and null first.
		panic("bundle: digest of an unchecked bundle: " + err.Error())
	}
	sum := sha256.Sum256(append([]byte(tag), enc...))
	return hex.EncodeToString(sum[:])
}
