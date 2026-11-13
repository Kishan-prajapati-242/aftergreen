package compare

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// Semantic parsing of usable manifests and lockfiles (section 4). The text is
// the source's lines joined with LF; every member keeps the original line of
// its name, and every object the line of its closing brace.

var depSections = []string{"dependencies", "devDependencies", "optionalDependencies"}

type jnode struct {
	kind      byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' bool, 'z' null
	str       string
	members   []jmember
	startLine int64 // objects and arrays: line of the opening brace or bracket
	endLine   int64 // objects and arrays: line of the closing brace or bracket
}

type jmember struct {
	name  string
	line  int64
	value *jnode
}

type section struct {
	present    bool
	start, end int64
	specs      map[string]string
	lines      map[string]int64
}

type parsedJSON struct {
	sections map[string]section
	// The containing object cited when a whole section is absent: the
	// manifest's top-level object, or the lockfile's packages[""] object.
	containerStart, containerEnd int64
}

var errDuplicateMember = errors.New("duplicate member name")

func parseLines(s *sourceDoc) (*jnode, string) {
	text := strings.Join(lineTexts(s), "\n")
	starts := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	lineAt := func(off int64) int64 {
		return int64(sort.Search(len(starts), func(i int) bool { return int64(starts[i]) > off }))
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var read func() (*jnode, error)
	read = func() (*jnode, error) {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case json.Delim:
			n := &jnode{kind: 'a', startLine: lineAt(dec.InputOffset() - 1)}
			if t == '{' {
				n.kind = 'o'
				seen := map[string]bool{}
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return nil, err
					}
					name, _ := kt.(string)
					line := lineAt(dec.InputOffset() - 1)
					if seen[name] {
						return nil, errDuplicateMember
					}
					seen[name] = true
					v, err := read()
					if err != nil {
						return nil, err
					}
					n.members = append(n.members, jmember{name: name, line: line, value: v})
				}
			} else {
				for dec.More() {
					if _, err := read(); err != nil {
						return nil, err
					}
				}
			}
			if _, err := dec.Token(); err != nil { // closing delimiter
				return nil, err
			}
			n.endLine = lineAt(dec.InputOffset() - 1)
			return n, nil
		case string:
			return &jnode{kind: 's', str: t}, nil
		case json.Number:
			return &jnode{kind: 'n', str: string(t)}, nil
		case bool:
			return &jnode{kind: 'b'}, nil
		default:
			return &jnode{kind: 'z'}, nil
		}
	}
	root, err := read()
	switch {
	case errors.Is(err, errDuplicateMember):
		return nil, "duplicate_key"
	case err != nil:
		return nil, "invalid_json"
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, "invalid_json"
	}
	if root.kind != 'o' {
		return nil, "not_an_object"
	}
	return root, ""
}

// hasControlRune reports U+0000-U+001F or U+007F-U+009F, which JSON escapes in
// a source line can decode to even though bundle v0 rejects them in raw text.
func hasControlRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return true
		}
	}
	return false
}

func memberOf(n *jnode, name string) *jmember {
	if n == nil || n.kind != 'o' {
		return nil
	}
	for i := range n.members {
		if n.members[i].name == name {
			return &n.members[i]
		}
	}
	return nil
}

func depSectionsOf(obj *jnode) (map[string]section, string) {
	out := map[string]section{}
	for _, name := range depSections {
		m := memberOf(obj, name)
		if m == nil {
			continue
		}
		if m.value.kind != 'o' {
			return nil, "bad_section"
		}
		sec := section{present: true, start: m.line, end: m.value.endLine, specs: map[string]string{}, lines: map[string]int64{}}
		for _, e := range m.value.members {
			if e.value.kind != 's' {
				return nil, "bad_section"
			}
			if hasControlRune(e.name) || hasControlRune(e.value.str) {
				return nil, "control_character"
			}
			sec.specs[e.name] = e.value.str
			sec.lines[e.name] = e.line
		}
		out[name] = sec
	}
	return out, ""
}

// parse parses a usable manifest or lockfile once and records failures.
func (c *ctx) parse(s *sourceDoc) (*parsedJSON, bool) {
	if p, ok := c.parsed[s.ID]; ok {
		return p, p != nil
	}
	p, reason := parseSource(s)
	c.parsed[s.ID] = p
	if p == nil {
		c.parseErr[s.ID] = reason
	}
	return p, p != nil
}

func parseSource(s *sourceDoc) (*parsedJSON, string) {
	root, reason := parseLines(s)
	if root == nil {
		return nil, reason
	}
	obj := root
	start, end := root.startLine, root.endLine
	if s.Kind == "lockfile" {
		v := memberOf(root, "lockfileVersion")
		pk := memberOf(root, "packages")
		if v == nil || v.value.kind != 'n' || (v.value.str != "2" && v.value.str != "3") || pk == nil {
			return nil, "unsupported_lockfile"
		}
		rootPkg := memberOf(pk.value, "")
		if rootPkg == nil || rootPkg.value.kind != 'o' {
			return nil, "unsupported_lockfile"
		}
		obj = rootPkg.value
		start, end = rootPkg.line, rootPkg.value.endLine
	}
	secs, reason := depSectionsOf(obj)
	if secs == nil {
		return nil, reason
	}
	return &parsedJSON{sections: secs, containerStart: start, containerEnd: end}, ""
}

// absenceCitation cites where an entry is absent: the section block when the
// section exists, otherwise the whole containing object.
func absenceCitation(s *sourceDoc, p *parsedJSON, sec section) Citation {
	if sec.present {
		return Citation{SourceID: s.ID, Start: sec.start, End: sec.end}
	}
	return Citation{SourceID: s.ID, Start: p.containerStart, End: p.containerEnd}
}

// diffSections compares dependency sections of side a and side b, whose
// fields are named aSide+"_spec" / aSide+"_section" and likewise for b. Each
// side gets one citation: its entry line, or where the entry is absent
// (absenceCitation); a side lacking the whole section is marked "absent".
func diffSections(kind, role string, a *sourceDoc, pa *parsedJSON, aSide string, b *sourceDoc, pb *parsedJSON, bSide string) []Observation {
	var out []Observation
	for _, name := range depSections {
		sa, sb := pa.sections[name], pb.sections[name]
		set := map[string]bool{}
		for k := range sa.specs {
			set[k] = true
		}
		for k := range sb.specs {
			set[k] = true
		}
		var names []string
		for k := range set {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, dep := range names {
			av, aok := sa.specs[dep]
			bv, bok := sb.specs[dep]
			if aok && bok && av == bv {
				continue
			}
			fields := map[string]string{"section": name, "name": dep}
			var cites []Citation
			if aok {
				fields[aSide+"_spec"] = av
				cites = append(cites, Citation{SourceID: a.ID, Start: sa.lines[dep], End: sa.lines[dep]})
			} else {
				cites = append(cites, absenceCitation(a, pa, sa))
				if !sa.present {
					fields[aSide+"_section"] = "absent"
				}
			}
			if bok {
				fields[bSide+"_spec"] = bv
				cites = append(cites, Citation{SourceID: b.ID, Start: sb.lines[dep], End: sb.lines[dep]})
			} else {
				cites = append(cites, absenceCitation(b, pb, sb))
				if !sb.present {
					fields[bSide+"_section"] = "absent"
				}
			}
			out = append(out, observation(kind, role, fields, cites...))
		}
	}
	return out
}

func (c *ctx) lockfileMismatches() []Observation {
	f := c.failed
	m, l := f.sources["manifest"], f.sources["lockfile"]
	if !usable(f, m) || !usable(f, l) {
		return nil
	}
	pm, okM := c.parse(m)
	pl, okL := c.parse(l)
	if !okM || !okL {
		return nil
	}
	return diffSections("lockfile_root_mismatch", "failed", m, pm, "manifest", l, pl, "lockfile")
}

func (c *ctx) dependencyChanges() []Observation {
	bm, fm := c.baseline.sources["manifest"], c.failed.sources["manifest"]
	if !usable(c.baseline, bm) || !usable(c.failed, fm) {
		return nil
	}
	pb, okB := c.parse(bm)
	pf, okF := c.parse(fm)
	if !okB || !okF {
		return nil
	}
	return diffSections("dependency_changed", "both", bm, pb, "baseline", fm, pf, "failed")
}
