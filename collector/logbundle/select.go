package logbundle

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
)

// Line selection. A line is a candidate when it is:
//   - a failure line (##[error], or "Process completed with exit code" and
//     a non-zero code);
//   - another error signal (npm ERR!, Error:, ERROR, FAIL, failed, Failed,
//     AssertionError, a Python traceback, panic:, timed out, TimeoutError);
//   - within contextLines of either; or
//   - among the first headLines or last tailLines of the log.
//
// Candidates are tried in that order of importance, later lines first within
// each rank. Each is included if it still fits the line limit and the byte
// budget; one that does not fit is skipped, and later, smaller ones are still
// tried. So a larger budget does not always include a superset of a smaller
// one.
//
// Every omitted line gets its exact reason, and no step changes it:
//   - redacted: withheld by redaction, wherever it is;
//   - line_too_long: a candidate over 2,048 bytes after cleaning, which is
//     then not redacted, or over 2,048 bytes after redaction. Neither kind
//     is scanned for signals;
//   - line_limit: a candidate that is not included because of the line, byte
//     or omitted-range budget;
//   - outside_selected_span: every other line.
//
// The bundle may hold at most 501 omitted ranges. When the exact reasons
// need more, fitRanges drops included lines, which become line_limit, but
// only blocks with line_limit lines on both sides: dropping one merges two
// ranges into one. Build tries line budgets from 110,000 bytes down in steps
// of 1,024 while positive, then 0 (lineBudgets), and keeps the first
// selection that fits both the range and the size limit; if none does, it
// returns ErrRangeLimit.

var (
	failureRE = regexp.MustCompile(`##\[error\]|Process completed with exit code [1-9]`)
	signalRE  = regexp.MustCompile(`npm ERR!|Error:|\bERROR\b|\bFAIL(?:ED)?\b|\b[Ff]ailed\b|AssertionError|Traceback \(most recent call last\)|panic:|[Tt]imed out|\bTimeoutError\b`)
)

const (
	contextLines = 3
	headLines    = 5
	tailLines    = 20

	maxLines     = 500  // contracts/bundle-v1.md: lines per source
	maxLineBytes = 2048 // and bytes per line text
	maxOmitted   = 501  // and omitted ranges per source
)

type lineDoc struct {
	text     string
	counts   map[string]int // inline redactions in this line, by rule
	withheld bool           // withheld by redaction: a key block, or hidden by escape removal
	tooLong  bool
}

type decision byte

const (
	included decision = iota + 1
	outside
	tooLong
	overLimit
	redacted
)

var reasonOf = map[decision]string{
	outside:   "outside_selected_span",
	tooLong:   "line_too_long",
	overLimit: "line_limit",
	redacted:  "redacted",
}

// ranking is what admission needs, computed once per log: each line's rank
// (0 is most important; -1 is not a candidate), the reasons that do not
// depend on the budget, and the admissible candidates in admission order
// with their encoded sizes.
type ranking struct {
	rank  []int
	base  []decision // 0 for an admissible candidate
	cands []int
	cost  []int // per candidate, in cands order
}

func rankLines(lines []lineDoc) ranking {
	n := len(lines)
	rank := make([]int, n)
	for i := range rank {
		rank[i] = -1
	}
	mark := func(i, r int) {
		if i >= 0 && i < n && (rank[i] < 0 || r < rank[i]) {
			rank[i] = r
		}
	}
	for i, l := range lines {
		r := -1
		switch {
		case l.withheld || l.tooLong:
			continue
		case failureRE.MatchString(l.text):
			r = 0
		case signalRE.MatchString(l.text):
			r = 1
		default:
			continue
		}
		mark(i, r)
		for d := 1; d <= contextLines; d++ {
			mark(i-d, 2)
			mark(i+d, 2)
		}
	}
	for i := 0; i < headLines; i++ {
		mark(i, 3)
	}
	for i := n - tailLines; i < n; i++ {
		mark(i, 3)
	}

	rk := ranking{rank: rank, base: make([]decision, n)}
	for i, l := range lines {
		switch {
		case l.withheld:
			rk.base[i] = redacted
		case rank[i] < 0:
			rk.base[i] = outside
		case l.tooLong:
			rk.base[i] = tooLong
		default:
			rk.cands = append(rk.cands, i)
		}
	}
	sort.SliceStable(rk.cands, func(a, b int) bool {
		if rank[rk.cands[a]] != rank[rk.cands[b]] {
			return rank[rk.cands[a]] < rank[rk.cands[b]]
		}
		return rk.cands[a] > rk.cands[b]
	})
	rk.cost = make([]int, len(rk.cands))
	for k, i := range rk.cands {
		rk.cost[k] = lineCost(int64(i+1), lines[i].text)
	}
	return rk
}

// admit decides, for every line, whether it is included and otherwise why
// not, within maxLines lines and textBudget bytes of encoded line objects.
func (rk ranking) admit(textBudget int) []decision {
	dec := append([]decision(nil), rk.base...)
	used, count := 0, 0
	for k, i := range rk.cands {
		if cost := rk.cost[k]; count < maxLines && used+cost <= textBudget {
			dec[i] = included
			used += cost
			count++
		} else {
			dec[i] = overLimit
		}
	}
	return dec
}

// choose is rankLines and admit together, for tests.
func choose(lines []lineDoc, textBudget int) ([]decision, []int) {
	rk := rankLines(lines)
	return rk.admit(textBudget), rk.rank
}

// lineCost is the encoded size of one line object and its separator.
func lineCost(n int64, text string) int {
	return len(`{"n":,"text":},`) + len(strconv.FormatInt(n, 10)) + len(encodeString(text))
}

func encodeString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
}

type omittedJSON struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Reason string `json:"reason"`
}

// fitRanges brings the omitted ranges within the limit without changing any
// omitted line's reason. It drops only included blocks that have a
// line_limit line on each side; the dropped lines are selected lines over
// the range budget, so line_limit is their exact reason, and each drop
// merges two ranges into one. Blocks go least important first: the highest
// best rank in the block, then the fewest lines, then the earliest. It
// returns the number of lines dropped, and false if the ranges still do not
// fit.
func fitRanges(dec []decision, rank []int) (dropped int, ok bool) {
	count := len(omittedRanges(dec))
	if count <= maxOmitted {
		return 0, true
	}
	type block struct{ start, end, best int }
	var blocks []block
	for i := 0; i < len(dec); {
		if dec[i] != included {
			i++
			continue
		}
		j := i
		best := rank[i]
		for j+1 < len(dec) && dec[j+1] == included {
			j++
			best = min(best, rank[j])
		}
		if i > 0 && j+1 < len(dec) && dec[i-1] == overLimit && dec[j+1] == overLimit {
			blocks = append(blocks, block{i, j, best})
		}
		i = j + 1
	}
	sort.SliceStable(blocks, func(a, b int) bool {
		x, y := blocks[a], blocks[b]
		switch {
		case x.best != y.best:
			return x.best > y.best
		case x.end-x.start != y.end-y.start:
			return x.end-x.start < y.end-y.start
		}
		return x.start < y.start
	})
	// Blocks are separated by line_limit lines, so dropping one leaves every
	// other block's neighbours unchanged.
	for _, b := range blocks {
		if count <= maxOmitted {
			break
		}
		for i := b.start; i <= b.end; i++ {
			dec[i] = overLimit
		}
		dropped += b.end - b.start + 1
		count--
	}
	return dropped, count <= maxOmitted
}

// omittedRanges groups consecutive lines that share a reason.
func omittedRanges(dec []decision) []omittedJSON {
	var out []omittedJSON
	for i, d := range dec {
		if d == included {
			continue
		}
		n := int64(i + 1)
		if k := len(out) - 1; k >= 0 && out[k].End == n-1 && out[k].Reason == reasonOf[d] {
			out[k].End = n
			continue
		}
		out = append(out, omittedJSON{Start: n, End: n, Reason: reasonOf[d]})
	}
	return out
}
