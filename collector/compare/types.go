// Package compare computes the deterministic comparison result of
// contracts/comparison-v0.md from one accepted v0 evidence bundle, and
// verifies comparison results against a bundle. It uses no network, no model
// and only the Go standard library plus the v0 bundle validator.
package compare

// Schema is the comparison result version string.
const Schema = "aftergreen.comparison.v0"

// Result is the comparison document. It is never written into a bundle.
type Result struct {
	Schema               string        `json:"schema"`
	BundleEvidenceSHA256 string        `json:"bundle_evidence_sha256"`
	EvidenceClass        string        `json:"evidence_class"`
	Decision             string        `json:"decision"`
	Rows                 []Row         `json:"rows"`
	Observations         []Observation `json:"observations"`
	Limitations          []Limitation  `json:"limitations"`
}

// Row is one line of the baseline reason table. Failed and Baseline are
// display strings; Outcome and Effect are normative.
type Row struct {
	Field    string `json:"field"`
	Failed   string `json:"failed"`
	Baseline string `json:"baseline"`
	Outcome  string `json:"outcome"`
	Effect   string `json:"effect"`
}

// Observation is a mechanically derived fact with exact citations.
type Observation struct {
	Kind      string            `json:"kind"`
	RunRole   string            `json:"run_role"`
	Fields    map[string]string `json:"fields"`
	Citations []Citation        `json:"citations"`
}

// Citation is a source ID and an inclusive original line range.
type Citation struct {
	SourceID string `json:"source_id"`
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
}

// Limitation records evidence that prevents a conclusion.
type Limitation struct {
	Code     string `json:"code"`
	RunRole  string `json:"run_role,omitempty"`
	SourceID string `json:"source_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Start    int64  `json:"start,omitempty"`
	End      int64  `json:"end,omitempty"`
}

// Problem is one verification failure. Observation is the index of the
// offending observation, or -1 for a problem with the bundle or summary.
type Problem struct {
	Code        string `json:"code"`
	Observation int    `json:"observation"`
	Detail      string `json:"detail"`
}

// BundleError reports that the input is not an accepted v0 bundle.
type BundleError struct {
	Code    string
	Pointer string
	Detail  string
}

func (e *BundleError) Error() string {
	return "bundle rejected: " + e.Code + " at " + e.Pointer + ": " + e.Detail
}

// Decoded v0 bundle. encoding/json is used only after bundle.Validate has
// accepted the bytes: validation already rejects duplicate or case-variant
// member names, unknown members, malformed UTF-8 and non-integer numbers, the
// cases encoding/json would otherwise mishandle.

type bundleDoc struct {
	Schema         string      `json:"schema"`
	CaseID         string      `json:"case_id"`
	EvidenceClass  string      `json:"evidence_class"`
	CreatedAt      string      `json:"created_at"`
	Redaction      string      `json:"redaction"`
	Runs           []runDoc    `json:"runs"`
	Sources        []sourceDoc `json:"sources"`
	EvidenceSHA256 string      `json:"evidence_sha256"`
}

type runDoc struct {
	Role             string      `json:"role"`
	Repository       repoDoc     `json:"repository"`
	Workflow         workflowDoc `json:"workflow"`
	RunID            int64       `json:"run_id"`
	RunAttempt       int64       `json:"run_attempt"`
	AttemptStartedAt string      `json:"attempt_started_at"`
	Event            string      `json:"event"`
	Branch           string      `json:"branch"`
	HeadSHA          string      `json:"head_sha"`
	Job              jobDoc      `json:"job"`
	Checkout         checkoutDoc `json:"checkout"`
	Matrix           matrixDoc   `json:"matrix"`
	Runner           runnerDoc   `json:"runner"`
}

type repoDoc struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
}

type workflowDoc struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
}

type jobDoc struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Conclusion  string `json:"conclusion"`
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

type checkoutDoc struct {
	Status   string    `json:"status"`
	SHA      string    `json:"sha"`
	Reason   string    `json:"reason"`
	Evidence []spanDoc `json:"evidence"`
}

type matrixDoc struct {
	Status   string        `json:"status"`
	Values   []matrixValue `json:"values"`
	Reason   string        `json:"reason"`
	Evidence []spanDoc     `json:"evidence"`
}

type matrixValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type runnerDoc struct {
	OS       string    `json:"os"`
	Arch     string    `json:"arch"`
	Labels   []string  `json:"labels"`
	Evidence []spanDoc `json:"evidence"`
}

type spanDoc struct {
	SourceID string `json:"source_id"`
	Start    int64  `json:"start"`
	End      int64  `json:"end"`
}

type sourceDoc struct {
	ID            string       `json:"id"`
	Kind          string       `json:"kind"`
	RunRole       string       `json:"run_role"`
	Status        string       `json:"status"`
	Path          string       `json:"path"`
	Revision      string       `json:"revision"`
	MissingReason string       `json:"missing_reason"`
	Extent        string       `json:"extent"`
	LineCount     int64        `json:"line_count"`
	Lines         []lineDoc    `json:"lines"`
	Omitted       []omittedDoc `json:"omitted"`
}

type lineDoc struct {
	N    int64  `json:"n"`
	Text string `json:"text"`
}

type omittedDoc struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Reason string `json:"reason"`
}
