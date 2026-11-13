package github

import (
	"errors"
	"time"
)

// Limits bound one collection. DefaultLimits returns the network defaults
// listed in docs/collector.md; MaxJobPages is this package's own choice.
type Limits struct {
	MaxRequests    int           // HTTP requests, the redirected log download included
	RequestTimeout time.Duration // one request: connection, headers and body
	Deadline       time.Duration // the whole collection
	MaxJSONBytes   int64         // one API response body, error bodies included
	MaxLogBytes    int64         // the job-log download body
	MaxTotalBytes  int64         // all response bodies of the collection together
	MaxJobPages    int           // pages of up to 100 jobs listed for the attempt
}

// DefaultLimits: 30 requests, 15 s per request, 90 s overall, 1 MiB per API
// JSON response, 2 MiB of job log, 8 MiB in total, 3 pages of jobs.
func DefaultLimits() Limits {
	return Limits{
		MaxRequests:    30,
		RequestTimeout: 15 * time.Second,
		Deadline:       90 * time.Second,
		MaxJSONBytes:   1 << 20,
		MaxLogBytes:    2 << 20,
		MaxTotalBytes:  8 << 20,
		MaxJobPages:    3,
	}
}

func (l Limits) check() error {
	if l.MaxRequests < 1 || l.RequestTimeout <= 0 || l.Deadline <= 0 || l.MaxJSONBytes < 1 ||
		l.MaxLogBytes < 1 || l.MaxTotalBytes < 1 || l.MaxJobPages < 1 {
		return errors.New("every limit must be positive")
	}
	return nil
}
