package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"aftergreen/collector/logbundle"
)

// CollectBundle makes the requests of Probe (auth "none") or ProbeWithGH
// (auth "gh"), keeps the downloaded job log in memory, and builds a bundle v1
// from it with package logbundle, labelled collected_public. created becomes
// the bundle's created_at.
//
// It returns the collection report and, when a bundle was built, the bundle
// and its summary. Otherwise the error says why; an error wrapping
// logbundle.ErrIncomplete means the collection did not establish what a
// bundle needs. A bundle holding a 12-character piece of the credential is
// never returned. This package writes nothing to disk.
func CollectBundle(ctx context.Context, ref RunRef, lim Limits, auth string, created time.Time) (*Report, []byte, *logbundle.Summary, error) {
	var src credentialSource
	switch auth {
	case "none":
	case "gh":
		src = newGHSource()
	default:
		return nil, nil, nil, errors.New(`auth must be "none" or "gh"`)
	}
	return collectBundle(ctx, ref, lim, newTransport(), src, logbundle.Options{
		EvidenceClass: "collected_public", Tool: "aftergreen-collect", APIVersion: APIVersion, CreatedAt: created})
}

// ErrCredentialInBundle is returned when a built bundle held part of the
// credential. The bundle is discarded.
var ErrCredentialInBundle = errors.New("the bundle would hold part of the credential, so it was discarded")

func collectBundle(ctx context.Context, ref RunRef, lim Limits, rt http.RoundTripper, src credentialSource, opt logbundle.Options) (*Report, []byte, *logbundle.Summary, error) {
	rep, ev := probeWith(ctx, ref, lim, rt, src, true)
	if ev == nil {
		return rep, nil, nil, fmt.Errorf("%w: no failed job of a public push run was selected, or the report was withheld (see the report's stop)", logbundle.ErrIncomplete)
	}
	raw, sum, err := logbundle.Build(ev.input(), opt)
	ev.Log.Bytes = nil // the raw log is not needed past this point
	if err != nil {
		return rep, nil, nil, err
	}
	if ev.reveals(raw) {
		return rep, nil, nil, ErrCredentialInBundle
	}
	return rep, raw, sum, nil
}
