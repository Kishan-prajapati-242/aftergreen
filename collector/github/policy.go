package github

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Network policy (docs/collector.md).
//
// API requests go only to fixed routes on api.github.com. The job-log
// endpoint answers with a short-lived redirect. The client follows that one
// redirect only to an exact allowed host, over HTTPS on the default port,
// with no user information, carrying none of the API request's headers.
//
// The allowed hosts are the productionresultssa<N>.blob.core.windows.net
// names that GitHub publishes in GET https://api.github.com/meta, in both
// domains.actions and domains.actions_inbound.full_domains, in the response
// dated 2026-11-08T00:51:10Z: N = 0-19, 30-49 and 100-199. GitHub's runner documentation lists
// only the wildcard *.blob.core.windows.net for logs, which this client does
// not trust. Other published Actions hosts are not trusted either, because no
// evidence shows that they serve job logs.
//
// Every connection, API or download, must reach a public address on port
// 443. The check runs on the resolved address at connection time, so a name
// that resolves to a private address is refused even if it passed the host
// policy. Proxy settings are ignored: through a proxy the client could not
// see the destination address.

var allowedLogHostRanges = [...][2]int{{0, 19}, {30, 49}, {100, 199}}

const (
	logHostPrefix = "productionresultssa"
	logHostSuffix = ".blob.core.windows.net"
	maxLocation   = 8192
)

// allowedLogHost reports whether host, already lowercased, is one of the
// exact allowed log-download hosts.
func allowedLogHost(host string) bool {
	if !strings.HasPrefix(host, logHostPrefix) || !strings.HasSuffix(host, logHostSuffix) {
		return false
	}
	num := host[len(logHostPrefix) : len(host)-len(logHostSuffix)]
	if num == "" || len(num) > 3 || (len(num) > 1 && num[0] == '0') {
		return false
	}
	n := 0
	for i := 0; i < len(num); i++ {
		if num[i] < '0' || num[i] > '9' {
			return false
		}
		n = n*10 + int(num[i]-'0')
	}
	for _, r := range allowedLogHostRanges {
		if n >= r[0] && n <= r[1] {
			return true
		}
	}
	return false
}

// dnsNameRE matches a lowercase DNS name with an alphabetic last label, so
// no IP address, port, underscore or other text matches.
var dnsNameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// redirectError explains why a log redirect was not followed. Host is set
// only when the destination parsed and named a host: to that host if it is a
// strict DNS name, otherwise to "withheld".
type redirectError struct {
	Reason string
	Host   string
}

func (e *redirectError) Error() string { return e.Reason }

// checkLogRedirect validates the Location of the job-log redirect. It never
// returns the URL's path or query in an error.
func checkLogRedirect(location string) (*url.URL, error) {
	if location == "" {
		return nil, &redirectError{Reason: "the redirect has no Location header"}
	}
	if len(location) > maxLocation {
		return nil, &redirectError{Reason: "the redirect Location is longer than 8192 bytes"}
	}
	for i := 0; i < len(location); i++ {
		if location[i] <= ' ' || location[i] > '~' {
			return nil, &redirectError{Reason: "the redirect Location is not printable ASCII"}
		}
	}
	u, err := url.Parse(location)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return nil, &redirectError{Reason: "the redirect Location is not an absolute URL"}
	}
	host := strings.ToLower(u.Hostname())
	shown := "withheld" // named only if it is a strict DNS name, never an address or other text
	if dnsNameRE.MatchString(host) {
		shown = host
	}
	switch {
	case u.Scheme != "https":
		return nil, &redirectError{Reason: "the redirect is not HTTPS", Host: shown}
	case u.User != nil:
		return nil, &redirectError{Reason: "the redirect carries user information", Host: shown}
	case u.Port() != "":
		return nil, &redirectError{Reason: "the redirect names an explicit port", Host: shown}
	case !allowedLogHost(host):
		return nil, &redirectError{Reason: "the redirect host is not in the allowed log-host list", Host: shown}
	}
	return u, nil
}

var (
	errNonPublicAddress = errors.New("destination address is not public")
	errPortNotAllowed   = errors.New("destination port is not 443")
)

// Special-purpose ranges that are never a public destination (IANA IPv4 and
// IPv6 special-purpose registries). NAT64 is handled separately.
var nonPublicPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96", "::1/128", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
		"2002::/16", "3fff::/20", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// publicAddr reports whether ip is a public unicast address. An address in
// the NAT64 well-known prefix is judged by the IPv4 address it embeds.
func publicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	if nat64.Contains(ip) {
		b := ip.As16()
		return publicAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}

// dialControl runs on every connection after name resolution and before
// connect, on the address actually used.
func dialControl(network, address string, _ syscall.RawConn) error {
	if network != "tcp4" && network != "tcp6" {
		return errNonPublicAddress
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errNonPublicAddress
	}
	if ap.Port() != 443 {
		return errPortNotAllowed
	}
	if !publicAddr(ap.Addr()) {
		return errNonPublicAddress
	}
	return nil
}

// NewTransport returns the production transport: direct connections only,
// public addresses on port 443 only, TLS 1.2 or later, no compression (so the
// counted body bytes are the bytes received), bounded response headers, and
// an HTTP/2 receive window of 64 KiB per stream instead of Go's 4 MiB, so the
// transport cannot buffer much more than the client has counted. Keep-alive
// is off: every request opens its own connection, so Go never resends a
// request on a reused connection without the probe counting it.
func NewTransport() *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: dialControl}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    10 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		HTTP2:                  &http.HTTP2Config{MaxReceiveBufferPerStream: 64 << 10},
	}
}
