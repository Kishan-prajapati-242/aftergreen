package github

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseRunURL(t *testing.T) {
	good := []struct {
		in   string
		want RunRef
	}{
		{"https://github.com/octo-org/demo/actions/runs/1001", RunRef{Owner: "octo-org", Repo: "demo", RunID: 1001}},
		{"https://github.com/octo-org/demo/actions/runs/1001/attempts/2", RunRef{Owner: "octo-org", Repo: "demo", RunID: 1001, Attempt: 2}},
		{"https://github.com/A1/repo.name_x-y/actions/runs/9007199254740991", RunRef{Owner: "A1", Repo: "repo.name_x-y", RunID: 9007199254740991}},
	}
	for _, g := range good {
		got, err := ParseRunURL(g.in)
		if err != nil || got != g.want {
			t.Errorf("ParseRunURL(%q) = %+v, %v; want %+v", g.in, got, err, g.want)
		}
	}
	bad := []string{
		"",
		"http://github.com/octo-org/demo/actions/runs/1001",
		"HTTPS://github.com/octo-org/demo/actions/runs/1001",
		"https://GitHub.com/octo-org/demo/actions/runs/1001",
		"https://www.github.com/octo-org/demo/actions/runs/1001",
		"https://github.com:443/octo-org/demo/actions/runs/1001",
		"https://user@github.com/octo-org/demo/actions/runs/1001",
		"https://github.com@evil.example/octo-org/demo/actions/runs/1001",
		"https://github.com.evil.example/octo-org/demo/actions/runs/1001",
		"https://api.github.com/repos/octo-org/demo/actions/runs/1001",
		"https://github.com/octo-org/demo/actions/runs/1001/",
		"https://github.com/octo-org/demo/actions/runs/1001?pr=5",
		"https://github.com/octo-org/demo/actions/runs/1001#top",
		"https://github.com/octo-org/demo/actions/runs/1001/job/2001",
		"https://github.com/octo-org/demo/actions/runs/1001/attempts/",
		"https://github.com/octo-org/demo/actions/runs/1001/attempts/0",
		"https://github.com/octo-org/demo/actions/runs/1001/attempts/01",
		"https://github.com/octo-org/demo/actions/runs/0",
		"https://github.com/octo-org/demo/actions/runs/-5",
		"https://github.com/octo-org/demo/actions/runs/+5",
		"https://github.com/octo-org/demo/actions/runs/1e3",
		"https://github.com/octo-org/demo/actions/runs/9007199254740992",
		"https://github.com/octo-org/demo/actions/runs/99999999999999999999",
		"https://github.com/octo-org/demo/actions/workflows/1001",
		"https://github.com/octo-org/../actions/runs/1001",
		"https://github.com/octo-org/./actions/runs/1001",
		"https://github.com/octo-org//actions/runs/1001",
		"https://github.com/-octo/demo/actions/runs/1001",
		"https://github.com/octo_org/demo/actions/runs/1001",
		"https://github.com/" + strings.Repeat("a", 40) + "/demo/actions/runs/1001",
		"https://github.com/octo-org/" + strings.Repeat("r", 101) + "/actions/runs/1001",
		"https://github.com/octo-org/de%6do/actions/runs/1001",
		"https://github.com/octo-org/de mo/actions/runs/1001",
		"https://github.com/octo-org/de\x00mo/actions/runs/1001",
		"https://github.com/octo-org/d\u00E9mo/actions/runs/1001",
		`https://github.com\octo-org/demo/actions/runs/1001`,
		" https://github.com/octo-org/demo/actions/runs/1001",
	}
	for _, in := range bad {
		if got, err := ParseRunURL(in); err == nil {
			t.Errorf("ParseRunURL(%q) = %+v; want an error", in, got)
		}
	}
}

func TestParseID(t *testing.T) {
	for _, s := range []string{"1", "42", "9007199254740991"} {
		if _, err := ParseID(s); err != nil {
			t.Errorf("ParseID(%q): %v", s, err)
		}
	}
	for _, s := range []string{"", "0", "01", "-1", "+1", "1.0", "1e3", " 1", "9007199254740992", "18446744073709551616", "abc"} {
		if n, err := ParseID(s); err == nil {
			t.Errorf("ParseID(%q) = %d; want an error", s, n)
		}
	}
}

// The defaults are the documented network limits (docs/collector.md); a
// change here must be a deliberate design change.
func TestDefaultLimits(t *testing.T) {
	want := Limits{MaxRequests: 30, RequestTimeout: 15 * time.Second, Deadline: 90 * time.Second,
		MaxJSONBytes: 1 << 20, MaxLogBytes: 2 << 20, MaxTotalBytes: 8 << 20, MaxJobPages: 3}
	if got := DefaultLimits(); got != want {
		t.Fatalf("DefaultLimits() = %+v; want %+v", got, want)
	}
}

func TestAllowedLogHost(t *testing.T) {
	for _, n := range []string{"0", "9", "19", "30", "49", "100", "150", "199"} {
		if h := "productionresultssa" + n + ".blob.core.windows.net"; !allowedLogHost(h) {
			t.Errorf("%s should be an allowed host", h)
		}
	}
	for _, h := range []string{
		"productionresultssa20.blob.core.windows.net", "productionresultssa29.blob.core.windows.net",
		"productionresultssa50.blob.core.windows.net", "productionresultssa99.blob.core.windows.net",
		"productionresultssa200.blob.core.windows.net", "productionresultssa1000.blob.core.windows.net",
		"productionresultssa00.blob.core.windows.net", "productionresultssa07.blob.core.windows.net",
		"productionresultssa.blob.core.windows.net", "productionresultssax.blob.core.windows.net",
		"productionresultssa1.blob.core.windows.net.evil.example", "xproductionresultssa1.blob.core.windows.net",
		"productionresultssa1.blob.core.windows.net.", "evil.blob.core.windows.net", "blob.core.windows.net",
		"pipelinesghubeus1.actions.githubusercontent.com", "results-receiver.actions.githubusercontent.com",
		"api.github.com", "",
	} {
		if allowedLogHost(h) {
			t.Errorf("%q should not be an allowed host", h)
		}
	}
}

func TestCheckLogRedirect(t *testing.T) {
	for _, loc := range []string{
		"https://productionresultssa0.blob.core.windows.net/actions-results/a/job-logs.txt?sig=abc&se=x",
		"https://PRODUCTIONRESULTSSA199.blob.core.windows.net/x",
	} {
		if _, err := checkLogRedirect(loc); err != nil {
			t.Errorf("checkLogRedirect(%q): %v", loc, err)
		}
	}
	for _, loc := range []string{
		"",
		"/relative/job-logs.txt?sig=SECRET",
		"//productionresultssa0.blob.core.windows.net/x?sig=SECRET",
		"http://productionresultssa0.blob.core.windows.net/x?sig=SECRET",
		"ftp://productionresultssa0.blob.core.windows.net/x?sig=SECRET",
		"https://user:pw@productionresultssa0.blob.core.windows.net/x?sig=SECRET",
		"https://productionresultssa0.blob.core.windows.net:443/x?sig=SECRET",
		"https://productionresultssa0.blob.core.windows.net:8443/x?sig=SECRET",
		"https://productionresultssa0.blob.core.windows.net./x?sig=SECRET",
		"https://productionresultssa20.blob.core.windows.net/x?sig=SECRET",
		"https://evil.blob.core.windows.net/x?sig=SECRET",
		"https://evil.example/x?sig=SECRET",
		"https://20.60.0.1/x?sig=SECRET",
		"https://[::1]/x?sig=SECRET",
		"https://api.github.com/x?sig=SECRET",
		"https://productionresultssa0.blob.core.windows.net/x?sig=SECRET\u00E9",
		"https://productionresultssa0.blob.core.windows.net/x y?sig=SECRET",
		"https://productionresultssa0.blob.core.windows.net/" + strings.Repeat("a", 8200),
	} {
		u, err := checkLogRedirect(loc)
		if err == nil {
			t.Errorf("checkLogRedirect(%q) accepted %v", loc, u)
			continue
		}
		var re *redirectError
		if !errors.As(err, &re) {
			t.Errorf("checkLogRedirect(%q): error %T is not a redirectError", loc, err)
		}
		if strings.Contains(err.Error(), "SECRET") || strings.Contains(re.Host, "SECRET") {
			t.Errorf("checkLogRedirect(%q) error reveals the query: %q host %q", loc, err, re.Host)
		}
	}
}

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"8.8.8.8", "140.82.112.6", "1.1.1.1", "::ffff:8.8.8.8", "2606:4700:4700::1111", "64:ff9b::808:808"} {
		if !publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range []string{
		"0.0.0.0", "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.88.99.1", "192.168.1.1", "198.18.0.1",
		"198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::10.0.0.1",
		"64:ff9b::a00:1", "64:ff9b::7f00:1", "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1",
		"2002:c000:204::1", "3fff::1", "fc00::1", "fd12:3456::1", "fe80::1", "fe80::1%en0", "fec0::1", "ff02::1",
	} {
		if publicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be public", s)
		}
	}
}

func TestDialControl(t *testing.T) {
	cases := []struct {
		network, address string
		want             error
	}{
		{"tcp4", "140.82.112.6:443", nil},
		{"tcp6", "[2606:4700:4700::1111]:443", nil},
		{"tcp4", "140.82.112.6:80", errPortNotAllowed},
		{"tcp4", "127.0.0.1:443", errNonPublicAddress},
		{"tcp4", "10.0.0.1:443", errNonPublicAddress},
		{"tcp6", "[::1]:443", errNonPublicAddress},
		{"tcp6", "[fe80::1%en0]:443", errNonPublicAddress},
		{"tcp6", "[::ffff:192.168.0.1]:443", errNonPublicAddress},
		{"udp4", "8.8.8.8:443", errNonPublicAddress},
		{"tcp4", "not-an-address", errNonPublicAddress},
	}
	for _, c := range cases {
		if got := dialControl(c.network, c.address, nil); !errors.Is(got, c.want) {
			t.Errorf("dialControl(%s, %s) = %v; want %v", c.network, c.address, got, c.want)
		}
	}
}

// The production transport refuses non-public addresses and other ports in
// the dialer's Control hook, which runs before connect, so these dials send
// no packet. Even if that hook were broken, the addresses used here cannot
// reach a real host: loopback, and the documentation range 192.0.2.0/24
// (with a short deadline). The port check runs before the address check, so
// a non-public address on port 80 still tests it.
func TestNewTransport(t *testing.T) {
	tr := NewTransport()
	if tr.Proxy != nil || !tr.DisableCompression || tr.MaxResponseHeaderBytes != 64<<10 ||
		tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion < tls.VersionTLS12 || tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("transport settings: proxy set %v, compression disabled %v, header limit %d, TLS %+v",
			tr.Proxy != nil, tr.DisableCompression, tr.MaxResponseHeaderBytes, tr.TLSClientConfig)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dial := func(addr string, want error) {
		conn, err := tr.DialContext(ctx, "tcp", addr)
		if conn != nil {
			conn.Close()
		}
		if !errors.Is(err, want) {
			t.Errorf("dial %s: %v; want %v", addr, err, want)
		}
	}
	dial("127.0.0.1:443", errNonPublicAddress)
	dial("192.0.2.1:443", errNonPublicAddress)
	dial("127.0.0.1:80", errPortNotAllowed)
	dial("192.0.2.1:80", errPortNotAllowed)
	if !tr.DisableKeepAlives || tr.HTTP2 == nil || tr.HTTP2.MaxReceiveBufferPerStream != 64<<10 || !tr.ForceAttemptHTTP2 {
		t.Errorf("keep-alive disabled %v, HTTP/2 config %+v, HTTP/2 attempted %v", tr.DisableKeepAlives, tr.HTTP2, tr.ForceAttemptHTTP2)
	}
}

// A refused connection through the production transport reaches the report
// as its own code, through the same path a live request takes. Every
// address here is refused before connect, so no packet is sent.
func TestProductionTransportRefusals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, c := range []struct{ host, code string }{
		{"127.0.0.1", "non_public_address"},
		{"192.0.2.1", "non_public_address"},
		{"[::1]", "non_public_address"},
		{"127.0.0.1:80", "port_not_allowed"},
		{"192.0.2.1:8443", "port_not_allowed"},
	} {
		col := newCollector(ctx, DefaultLimits(), NewTransport())
		x, s := col.send("test", &url.URL{Scheme: "https", Host: c.host, Path: "/x"}, "GET /x", false, false)
		if x != nil {
			x.close()
			t.Fatalf("%s: a connection was made", c.host)
		}
		if s == nil || s.Code != c.code || col.reqs[0].Error != c.code {
			t.Errorf("%s: stop %+v; want %s", c.host, s, c.code)
		}
	}
}

// The network error categories never repeat the error's own text, which can
// hold the local address and port or a URL.
func TestFailureWithholdsErrorText(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("192.168.1.23"), Port: 52144}
	remote := &net.TCPAddr{IP: net.ParseIP("20.60.40.4"), Port: 443}
	col := newCollector(context.Background(), DefaultLimits(), nil)
	for _, c := range []struct {
		err    error
		code   string
		detail string
	}{
		{&net.OpError{Op: "read", Net: "tcp", Source: local, Addr: remote, Err: syscall.ECONNRESET}, "network_error", "the connection was reset"},
		{&net.OpError{Op: "dial", Net: "tcp", Source: local, Addr: remote, Err: syscall.ECONNREFUSED}, "network_error", "the connection was refused"},
		{&net.OpError{Op: "read", Net: "tcp", Source: local, Addr: remote, Err: os.ErrDeadlineExceeded}, "network_timeout", "timed out"},
		{&net.DNSError{Err: "no such host", Name: "productionresultssa7.blob.core.windows.net"}, "network_error", "could not be resolved"},
		{fmt.Errorf("wrapped: %w", io.ErrUnexpectedEOF), "network_error", "closed before the response was complete"},
		{&url.Error{Op: "Get", URL: "https://x.example/p?sig=SIGNATURE-SENTINEL", Err: errors.New("malformed HTTP response \"\\x16\\x03\" from 192.168.1.23")}, "network_error", "withheld"},
	} {
		s := col.failure("log_download", context.Background(), c.err)
		text := s.Code + " " + s.Detail
		if s.Code != c.code || !strings.Contains(s.Detail, c.detail) ||
			strings.Contains(text, "192.168") || strings.Contains(text, "20.60") || strings.Contains(text, "SIGNATURE") || strings.Contains(text, "x.example") {
			t.Errorf("failure(%v) = %s: %s; want %s containing %q and no address or URL", c.err, s.Code, s.Detail, c.code, c.detail)
		}
	}
}

func TestSafeText(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"plain name (20)", 100, "plain name (20)"},
		{"a\x1b[31mb", 100, `a\u{001B}[31mb`},
		{"tab\there", 100, `tab\u{0009}here`},
		{"\u202Eevil", 100, `\u{202E}evil`},
		{"zero\u200Bwidth", 100, `zero\u{200B}width`},
		{"x\u2028y", 100, `x\u{2028}y`},
		{"c1\u009bz", 100, `c1\u{009B}z`},
		{"tag\U000E0041", 100, `tag\u{E0041}`},
		{"bad\xffbyte", 100, "bad\uFFFDbyte"},
		{"a\uFE0Fb", 100, `a\u{FE0F}b`},             // variation selector
		{"a\U000E0100b", 100, `a\u{E0100}b`},        // variation selector supplement
		{"a\u034Fb", 100, `a\u{034F}b`},             // combining grapheme joiner
		{"a\u3164b", 100, `a\u{3164}b`},             // Hangul filler
		{"a\u00ADb", 100, `a\u{00AD}b`},             // soft hyphen
		{"\u05D0\u05D1 12", 100, "\u05D0\u05D1 12"}, // right-to-left letters are kept
		{strings.Repeat("a", 12), 10, "aaaaaaaaaa[cut]"},
		{"ab\u202E", 4, "ab[cut]"},
	}
	for _, c := range cases {
		if got := safeText(c.in, c.max); got != c.want {
			t.Errorf("safeText(%q, %d) = %q; want %q", c.in, c.max, got, c.want)
		}
	}
}

// Line counting matches contracts/bundle-v0.md section 4, across write
// boundaries.
func TestLineCounter(t *testing.T) {
	cases := []struct {
		parts []string
		want  int64
	}{
		{nil, 0}, {[]string{""}, 0}, {[]string{"a"}, 1}, {[]string{"a\n"}, 1}, {[]string{"a\nb"}, 2},
		{[]string{"a\nb\n"}, 2}, {[]string{"a\r\nb\r\n"}, 2}, {[]string{"\n"}, 1}, {[]string{"\n\n"}, 2},
		{[]string{"a\rb"}, 1}, {[]string{"a", "\n", "b"}, 2}, {[]string{"a\n", ""}, 1}, {[]string{"a", "\n"}, 1},
	}
	for _, c := range cases {
		var l lineCounter
		for _, p := range c.parts {
			l.write([]byte(p))
		}
		if got := l.lines(); got != c.want {
			t.Errorf("lines(%q) = %d; want %d", c.parts, got, c.want)
		}
	}
}
