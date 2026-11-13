package github

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Optional authentication. The only source is the github.com login stored by
// the GitHub CLI; token environment variables that gh would prefer are
// removed from its environment. The credential is held in memory only. It is
// obtained only after the run is shown public and one failed job is
// selected, and sent as an Authorization header only on the job-log GET to
// api.github.com (see send): never on a metadata request, never to the
// log-download host, never to another process, and never into a report or
// bundle.

// credential is a GitHub API token. The token is held only inside a
// closure, which reflection cannot look into: printing a struct that holds a
// credential, with any verb, shows at most a function address. The
// credential's own formatting, printing and marshalling methods yield a mask.
type credential struct{ secret func() string }

const credentialMask = "[credential]"

func newCredential(token string) credential {
	return credential{secret: func() string { return token }}
}

func (c credential) token() string {
	if c.secret == nil {
		return ""
	}
	return c.secret()
}

func (c credential) usable() bool { return tokenRE.MatchString(c.token()) }

func (credential) String() string               { return credentialMask }
func (credential) GoString() string             { return credentialMask }
func (credential) Format(f fmt.State, _ rune)   { io.WriteString(f, credentialMask) }
func (credential) MarshalText() ([]byte, error) { return []byte(credentialMask), nil }
func (credential) MarshalJSON() ([]byte, error) { return []byte(`"` + credentialMask + `"`), nil }

// tokenRE accepts the character set and length of GitHub's token formats
// (gho_, ghp_, github_pat_ and others, and 40-character legacy tokens).
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_]{20,255}$`)

// credentialSource supplies the credential for an authenticated probe.
type credentialSource interface {
	name() string // shown in the report as "auth"
	credential(ctx context.Context) (credential, error)
}

// credentialError carries one of this package's fixed reasons. A reason is
// never text from a child process or a server.
type credentialError struct{ reason string }

func (e *credentialError) Error() string { return e.reason }

const (
	ghTimeout   = 10 * time.Second
	ghMaxOutput = 4 << 10
)

// ghCLI is the github.com login stored by the GitHub CLI. It runs
// `gh auth token --hostname github.com` as a child process, never through a
// shell. Its stdin is empty, so gh cannot prompt; at most 4 KiB of its stdout
// is kept and read only for the token; its stderr is discarded. The update
// notifier and prompts are turned off, and the variables in tokenEnv are
// removed, because gh would print one of them instead of its stored login. It
// does not install gh or start a login. The token is never passed to another
// process.
type ghCLI struct {
	// Test hooks; zero in production.
	lookPath func(file string) (string, error)
	command  func(ctx context.Context, name string, args ...string) *exec.Cmd
	timeout  time.Duration
}

func (ghCLI) name() string { return "gh" }

func (g ghCLI) credential(ctx context.Context) (credential, error) {
	look := exec.LookPath // refuses a relative match found through "." in PATH
	if g.lookPath != nil {
		look = g.lookPath
	}
	path, err := look("gh")
	if err != nil {
		return credential{}, &credentialError{"the GitHub CLI (gh) was not found on PATH"}
	}
	timeout := ghTimeout
	if g.timeout > 0 {
		timeout = g.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	mk := exec.CommandContext
	if g.command != nil {
		mk = g.command
	}
	cmd := mk(ctx, path, "auth", "token", "--hostname", "github.com")
	cmd.Env = childEnv(cmd.Environ())
	cmd.Stdin = nil // the null device
	out := &cappedBuffer{max: ghMaxOutput}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return credential{}, &credentialError{"gh did not answer within its time limit"}
		}
		return credential{}, &credentialError{"gh did not return a github.com credential (it may not be logged in)"}
	}
	if out.over {
		return credential{}, &credentialError{"gh printed more than a token"}
	}
	token := bytes.TrimSuffix(bytes.TrimSuffix(out.buf.Bytes(), []byte("\n")), []byte("\r"))
	c := newCredential(string(token))
	if !c.usable() {
		return credential{}, &credentialError{"gh printed something that is not a token"}
	}
	return c, nil
}

// tokenEnv are the variables gh documents as taking precedence over its
// stored credentials.
var tokenEnv = []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// childEnv is env without tokenEnv, with gh's prompts and update notifier off.
func childEnv(env []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if name, _, _ := strings.Cut(kv, "="); slices.Contains(tokenEnv, name) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "GH_NO_UPDATE_NOTIFIER=1", "GH_PROMPT_DISABLED=1")
}

// cappedBuffer keeps at most max bytes and records whether more arrived.
type cappedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); len(p) > room {
		b.over = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}
