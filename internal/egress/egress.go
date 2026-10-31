// Package egress is the console's only way out to a remote log backend: an
// HTTP client whose dialer is pinned to the configured host and port, that
// uses no proxy and follows no redirect, sends only the requests of an
// allowlist (method and path, segment by segment), caps every response,
// and checks the server's certificate as the profile's tls mode says. It
// also probes whether a backend answers a data read without credentials,
// which a production profile refuses.
//
// The console reaches a backend only through the Docker network the human
// names with LOCKLOG_NETWORK (no network otherwise). Whether agents can
// also reach that network, or the backend's unauthenticated ports, is a
// deployment precondition, not something this package can see. The pin is
// in-process: a parser exploit in the console could still use the network
// the console is on.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	kconfig "github.com/DavidGodefroid/lockkit/config"

	"github.com/DavidGodefroid/locklog/internal/config"
)

// MaxResponseBytes caps one response body (design: 64 MiB per response).
const MaxResponseBytes = 64 << 20

// ErrNotAllowed is returned for a request outside the allowlist.
var ErrNotAllowed = errors.New("egress: request not in the allowlist")

// ErrResponseTooLarge is returned when a body passes MaxResponseBytes.
var ErrResponseTooLarge = errors.New("egress: response larger than the cap")

// Route is one allowed request: a method and a path pattern relative to
// the source URL's path, its segments either literal or "{name}" (one
// non-empty segment, no "." or "..").
type Route struct {
	Method string
	Path   string
}

// Allowlist is a compiled set of routes.
type Allowlist struct {
	routes []compiledRoute
}

type compiledRoute struct {
	method string
	segs   []string
}

// NewAllowlist compiles routes. It panics on a malformed route: the lists
// are constants of the code.
func NewAllowlist(routes ...Route) *Allowlist {
	a := &Allowlist{}
	for _, r := range routes {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			panic("egress: route method " + r.Method)
		}
		if !strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, "//") {
			panic("egress: route path " + r.Path)
		}
		a.routes = append(a.routes, compiledRoute{method: r.Method, segs: strings.Split(r.Path[1:], "/")})
	}
	return a
}

// Allows reports whether method and path (relative to the base path, raw
// and unescaped forms both checked) are in the list.
func (a *Allowlist) Allows(method, path string) bool {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") {
		return false
	}
	segs := strings.Split(path[1:], "/")
	for _, r := range a.routes {
		if r.method != method || len(r.segs) != len(segs) {
			continue
		}
		ok := true
		for i, s := range r.segs {
			if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
				if segs[i] == "" || segs[i] == "." || segs[i] == ".." {
					ok = false
					break
				}
				continue
			}
			if segs[i] != s {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// LokiRoutes are the only Loki requests locklog sends (read endpoints).
var LokiRoutes = NewAllowlist(
	Route{http.MethodGet, "/loki/api/v1/query_range"},
	Route{http.MethodGet, "/loki/api/v1/query"},
	Route{http.MethodGet, "/loki/api/v1/labels"},
	Route{http.MethodGet, "/loki/api/v1/label/{name}/values"},
	Route{http.MethodGet, "/loki/api/v1/series"},
	Route{http.MethodGet, "/loki/api/v1/index/stats"},
	Route{http.MethodGet, "/loki/api/v1/index/volume"},
	Route{http.MethodGet, "/ready"},
	Route{http.MethodGet, "/loki/api/v1/status/buildinfo"},
)

// Credentials are what the console obtained for a source (asked or read
// from Vault). The zero value sends none.
type Credentials struct {
	User   string
	Secret string
}

// Client sends the allowed requests of one remote source.
type Client struct {
	base      *url.URL
	addr      string // the pinned host:port
	allow     *Allowlist
	auth      string
	creds     Credentials
	orgID     string
	http      *http.Client
	userAgent string
	maxBody   int64
}

// Options tune a client; tests set them.
type Options struct {
	// Resolver resolves host names (default net.DefaultResolver).
	Resolver *net.Resolver
	// RootCAs, when set, replaces the system roots (tests).
	RootCAs *x509.CertPool
	// Timeout bounds one request (default 60 s).
	Timeout time.Duration
	// AllowLinkLocal lets the dialer reach link-local addresses (tests
	// only: the cloud metadata service lives there).
	AllowLinkLocal bool
	// MaxResponseBytes overrides MaxResponseBytes (tests).
	MaxResponseBytes int64
}

// New builds the client of a remote source. creds are the source's
// secret; they are never sent by Probe.
func New(r *config.Remote, allow *Allowlist, creds Credentials, opt Options) (*Client, error) {
	if r == nil {
		return nil, errors.New("egress: not a remote source")
	}
	u, err := url.Parse(r.URL)
	if err != nil || u.Hostname() == "" {
		return nil, errors.New("egress: invalid source url")
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	tlsConf, err := tlsConfig(r, u, opt)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	c := &Client{base: u, addr: addr, allow: allow, auth: r.Auth, creds: creds, orgID: r.OrgID, userAgent: "locklog", maxBody: MaxResponseBytes}
	if opt.MaxResponseBytes > 0 {
		c.maxBody = opt.MaxResponseBytes
	}
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	resolver := opt.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		// No proxy: HTTP_PROXY and friends never apply.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, a string) (net.Conn, error) {
			if a != addr {
				return nil, fmt.Errorf("egress: dial %s refused: the source is pinned to %s", a, addr)
			}
			host, p, _ := net.SplitHostPort(a)
			ips, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("egress: resolve %s: %w", host, err)
			}
			var last error
			for _, ip := range ips {
				if !opt.AllowLinkLocal && (ip.IP.IsLinkLocalUnicast() || ip.IP.IsLinkLocalMulticast()) {
					last = fmt.Errorf("egress: %s resolves to a link-local address, refused", host)
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), p))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			if last == nil {
				last = fmt.Errorf("egress: %s has no address", host)
			}
			return nil, last
		},
		TLSClientConfig:       tlsConf,
		ForceAttemptHTTP2:     true,
		MaxIdleConnsPerHost:   4,
		ResponseHeaderTimeout: timeout,
		DisableCompression:    false,
	}
	c.http = &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("egress: redirects are not followed")
		},
	}
	return c, nil
}

func tlsConfig(r *config.Remote, u *url.URL, opt Options) (*tls.Config, error) {
	if u.Scheme != "https" {
		return nil, nil
	}
	conf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: opt.RootCAs}
	if r.TLSCA != "" {
		pem, err := os.ReadFile(r.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("egress: tls_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("egress: tls_ca holds no PEM certificate")
		}
		conf.RootCAs = pool
	}
	if r.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(r.TLSCert, r.TLSKey)
		if err != nil {
			return nil, errors.New("egress: tls_cert / tls_key: cannot load the client certificate")
		}
		conf.Certificates = []tls.Certificate{cert}
	}
	switch {
	case r.TLS == kconfig.TLSVerifyFull:
	case r.TLS == kconfig.TLSVerifyCA || (r.TLS == kconfig.TLSRequire && r.TLSCA != ""):
		// The chain, not the name: verified by hand.
		roots := conf.RootCAs
		conf.InsecureSkipVerify = true
		conf.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("egress: no server certificate")
			}
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter})
			return err
		}
	case r.TLS == kconfig.TLSRequire:
		// Encrypted, not verified: refused on production by the config.
		conf.InsecureSkipVerify = true
	default:
		return nil, fmt.Errorf("egress: tls mode %s does not apply to https", r.TLS)
	}
	return conf, nil
}

// request builds a request for path (relative to the source URL's path)
// with query q, checked against the allowlist.
func (c *Client) request(ctx context.Context, method, path string, q url.Values, body io.Reader) (*http.Request, error) {
	if !c.allow.Allows(method, path) {
		return nil, fmt.Errorf("%w: %s %s", ErrNotAllowed, method, path)
	}
	u := *c.base
	u.Path = strings.TrimSuffix(c.base.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	// The URL as sent is the URL as checked: no escape changes its path.
	if req.URL.EscapedPath() != (&url.URL{Path: u.Path}).EscapedPath() || req.URL.Host != c.base.Host {
		return nil, fmt.Errorf("%w: %s %s", ErrNotAllowed, method, path)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-Query-Tags", "source=locklog")
	return req, nil
}

func (c *Client) authorize(req *http.Request) {
	switch c.auth {
	case config.AuthBasic:
		req.SetBasicAuth(c.creds.User, c.creds.Secret)
	case config.AuthBearer:
		req.Header.Set("Authorization", "Bearer "+c.creds.Secret)
	}
	if c.orgID != "" {
		req.Header.Set("X-Scope-OrgID", c.orgID)
	}
}

// Response is a capped response: the status and the body.
type Response struct {
	Status int
	Body   []byte
}

// Get sends an allowed GET with the source's credentials and returns the
// capped body. A non-2xx status is an error whose text never quotes the
// body.
func (c *Client) Get(ctx context.Context, path string, q url.Values) (Response, error) {
	req, err := c.request(ctx, http.MethodGet, path, q, nil)
	if err != nil {
		return Response{}, err
	}
	c.authorize(req)
	return c.do(req)
}

func (c *Client) do(req *http.Request) (Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			// Never the URL: its query carries the selector.
			return Response{}, fmt.Errorf("egress: %s %s: %w", req.Method, req.URL.Path, ue.Err)
		}
		return Response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return Response{}, fmt.Errorf("egress: %s %s: reading the response: %w", req.Method, req.URL.Path, err)
	}
	if int64(len(body)) > c.maxBody {
		return Response{}, ErrResponseTooLarge
	}
	r := Response{Status: resp.StatusCode, Body: body}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return r, fmt.Errorf("egress: %s %s: status %s", req.Method, req.URL.Path, strconv.Itoa(resp.StatusCode))
	}
	return r, nil
}

// Recognizer reports whether a 2xx body is the backend's data answer (and
// not, say, a login page).
type Recognizer func(body []byte) bool

// Probe sends one read of a data endpoint WITHOUT credentials (no
// Authorization, no X-Scope-OrgID), follows no redirect, and reports
// whether the backend answered it: a 2xx with a body recognize accepts. A
// production profile refuses such a backend: anyone on its network reads
// the logs without the console.
func (c *Client) Probe(ctx context.Context, path string, recognize Recognizer) (bool, error) {
	req, err := c.request(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return false, err
	}
	r, err := c.do(req)
	if err != nil {
		if r.Status != 0 {
			return false, nil // refused (401, 403, a redirect): authenticated
		}
		if strings.Contains(err.Error(), "redirects are not followed") {
			return false, nil
		}
		return false, err
	}
	return recognize(r.Body), nil
}

// LokiProbePath is the data endpoint the unauthenticated-read check reads.
const LokiProbePath = "/loki/api/v1/labels"

// LokiData recognizes a Loki data answer: {"status":"success","data":[...]}.
func LokiData(body []byte) bool {
	s := strings.Join(strings.Fields(string(body)), "")
	return strings.HasPrefix(s, `{"status":"success","data":[`) || (strings.Contains(s, `"status":"success"`) && strings.Contains(s, `"data":[`))
}

// CheckUnauthenticated is the production check of a Loki source: it
// refuses the source when the probe reads data without credentials.
func CheckUnauthenticated(ctx context.Context, c *Client, production bool) error {
	if !production {
		return nil
	}
	open, err := c.Probe(ctx, LokiProbePath, LokiData)
	if err != nil {
		return fmt.Errorf("egress: unauthenticated-read check: %w", err)
	}
	if open {
		return errors.New("egress: the backend answers a data read without credentials: a production profile refuses it (put it behind an authenticating proxy and unpublish its port)")
	}
	return nil
}

// ExtraInterfaces lists the network interfaces of sysClassNet
// (/sys/class/net) other than the loopback: none in a console started
// with --network none.
func ExtraInterfaces(sysClassNet string) ([]string, error) {
	entries, err := os.ReadDir(sysClassNet)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.Name() != "lo" {
			out = append(out, e.Name())
		}
	}
	return out, nil
}
