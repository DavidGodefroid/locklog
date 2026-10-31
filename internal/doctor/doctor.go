// Package doctor is `locklog doctor`: an advisory check of what the
// agent's account can reach where it runs, around the console. It is not
// a boundary: a clean report does not make a placement safe, and the
// console enforces nothing doctor says.
//
// Findings are what the agent could use to read logs, or the console's
// secrets, without the console: the Docker engine, the log groups, sudo,
// root, the journal and Docker's state, a backend that answers without
// credentials, the cloud's metadata credentials. Residuals are the
// console's own weak spots (Landlock, a shareable IPC namespace, swarm
// mode). On a production profile the findings are red and doctor exits
// non-zero.
//
// No probe's response body is ever printed: a status code, and whether the
// API was recognised, only.
package doctor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/egress"
	"github.com/DavidGodefroid/locklog/internal/hostfacts"
)

// Item is one line of the report.
type Item struct {
	// Finding is something the agent can use; a non-finding is "ok" (or
	// "info" when unknown).
	Finding bool
	Unknown bool
	Text    string
	Remedy  string
}

// Report is doctor's result.
type Report struct {
	Findings  []Item
	Residuals []Item
	// Production: the findings are red, and doctor fails.
	Production bool
	Profile    string
}

// Count is the number of findings.
func (r Report) Count() int {
	n := 0
	for _, it := range r.Findings {
		if it.Finding {
			n++
		}
	}
	return n
}

// Endpoint is a cloud metadata path probed without credentials. No probe
// asks for a token: it would mint one.
type Endpoint struct {
	Cloud  string
	Method string
	URL    string
	Header map[string]string
	// Answers is the finding when it answers 200 (default: its
	// credentials are handed out).
	Answers string
}

// Metadata are the clouds' metadata paths: a 200 means this account can
// list the instance's credentials (AWS, GCP), or reach the service that
// hands out its identity's tokens (Azure: its instance document, which
// issues nothing).
var Metadata = []Endpoint{
	{Cloud: "AWS", Method: http.MethodGet, URL: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
	{Cloud: "GCP", Method: http.MethodGet, URL: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
		Header: map[string]string{"Metadata-Flavor": "Google"}},
	{Cloud: "Azure", Method: http.MethodGet, URL: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		Header:  map[string]string{"Metadata": "true"},
		Answers: "the Azure metadata service answers (status %d): an identity may be available to the agent (a managed identity's tokens come from it)"},
}

// Options of one doctor run.
type Options struct {
	Facts hostfacts.Facts
	// Profiles are the configured profiles; Profile pins one ("" : all,
	// production when any is).
	Profiles map[string]config.Profile
	Profile  string
	// Landlock returns the ABI and, when 0, why (landlock.ABI).
	Landlock func() (int, string)
	// Metadata are the endpoints probed (default Metadata).
	Metadata []Endpoint
	// Timeout of one probe (default 2 s).
	Timeout time.Duration
}

// Run checks and returns the report.
func Run(ctx context.Context, o Options) (Report, error) {
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	if o.Metadata == nil {
		o.Metadata = Metadata
	}
	var r Report
	profiles := o.Profiles
	if o.Profile != "" {
		p, ok := o.Profiles[o.Profile]
		if !ok {
			return r, fmt.Errorf("doctor: no profile %q", o.Profile)
		}
		profiles = map[string]config.Profile{p.Name: p}
		r.Profile = p.Name
	}
	names := make([]string, 0, len(profiles))
	for n, p := range profiles {
		names = append(names, n)
		if p.Production {
			r.Production = true
			if r.Profile == "" {
				r.Profile = n
			}
		}
	}
	sort.Strings(names)

	f := o.Facts
	add := func(it Item) { r.Findings = append(r.Findings, it) }
	add(dockerItem(f))
	for _, g := range []struct{ name, why, remedy string }{
		{"docker", "the docker group is root on this host: it starts a container that reads every log",
			"take the agent's account out of the docker group (sudo gpasswd -d $USER docker), or run the agent in a container of its own (locklog setup --agent container)"},
		{"adm", "the adm group reads /var/log",
			"take the agent's account out of adm (sudo gpasswd -d $USER adm): the console reads the logs for it"},
		{"systemd-journal", "the systemd-journal group reads the whole journal",
			"take the agent's account out of systemd-journal (sudo gpasswd -d $USER systemd-journal)"},
	} {
		switch {
		case f.Groups == nil:
			add(Item{Unknown: true, Text: "group " + g.name + ": the account's groups are unknown"})
		case f.InGroup(g.name):
			add(Item{Finding: true, Text: "group " + g.name + ": the agent's account is a member; " + g.why, Remedy: g.remedy})
		default:
			add(Item{Text: "group " + g.name + ": not a member"})
		}
	}
	switch f.Sudo {
	case hostfacts.SudoNoPasswd:
		add(Item{Finding: true, Text: "sudo -n true succeeds: the agent can become root without a password",
			Remedy: "remove the NOPASSWD rule (or the sudo timestamp) of the agent's account, or run the agent in an account without sudo"})
	case hostfacts.SudoPassword:
		add(Item{Text: "sudo asks for a password (sudo -n fails)"})
	case hostfacts.SudoAbsent:
		add(Item{Text: "no sudo"})
	default:
		add(Item{Unknown: true, Text: "sudo: unknown"})
	}
	switch {
	case f.EUID == 0:
		add(Item{Finding: true, Text: "euid 0: the agent runs as root, which reads everything the console guards",
			Remedy: "run the agent in an unprivileged account"})
	case f.EUID > 0:
		add(Item{Text: fmt.Sprintf("euid %d (not root)", f.EUID)})
	default:
		add(Item{Unknown: true, Text: "euid: unknown"})
	}
	for _, p := range hostfacts.SensitivePaths {
		switch {
		case contains(f.Readable, p):
			add(Item{Finding: true, Text: p + " is readable by the agent's account",
				Remedy: "remove the account's access to " + p + " (its group or an ACL): only the console should read it"})
		case contains(f.Unreadable, p):
			add(Item{Text: p + " is not readable"})
		}
	}
	for _, c := range f.CredFiles {
		add(Item{Finding: true, Text: "cloud credentials file " + c + " is present: the agent can use them to read logs at the provider",
			Remedy: "keep cloud credentials out of the agent's account (another account, or short-lived credentials the agent cannot reach)"})
	}

	// Probes, concurrently, each bounded: backends, then metadata.
	type probe struct {
		label string
		fn    func(context.Context) Item
	}
	var probes []probe
	for _, n := range names {
		for _, s := range profiles[n].Sources {
			if s.Remote == nil {
				continue
			}
			src, label := s, n+"/"+s.Name
			probes = append(probes, probe{label, func(ctx context.Context) Item { return backendItem(ctx, label, src, o.Timeout) }})
		}
	}
	for _, e := range o.Metadata {
		probes = append(probes, probe{e.Cloud, func(ctx context.Context) Item { return metadataItem(ctx, e, o.Timeout) }})
	}
	items := make([]Item, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func() { defer wg.Done(); items[i] = p.fn(ctx) }()
	}
	wg.Wait()
	r.Findings = append(r.Findings, items...)

	// Residuals: the console's guards.
	if o.Landlock != nil {
		abi, why := o.Landlock()
		if abi > 0 {
			r.Residuals = append(r.Residuals, Item{Text: fmt.Sprintf("Landlock ABI %d: the console confines its own file access", abi)})
		} else {
			r.Residuals = append(r.Residuals, Item{Finding: true, Text: "Landlock is unavailable (" + why + "): a docker source relies on the mounts alone",
				Remedy: "a kernel with Landlock (5.13 or later, lsm=landlock), not disabled by the container runtime's seccomp profile"})
		}
	}
	for _, c := range f.IPCShareable {
		r.Residuals = append(r.Residuals, Item{Finding: true, Text: "container " + c + " runs with IpcMode shareable: its /dev/shm mount can appear in the console's bound containers root",
			Remedy: "use --ipc private (the default) unless another container joins it; Landlock guards the console against it"})
	}
	switch f.Swarm {
	case "":
	case "active":
		r.Residuals = append(r.Residuals, Item{Finding: true, Text: "swarm mode is active: services' secrets are mounted under the containers root",
			Remedy: "keep docker sources off a swarm node, or leave the swarm (docker swarm leave)"})
	default:
		r.Residuals = append(r.Residuals, Item{Text: "swarm mode " + f.Swarm})
	}
	return r, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func dockerItem(f hostfacts.Facts) Item {
	host := ""
	if f.DockerHost {
		host = " (DOCKER_HOST is set)"
	}
	switch f.Docker {
	case hostfacts.DockerReachable:
		return Item{Finding: true, Text: "the Docker engine answers the agent's account" + host + ": it can start a container that reads every log and the console's volumes",
			Remedy: "run the agent where the Docker socket and DOCKER_HOST are out of reach (not in the docker group, no socket mounted), or in a container of its own (locklog setup --agent container)"}
	case hostfacts.DockerUnreachable:
		return Item{Text: "no Docker engine answers the agent's account" + host}
	case hostfacts.DockerAbsent:
		return Item{Text: "no Docker client or socket here"}
	}
	return Item{Unknown: true, Text: "Docker: unknown"}
}

// client is a probe's HTTP client: no proxy, no redirect, no credentials,
// and no certificate check (the question is whether anyone can read, and
// an agent need not check either).
func client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:           nil,
			DialContext:     (&net.Dialer{Timeout: timeout}).DialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// maxProbeBody is the most of a body read to recognise the API (a
// mapping answer can be long); it is never printed.
const maxProbeBody = 1 << 20

// probeAPI is the data read of a source kind without credentials: its
// path, the API's name and how its data answer is recognised (the
// console's production check, egress, reads the same).
func probeAPI(s config.Source) (path, api string, recognize egress.Recognizer, err error) {
	switch s.Kind {
	case config.KindLoki:
		return egress.LokiProbePath, "Loki", egress.LokiData, nil
	case config.KindElastic, config.KindOpenSearch:
		p, err := egress.ElasticProbePath(s.Remote.Indices)
		api = "Elasticsearch"
		if s.Kind == config.KindOpenSearch {
			api = "OpenSearch"
		}
		return p, api, egress.ElasticData, err
	}
	return "", "", nil, fmt.Errorf("kind %s", s.Kind)
}

// backendItem probes a data read of a remote source without credentials:
// Loki's label list, the mappings of an Elasticsearch / OpenSearch
// source's indices.
func backendItem(ctx context.Context, label string, s config.Source, timeout time.Duration) Item {
	u, err := url.Parse(s.Remote.URL)
	if err != nil {
		return Item{Unknown: true, Text: "backend " + label + ": its url does not parse"}
	}
	shown := u.Scheme + "://" + u.Host
	path, api, recognize, err := probeAPI(s)
	if err != nil {
		return Item{Unknown: true, Text: "backend " + label + " (" + shown + "): no probe for this kind"}
	}
	u = u.JoinPath(strings.Split(strings.TrimPrefix(path, "/"), "/")...)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Item{Unknown: true, Text: "backend " + label + ": " + shown}
	}
	resp, err := client(timeout).Do(req)
	if err != nil {
		return Item{Text: "backend " + label + " (" + shown + "): not reachable from here"}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
	recognised := resp.StatusCode == http.StatusOK && err == nil && len(body) <= maxProbeBody && recognize(body)
	switch {
	case recognised:
		remedy := "put it behind authentication (locklog setup --loki-proxy for a Compose Loki), or out of the agent's network"
		if s.Kind != config.KindLoki {
			remedy = "turn its security on (authentication for every read), or keep it out of the agent's network"
		}
		return Item{Finding: true, Text: fmt.Sprintf("backend %s (%s) answers %s read without credentials (status %d): the agent can read it directly", label, shown, article(api), resp.StatusCode),
			Remedy: remedy}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Item{Text: fmt.Sprintf("backend %s (%s) needs credentials (status %d)", label, shown, resp.StatusCode)}
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return Item{Finding: true, Text: fmt.Sprintf("backend %s (%s) answers without credentials (status %d, API not recognised)", label, shown, resp.StatusCode),
			Remedy: "check what it serves without credentials; put it behind authentication"}
	}
	return Item{Text: fmt.Sprintf("backend %s (%s): status %d without credentials", label, shown, resp.StatusCode)}
}

func article(api string) string {
	if strings.HasPrefix(api, "E") || strings.HasPrefix(api, "O") {
		return "an " + api
	}
	return "a " + api
}

// metadataItem probes one cloud metadata credential path.
func metadataItem(ctx context.Context, e Endpoint, timeout time.Duration) Item {
	req, err := http.NewRequestWithContext(ctx, e.Method, e.URL, nil)
	if err != nil {
		return Item{Unknown: true, Text: e.Cloud + " metadata: bad endpoint"}
	}
	for k, v := range e.Header {
		req.Header.Set(k, v)
	}
	resp, err := client(timeout).Do(req)
	if err != nil {
		return Item{Text: e.Cloud + " metadata credentials: not reachable"}
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		text := fmt.Sprintf("%s metadata credentials answer (status %d): the agent can take the instance's cloud identity", e.Cloud, resp.StatusCode)
		if e.Answers != "" {
			text = fmt.Sprintf(e.Answers, resp.StatusCode)
		}
		return Item{Finding: true, Text: text,
			Remedy: "block the metadata service for the agent (a firewall rule, IMDSv2 with hop limit 1, no instance identity) or run it where it is not reachable"}
	}
	return Item{Text: fmt.Sprintf("%s metadata credentials: status %d", e.Cloud, resp.StatusCode)}
}

// Print writes the report and returns the exit code: 1 when a production
// profile has findings, else 0.
func Print(w io.Writer, r Report) int {
	fmt.Fprintln(w, "locklog doctor: what the agent's account can reach here (advisory: a check, not a boundary)")
	mark := func(it Item, residual bool) string {
		switch {
		case it.Finding && r.Production && !residual:
			return "RED "
		case it.Finding:
			return "warn"
		case it.Unknown:
			return "?   "
		}
		return "ok  "
	}
	section := func(items []Item, residual bool) {
		for _, it := range items {
			fmt.Fprintf(w, "  %s  %s\n", mark(it, residual), it.Text)
			if it.Finding && it.Remedy != "" {
				fmt.Fprintf(w, "        remedy: %s\n", it.Remedy)
			}
		}
	}
	fmt.Fprintln(w)
	section(r.Findings, false)
	fmt.Fprintln(w, "\nresiduals (the console's own guards; warnings, whatever the profile):")
	section(r.Residuals, true)
	n := r.Count()
	fmt.Fprintln(w)
	switch {
	case n == 0:
		fmt.Fprintln(w, "no finding")
	case r.Production:
		fmt.Fprintf(w, "%d %s on production profile %s: fix them, or run the agent in a container of its own (locklog setup --agent container)\n", n, plural(n, "finding"), r.Profile)
		return 1
	default:
		fmt.Fprintf(w, "%d %s (no production profile: warnings)\n", n, plural(n, "finding"))
	}
	return 0
}

func plural(n int, s string) string {
	if n == 1 {
		return s
	}
	return s + "s"
}
