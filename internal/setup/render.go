package setup

import (
	"fmt"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/config"
)

// Plan is the config setup writes.
type Plan struct {
	// Profile is the main profile's name; the containers go to
	// Profile-docker (a docker source needs a console of its own), a
	// proxied Loki to Profile-loki (a console on the Compose network).
	Profile    string
	Production bool
	Detected   Detected
	// LokiProxy, when set, is the proxied Loki's source.
	LokiProxy *LokiSource
}

// LokiSource is the profile entry of a Loki behind the generated proxy.
type LokiSource struct {
	URL, User, CACert string
	// Credentials is "ask" or "vault" (with VaultPath).
	Credentials, VaultPath string
	// Selector is "label=value"; empty writes the profile commented out
	// (a Loki source needs at least one label matcher).
	Selector string
	// Network is the Compose network the console joins.
	Network string
}

// DockerProfile and LokiProfile name the side profiles of p.
func DockerProfile(p string) string { return p + "-docker" }
func LokiProfile(p string) string   { return p + "-loki" }

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\u%04x", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func tomlList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = tomlString(x)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// Render writes the config file of p and checks that it loads.
func Render(p Plan) ([]byte, error) {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("# locklog: the project's log sources, written by `locklog setup` from what\n")
	w("# it found on this host. Nothing here is read until the console shows it to\n")
	w("# you: `locklog console` reviews the profile, and every later change that\n")
	w("# loosens it, before any log is opened. Remove what the agent should not see.\n")
	w("version = 1\n")
	d := p.Detected
	prod := "false"
	if p.Production {
		prod = "true"
	}
	main := len(d.Files) > 0 || d.Journald
	if main {
		w("\n[profiles.%s]\nproduction = %s\n", p.Profile, prod)
		for _, f := range d.Files {
			w("\n[profiles.%s.sources.%s]\nkind = \"file\"\npaths = %s\n", p.Profile, f.Name, tomlList(f.Paths))
		}
		if d.Journald {
			w("\n# Every unit; list the ones to serve with units = [\"nginx.service\"].\n")
			w("[profiles.%s.sources.journal]\nkind = \"journald\"\n", p.Profile)
		}
	} else {
		w("\n# No log file or journal was found here. Add a source, e.g.:\n")
		w("#\n# [profiles.%s]\n# production = %s\n#\n# [profiles.%s.sources.app]\n# kind = \"file\"\n# paths = [\"/var/log/app/app.log*\"]\n", p.Profile, prod, p.Profile)
	}
	if len(d.Containers) > 0 {
		dp := DockerProfile(p.Profile)
		w("\n# The running containers. A docker source runs in a console of its own:\n")
		w("# locklog console --profile %s\n", dp)
		w("[profiles.%s]\nproduction = %s\n", dp, prod)
		w("\n[profiles.%s.sources.containers]\nkind = \"docker\"\ncontainers = %s\n", dp, tomlList(d.Containers))
	}
	if l := p.LokiProxy; l != nil {
		lp := LokiProfile(p.Profile)
		var s strings.Builder
		sw := func(format string, a ...any) { fmt.Fprintf(&s, format, a...) }
		sw("[profiles.%s]\nproduction = %s\n\n", lp, prod)
		sw("[profiles.%s.sources.loki]\nkind = \"loki\"\nurl = %s\nauth = \"basic\"\nuser = %s\n", lp, tomlString(l.URL), tomlString(l.User))
		sw("credentials = %s\n", tomlString(l.Credentials))
		if l.VaultPath != "" {
			sw("vault_path = %s\n", tomlString(l.VaultPath))
		}
		sw("tls_ca = %s\n", tomlString(l.CACert))
		if k, v, ok := strings.Cut(l.Selector, "="); ok {
			sw("selector = { %s = %s }\n", k, tomlString(v))
		}
		w("\n# The Compose Loki, behind the authenticating proxy setup generated (its\n")
		w("# files are outside the project). The console reaches it on the Compose\n")
		w("# network: LOCKLOG_NETWORK=%s locklog console --profile %s\n", l.Network, lp)
		if l.Selector == "" {
			w("# Uncomment it once it names the streams to serve: selector = { app = \"api\" }.\n")
			for _, line := range strings.Split(strings.TrimSuffix(s.String(), "\n"), "\n") {
				if line == "" {
					w("#\n")
				} else {
					w("# %s\n", line)
				}
			}
		} else {
			w("%s", s.String())
		}
	}
	out := []byte(b.String())
	if _, err := config.ParseProfiles(out, ".locklog/config.toml"); err != nil {
		return nil, fmt.Errorf("setup: the config written would not load: %w", err)
	}
	return out, nil
}
