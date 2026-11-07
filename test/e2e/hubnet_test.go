//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// localProfile writes a profile "e2e" reading e.logs only (a local-only
// console: no remote source, no LOCKLOG_NETWORK).
func localProfile(t *testing.T, e *e2eEnv) {
	t.Helper()
	cfg := strings.Join([]string{
		"version = 1",
		"[profiles.e2e]",
		"production = false",
		"[profiles.e2e.sources.app]",
		`kind = "file"`,
		fmt.Sprintf("paths = [%q]", e.logs+"/app.log*"),
		`format = "logfmt"`,
		"",
	}, "\n")
	mkdir(t, filepath.Join(e.proj, ".locklog"))
	p := filepath.Join(e.proj, ".locklog", "config.toml")
	if err := os.WriteFile(p, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A local-only console under lox run is on the internal hub network alone
// (no LOCKLOG_NETWORK): it accepts that network, opens its session and
// answers the agent (#136).
func TestHubNetworkLocalOnly(t *testing.T) {
	e, _, _, _ := newEnv(t, "hubnet")
	localProfile(t, e)
	lr := startLoxRun(t, e, "e2e", "", [2]string{"Apply these changes? [y/N]", "y"})
	if got := docker(t, "inspect", "-f", "{{range $n, $_ := .NetworkSettings.Networks}}{{$n}} {{end}}", lr.name); got != lr.network {
		t.Fatalf("the console's networks: %q, want %s alone", got, lr.network)
	}
	if got := docker(t, "network", "inspect", "-f", "{{.Internal}}", lr.network); got != "true" {
		t.Fatalf("%s internal = %s", lr.network, got)
	}
	if env := docker(t, "inspect", "-f", "{{json .Config.Env}}", lr.name); strings.Contains(env, "LOCKLOG_NETWORK=") {
		t.Fatalf("LOCKLOG_NETWORK set for a local-only console: %s", env)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cs := e.connect(t, ctx, []string{"locklog", "mcp"})
	if _, st := call(t, ctx, cs, "locklog_status", nil); !strings.Contains(st, "profile e2e: console running") {
		t.Fatalf("locklog_status: the console is not running:\n%s", st)
	}
}

// On a network with a route out (a plain bridge network, not lox run's
// internal hub network), a local-only console refuses its session.
func TestHubNetworkRouteOutRefused(t *testing.T) {
	e, _, _, _ := newEnv(t, "hubnet-out")
	localProfile(t, e)
	_, screen, exited := launchLoxRun(t, e, false, "e2e", "", [2]string{"Apply these changes? [y/N]", "y"})
	waitFor(t, screen, "has the hub's internal network only: it has a route out", 2*time.Minute, exited)
	select {
	case <-exited:
	case <-time.After(time.Minute):
		t.Fatal("the console did not stop after refusing its network")
	}
	if strings.Contains(plain(screen.String()), "Listening on ") {
		t.Fatalf("the console listened on a network with a route out:\n%s", plain(screen.String()))
	}
}
