package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConsoleRefusedWithoutHub: `locklog console` is started by lox run
// only. Without --hub, --hub-key-file and --instance (or with only some of
// them) it refuses with lockkit's text, before it looks for a terminal, a
// project or a config, and writes nothing.
func TestConsoleRefusedWithoutHub(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	for _, args := range [][]string{
		{"console"},
		{"console", "--profile", "staging"},
		{"console", "--hub", "https://hub.example.com"},
		{"console", "--hub", "https://hub.example.com", "--hub-key-file", "hub.pub"},
		{"console", "--hub-key-file", "hub.pub", "--instance", "logs"},
		{"console", "--profile", "staging", "--allowed-uids", "1000"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		msg := errb.String()
		if !strings.Contains(msg, "the console is launched by `lox run` only: --hub, --hub-key-file and --instance are required") ||
			!strings.Contains(msg, "(started by lox run only)") || out.Len() != 0 {
			t.Errorf("%v: stdout %q, stderr %q", args, out.String(), msg)
		}
		// Refused before the terminal check, which would say so.
		if strings.Contains(msg, "terminal") || strings.Contains(msg, ".locklog") {
			t.Errorf("%v: got past the hub check: %q", args, msg)
		}
	}
	if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
		t.Errorf("the refused console wrote %v (%v)", ents, err)
	}
}

// TestMCPInstance: `locklog mcp` resolves its lock instance as lockkit
// does, before it serves: several listed by lea and none chosen is an
// error naming them; a malformed --instance names the flag, never the
// value.
func TestMCPInstance(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("LEA_LOCKLOG_INSTANCES", "app-logs infra-logs")
	t.Setenv("LOCKLOG_INSTANCE", "")
	var out, errb bytes.Buffer
	if code := mcpCmd(nil, strings.NewReader(""), &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "several locklog locks: app-logs infra-logs; pass --instance NAME") {
		t.Errorf("several: exit %d, %q", code, errb.String())
	}
	errb.Reset()
	if code := mcpCmd([]string{"--instance", "infra-logs"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Errorf("--instance infra-logs: exit %d, %q", code, errb.String())
	}
	errb.Reset()
	const bad = "Secret$Value"
	if code := mcpCmd([]string{"--instance", bad}, strings.NewReader(""), &out, &errb); code != 2 ||
		strings.Contains(errb.String(), bad) || !strings.Contains(errb.String(), "--instance") {
		t.Errorf("bad --instance: exit %d, %q", code, errb.String())
	}
	errb.Reset()
	if code := mcpCmd([]string{"--instance", "other"}, strings.NewReader(""), &out, &errb); code != 2 ||
		!strings.Contains(errb.String(), "no locklog lock other: app-logs infra-logs") {
		t.Errorf("unlisted --instance: exit %d, %q", code, errb.String())
	}
}
