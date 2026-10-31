package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		code       int
		stdout     string
		stderrPart string
	}{
		{name: "version", args: []string{"version"}, code: 0, stdout: "locklog dev\n"},
		{name: "--version", args: []string{"--version"}, code: 0, stdout: "locklog dev\n"},
		{name: "version with an argument", args: []string{"version", "x"}, code: 2, stderrPart: "usage: locklog"},
		{name: "no command", args: nil, code: 2, stderrPart: "usage: locklog"},
		{name: "unknown command", args: []string{"nope"}, code: 2, stderrPart: `unknown command "nope"`},
		{name: "help", args: []string{"help"}, code: 0, stdout: usage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tt.args, &stdout, &stderr)
			if code != tt.code {
				t.Errorf("exit code = %d, want %d (stderr %q)", code, tt.code, stderr.String())
			}
			if tt.stdout != "" && stdout.String() != tt.stdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.stdout)
			}
			if tt.stderrPart != "" && !strings.Contains(stderr.String(), tt.stderrPart) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.stderrPart)
			}
		})
	}
}

func TestVersionFromLdflags(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })
	version = "0.1.0"
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 || stdout.String() != "locklog 0.1.0\n" {
		t.Fatalf("run(version) = %d, %q", code, stdout.String())
	}
}
