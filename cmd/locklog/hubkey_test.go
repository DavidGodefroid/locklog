package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
)

// With pinned devices and no --require-device, a read-pii approval must be
// signed by one of them; a --require-device given stays as it is.
func TestHubDefaults(t *testing.T) {
	if h := hubDefaults(console.HubOptions{DevicesFile: "/run/lockfamily/devices.json"}); h.RequireDevice != "read-pii" {
		t.Errorf("default: %q", h.RequireDevice)
	}
	if h := hubDefaults(console.HubOptions{DevicesFile: "d.json", RequireDevice: "read,read-pii"}); h.RequireDevice != "read,read-pii" {
		t.Errorf("given: %q", h.RequireDevice)
	}
	if h := hubDefaults(console.HubOptions{URL: "http://lockhub:8443"}); h.RequireDevice != "" {
		t.Errorf("no devices: %q", h.RequireDevice)
	}
}

// The console takes the hub flags (then needs a terminal, as without).
func TestConsoleHubArgs(t *testing.T) {
	var out, errb bytes.Buffer
	args := []string{"console", "--hub", "http://lockhub:8443", "--hub-plain-http", "--hub-key-file", "/run/locklog-hub/hub.pub", "--instance", "logs",
		"--devices-file", "/run/locklog-hub/devices.json", "--require-device", "read-pii", "--seal-clear", "--facade-keys-file", "/run/locklog-hub/facades.json"}
	if code := run(args, &out, &errb); code != 2 || !strings.Contains(errb.String(), "must run in a terminal") {
		t.Errorf("console with the hub flags = %d %s", code, errb.String())
	}
	if !strings.Contains(consoleUsage, "--hub URL --hub-key-file FILE --instance NAME") {
		t.Error("the usage does not name the hub flags")
	}
}
