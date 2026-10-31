package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/sysconf"
)

func TestParseAllowedUIDs(t *testing.T) {
	for in, want := range map[string][]int{
		"":               nil,
		"1000":           {1000},
		"1000,1001":      {1000, 1001},
		"1001,1001":      {1001},
		"10052,1000,999": {10052, 1000, 999},
	} {
		got, err := parseAllowedUIDs(in)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("parseAllowedUIDs(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"0", "007", "1000,0", "1,,2", ",1", "1,", "-1", "+1", " 1", "a", "65534", "10051", "4294967295", "99999999999999999999"} {
		if got, err := parseAllowedUIDs(bad); err == nil {
			t.Errorf("parseAllowedUIDs(%q) = %v, want an error", bad, got)
		}
	}
}

func TestAllowUIDs(t *testing.T) {
	env := console.IsolationEnv{LoadSys: func() (*sysconf.Config, error) {
		return &sysconf.Config{ServiceUser: "locklog", ClientGroup: "locklog-clients", AllowedUIDs: []int{4242}}, nil
	}}
	sys, err := allowUIDs(env, []int{1000, 4242}).LoadSys()
	if err != nil || !slices.Equal(sys.AllowedUIDs, []int{4242, 1000}) {
		t.Errorf("allowUIDs = %+v, %v", sys, err)
	}
	none := console.IsolationEnv{LoadSys: func() (*sysconf.Config, error) { return nil, nil }}
	if _, err := allowUIDs(none, []int{1000}).LoadSys(); err == nil || !strings.Contains(err.Error(), "/etc/locklog/system.toml") {
		t.Errorf("no separated setup: %v", err)
	}
	if joinUIDs([]int{1000, 1001}) != "1000,1001" {
		t.Error("joinUIDs")
	}
}

func TestConsoleArgs(t *testing.T) {
	for _, args := range [][]string{{"extra"}, {"--allowed-uids", "0"}, {"--allowed-uids", "1000", "--allowed-uids", "1001"}, {"--bogus"}} {
		var out, errb bytes.Buffer
		if code := run(append([]string{"console"}, args...), &out, &errb); code != 2 {
			t.Errorf("console %v = %d (%s)", args, code, errb.String())
		}
	}
	// Not a terminal (go test's stdin): refused.
	var out, errb bytes.Buffer
	if code := run([]string{"console"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "must run in a terminal") {
		t.Errorf("console without a terminal = %d %s", code, errb.String())
	}
}
