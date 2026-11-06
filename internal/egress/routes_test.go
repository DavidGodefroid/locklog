package egress

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// route4 is a /proc/net/route line: addresses in the host's byte order.
func route4(iface, dst, gw, mask string, flags int) string {
	h := func(s string) string {
		return fmt.Sprintf("%08X", binary.NativeEndian.Uint32(net.ParseIP(s).To4()))
	}
	return fmt.Sprintf("%s\t%s\t%s\t%04X\t0\t0\t0\t%s\t0\t0\t0", iface, h(dst), h(gw), flags, h(mask))
}

const routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT"

// ipv6Internal is the IPv6 table of a container on an internal Docker
// network with IPv6 off (Docker 29): the kernel's unreachable ::/0 on the
// loopback, and the loopback's own address.
const ipv6Internal = `00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000004 00000000 80200001       lo
`

func writeProcNet(t *testing.T, v4 []string, v6 string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "route"), []byte(routeHeader+"\n"+strings.Join(v4, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if v6 != "-" {
		if err := os.WriteFile(filepath.Join(d, "ipv6_route"), []byte(v6), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestRoutesInternalNetwork(t *testing.T) {
	d := writeProcNet(t, []string{route4("eth0", "172.24.0.0", "0.0.0.0", "255.255.0.0", rtfUp)}, ipv6Internal)
	rs, err := Routes(d)
	if err != nil {
		t.Fatal(err)
	}
	// The unreachable ::/0 is not up (RTF_UP unset): skipped.
	if len(rs) != 2 {
		t.Fatalf("routes = %+v", rs)
	}
	for _, r := range rs {
		if r.Out() {
			t.Errorf("an internal network's route is a route out: %+v", r)
		}
	}
	if got := RouteTo(rs, net.ParseIP("172.24.0.3")); got != "eth0" {
		t.Errorf("RouteTo(172.24.0.3) = %q", got)
	}
	if got := RouteTo(rs, net.ParseIP("10.0.0.1")); got != "" {
		t.Errorf("RouteTo(10.0.0.1) = %q", got)
	}
	// No interface reaches an IPv6 address.
	if got := RouteTo(rs, net.ParseIP("2001:db8::1")); got != "" {
		t.Errorf("RouteTo(2001:db8::1) = %q", got)
	}
}

func TestRoutesOut(t *testing.T) {
	for _, tt := range []struct {
		name string
		v4   []string
		v6   string
	}{
		{"an IPv4 default route (a bridge network)", []string{
			route4("eth0", "0.0.0.0", "172.17.0.1", "0.0.0.0", rtfUp|rtfGateway),
			route4("eth0", "172.17.0.0", "0.0.0.0", "255.255.0.0", rtfUp)}, "-"},
		{"an IPv4 route through a gateway", []string{
			route4("eth0", "172.24.0.0", "0.0.0.0", "255.255.0.0", rtfUp),
			route4("eth0", "10.0.0.0", "172.24.0.1", "255.0.0.0", rtfUp|rtfGateway)}, ""},
		{"an IPv6 default route", []string{route4("eth0", "172.24.0.0", "0.0.0.0", "255.255.0.0", rtfUp)},
			"00000000000000000000000000000000 00 00000000000000000000000000000000 00 fd000000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n"},
	} {
		rs, err := Routes(writeProcNet(t, tt.v4, tt.v6))
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		out := false
		for _, r := range rs {
			out = out || r.Out()
		}
		if !out {
			t.Errorf("%s: no route out in %+v", tt.name, rs)
		}
	}
}

// A route that refuses its traffic is no way to its addresses, nor out.
func TestRoutesReject(t *testing.T) {
	d := writeProcNet(t, []string{route4("eth0", "172.24.0.0", "0.0.0.0", "255.255.0.0", rtfUp)},
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200201     eth0\n")
	rs, err := Routes(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[1].Out() || !rs[1].Reject {
		t.Fatalf("routes = %+v", rs)
	}
	if got := RouteTo(rs, net.ParseIP("2001:db8::1")); got != "" {
		t.Errorf("RouteTo through a reject route = %q", got)
	}
}

func TestRoutesSkipsDownAndMostSpecific(t *testing.T) {
	d := writeProcNet(t, []string{
		route4("eth1", "0.0.0.0", "10.0.0.1", "0.0.0.0", rtfGateway), // down: not up
		route4("eth0", "172.24.0.0", "0.0.0.0", "255.255.0.0", rtfUp),
		route4("eth1", "172.24.5.0", "0.0.0.0", "255.255.255.0", rtfUp),
	}, "-")
	rs, err := Routes(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("routes = %+v", rs)
	}
	if got := RouteTo(rs, net.ParseIP("172.24.5.9")); got != "eth1" {
		t.Errorf("most specific: %q", got)
	}
	if got := RouteTo(rs, net.ParseIP("172.24.6.9")); got != "eth0" {
		t.Errorf("subnet: %q", got)
	}
}

func TestRoutesMalformed(t *testing.T) {
	for _, tt := range []struct{ v4, v6 string }{
		{"eth0 zz 00000000 0001 0 0 0 0000FFFF", ""},
		{"eth0 0000", ""},
		{"", "0000 00 0000 00 0000 00000000 00000001 00000000 00000001 eth0\n"},
	} {
		d := t.TempDir()
		_ = os.WriteFile(filepath.Join(d, "route"), []byte(routeHeader+"\n"+tt.v4+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(d, "ipv6_route"), []byte(tt.v6), 0o644)
		if _, err := Routes(d); err == nil {
			t.Errorf("accepted %q / %q", tt.v4, tt.v6)
		}
	}
	if _, err := Routes(t.TempDir()); err == nil {
		t.Error("no IPv4 table accepted")
	}
}
