package egress

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The route flags of /proc/net/route and /proc/net/ipv6_route
// (linux/route.h).
const (
	rtfUp      = 0x0001
	rtfGateway = 0x0002
	rtfReject  = 0x0200
)

// NetRoute is one entry of the kernel's routing tables, as a container sees
// them in /proc/net/route (IPv4) and /proc/net/ipv6_route (IPv6).
type NetRoute struct {
	// Iface is the interface the route leaves by.
	Iface string
	// Dst is the destination network (0.0.0.0/0 or ::/0 for a default
	// route).
	Dst *net.IPNet
	// Gateway is set when the route goes through a gateway (RTF_GATEWAY):
	// past the interface's own network.
	Gateway bool
	// Reject is a route that refuses its traffic (RTF_REJECT: the kernel's
	// unreachable ::/0 on the loopback).
	Reject bool
}

// Out reports whether r is a route out of the interface's own network: a
// default route or one through a gateway, on an interface other than the
// loopback, that does not refuse its traffic. An internal Docker network
// gives its containers neither.
func (r NetRoute) Out() bool {
	if r.Iface == "lo" || r.Reject {
		return false
	}
	ones, _ := r.Dst.Mask.Size()
	return r.Gateway || ones == 0
}

// Routes reads the routing tables of procNet (/proc/net). The IPv4 table
// is required; the IPv6 one is read when the kernel has it (none with
// IPv6 disabled).
func Routes(procNet string) ([]NetRoute, error) {
	v4, err := os.ReadFile(filepath.Join(procNet, "route"))
	if err != nil {
		return nil, err
	}
	out, err := parseRoutes4(string(v4))
	if err != nil {
		return nil, err
	}
	v6, err := os.ReadFile(filepath.Join(procNet, "ipv6_route"))
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	r6, err := parseRoutes6(string(v6))
	if err != nil {
		return nil, err
	}
	return append(out, r6...), nil
}

// parseRoutes4 parses /proc/net/route: a header, then "Iface Destination
// Gateway Flags RefCnt Use Metric Mask MTU Window IRTT", addresses in hex
// in the host's byte order.
func parseRoutes4(s string) ([]NetRoute, error) {
	var out []NetRoute
	sc := bufio.NewScanner(strings.NewReader(s))
	first := true
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if first {
			first = false
			if len(f) > 0 && f[0] == "Iface" {
				continue
			}
		}
		if len(f) == 0 {
			continue
		}
		if len(f) < 8 {
			return nil, fmt.Errorf("route: malformed line %q", sc.Text())
		}
		dst, err1 := hostIP4(f[1])
		mask, err2 := hostIP4(f[7])
		flags, err3 := strconv.ParseUint(f[3], 16, 32)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, fmt.Errorf("route: malformed line %q: %w", sc.Text(), err)
		}
		if flags&rtfUp == 0 {
			continue
		}
		m := net.IPMask(mask)
		out = append(out, NetRoute{Iface: f[0], Dst: &net.IPNet{IP: net.IP(dst).Mask(m), Mask: m},
			Gateway: flags&rtfGateway != 0, Reject: flags&rtfReject != 0})
	}
	return out, sc.Err()
}

// hostIP4 decodes an IPv4 address of /proc/net/route (8 hex digits, the
// host's byte order).
func hostIP4(h string) ([]byte, error) {
	if len(h) != 8 {
		return nil, fmt.Errorf("address %q", h)
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, uint32(v))
	return b, nil
}

// parseRoutes6 parses /proc/net/ipv6_route: "dst dst_len src src_len
// next_hop metric refcnt use flags iface", addresses in hex in network
// order.
func parseRoutes6(s string) ([]NetRoute, error) {
	var out []NetRoute
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if len(f) < 10 {
			return nil, fmt.Errorf("ipv6_route: malformed line %q", sc.Text())
		}
		dst, err1 := hex.DecodeString(f[0])
		plen, err2 := strconv.ParseUint(f[1], 16, 8)
		flags, err3 := strconv.ParseUint(f[8], 16, 32)
		if err := errors.Join(err1, err2, err3); err != nil || len(dst) != net.IPv6len || plen > 128 {
			return nil, fmt.Errorf("ipv6_route: malformed line %q", sc.Text())
		}
		if flags&rtfUp == 0 {
			continue
		}
		m := net.CIDRMask(int(plen), 128)
		out = append(out, NetRoute{Iface: f[9], Dst: &net.IPNet{IP: net.IP(dst).Mask(m), Mask: m},
			Gateway: flags&rtfGateway != 0, Reject: flags&rtfReject != 0})
	}
	return out, sc.Err()
}

// RouteTo is the interface the most specific route to ip leaves by ("" if
// no route reaches it, or the one that does refuses its traffic).
func RouteTo(routes []NetRoute, ip net.IP) string {
	best, iface := -1, ""
	v4 := ip.To4() != nil
	for _, r := range routes {
		if (r.Dst.IP.To4() != nil) != v4 || !r.Dst.Contains(ip) {
			continue
		}
		if ones, _ := r.Dst.Mask.Size(); ones > best {
			best, iface = ones, r.Iface
			if r.Reject {
				iface = ""
			}
		}
	}
	return iface
}
