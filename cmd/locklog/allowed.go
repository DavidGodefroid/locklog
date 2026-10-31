package main

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/lockkit/console"
	"github.com/DavidGodefroid/lockkit/sysconf"

	"github.com/DavidGodefroid/locklog/internal/product"
)

// parseAllowedUIDs reads `console --allowed-uids`: comma-separated decimal
// uids, as the image's ALLOWED_UIDS build argument takes them. Root (0) and
// leading zeros are refused here; the console's own uid is refused by the
// isolation checks (the separation would be void).
func parseAllowedUIDs(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}
	var uids []int
	for _, f := range strings.Split(s, ",") {
		if f == "" || strings.Trim(f, "0123456789") != "" {
			return nil, fmt.Errorf("--allowed-uids: comma-separated uids, got %q", s)
		}
		if f[0] == '0' {
			return nil, fmt.Errorf("--allowed-uids: %s is root or has a leading zero", f)
		}
		// 2^32-1 is (uid_t)-1, no account's.
		v, err := strconv.ParseUint(f, 10, 32)
		if err != nil || v == math.MaxUint32 {
			return nil, fmt.Errorf("--allowed-uids: %s is not a uid", f)
		}
		n := int(v)
		if n == product.ConsoleUID {
			return nil, fmt.Errorf("--allowed-uids: %d is the console's own account", n)
		}
		if n == 65534 {
			// The overflow uid: any peer of a user namespace with no
			// mapping for its uid, never one agent.
			return nil, fmt.Errorf("--allowed-uids: 65534 is nobody, the kernel's overflow uid")
		}
		if !slices.Contains(uids, n) {
			uids = append(uids, n)
		}
	}
	return uids, nil
}

// onceFlag is a string flag given at most once: a second --allowed-uids
// (one a wrapper prepends, say) would otherwise replace the first.
type onceFlag struct {
	v   string
	set bool
}

func (f *onceFlag) String() string { return f.v }

func (f *onceFlag) Set(s string) error {
	if f.set {
		return errors.New("given twice: list every uid in one --allowed-uids")
	}
	f.v, f.set = s, true
	return nil
}

// allowUIDs returns env whose separated setup also lets uids connect, as
// allowed_uids in the image's system.toml does: every check that reads
// the setup sees them (the peers served, and the accounts whose session or
// terminal the console refuses). Without a separated setup it refuses.
func allowUIDs(env console.IsolationEnv, uids []int) console.IsolationEnv {
	if len(uids) == 0 {
		return env
	}
	load := env.LoadSys
	env.LoadSys = func() (*sysconf.Config, error) {
		sys, err := load()
		if err != nil {
			return nil, err
		}
		if sys == nil {
			return nil, errors.New("--allowed-uids needs the separated setup (/etc/locklog/system.toml, as in the image)")
		}
		c := *sys
		c.AllowedUIDs = slices.Clone(sys.AllowedUIDs)
		for _, u := range uids {
			if !slices.Contains(c.AllowedUIDs, u) {
				c.AllowedUIDs = append(c.AllowedUIDs, u)
			}
		}
		return &c, nil
	}
	return env
}

// joinUIDs prints uids as the flag takes them.
func joinUIDs(uids []int) string {
	s := make([]string, len(uids))
	for i, u := range uids {
		s[i] = strconv.Itoa(u)
	}
	return strings.Join(s, ",")
}
