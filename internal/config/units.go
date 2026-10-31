package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Day is 24 hours: the unit of the long ranges ("7d", "400d").
const Day = 24 * time.Hour

// ParseDuration parses a Go duration ("90m", "24h") or a whole number of
// days ("7d"). Only positive durations are valid.
func ParseDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseInt(n, 10, 64)
		if err != nil || days <= 0 || days > 100*365 {
			return 0, fmt.Errorf("want a positive duration such as \"7d\" or \"24h\"")
		}
		return time.Duration(days) * Day, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("want a positive duration such as \"7d\" or \"24h\"")
	}
	return d, nil
}

// FormatDuration is the inverse of ParseDuration: whole days as "Nd",
// anything else in Go's form.
func FormatDuration(d time.Duration) string {
	if d > 0 && d%Day == 0 {
		return strconv.FormatInt(int64(d/Day), 10) + "d"
	}
	return d.String()
}

// Byte sizes.
const (
	KiB int64 = 1 << 10
	MiB int64 = 1 << 20
	GiB int64 = 1 << 30
	TiB int64 = 1 << 40
)

var sizeUnits = []struct {
	suffix string
	mult   int64
}{{"TiB", TiB}, {"GiB", GiB}, {"MiB", MiB}, {"KiB", KiB}, {"B", 1}}

// ParseSize parses a positive byte size written with a binary unit:
// "64KiB", "4GiB", "512B".
func ParseSize(s string) (int64, error) {
	for _, u := range sizeUnits {
		n, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		v, err := strconv.ParseInt(n, 10, 64)
		if err != nil || v <= 0 || v > (1<<62)/u.mult {
			break
		}
		return v * u.mult, nil
	}
	return 0, fmt.Errorf("want a positive size such as \"64KiB\" or \"4GiB\"")
}

// FormatSize writes n with the largest binary unit that divides it.
func FormatSize(n int64) string {
	for _, u := range sizeUnits {
		if n != 0 && n%u.mult == 0 {
			return strconv.FormatInt(n/u.mult, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10) + "B"
}
