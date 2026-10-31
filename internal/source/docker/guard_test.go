package docker

import (
	"errors"
	"testing"

	"github.com/DavidGodefroid/locklog/internal/landlock"
)

func TestGuard(t *testing.T) {
	none := landlock.Status{State: landlock.Unsupported, Detail: "x"}
	on := landlock.Status{State: landlock.Enforced, ABI: 5}
	part := landlock.Status{State: landlock.Partial, ABI: 2}
	for _, tt := range []struct {
		prod    bool
		ll      landlock.Status
		openat2 bool
		refused bool
		res     int
	}{
		{true, none, false, true, 2},
		{true, none, true, false, 1},
		{true, on, false, false, 1},
		{true, part, false, false, 2},
		{true, on, true, false, 0},
		{false, none, false, false, 2},
	} {
		err := Guard(tt.prod, tt.ll, tt.openat2)
		if errors.Is(err, ErrUnguarded) != tt.refused {
			t.Errorf("%+v: %v", tt, err)
		}
		if got := Residuals(tt.ll, tt.openat2); len(got) != tt.res {
			t.Errorf("%+v: residuals %q", tt, got)
		}
	}
}
