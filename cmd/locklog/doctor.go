package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/doctor"
	"github.com/DavidGodefroid/locklog/internal/landlock"
)

// doctorCmd is `locklog doctor [--profile P]`: what the agent's account
// can reach where it runs (advisory). Through the launcher, the account's
// facts are the host's (--facts); the probes and Landlock are read here.
func doctorCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "check against one profile")
	facts := fs.String("facts", "", "the host's facts (written by the launcher)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: locklog doctor [--profile P]")
		return 2
	}
	f, err := loadFacts(*facts, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "locklog doctor:", err)
		return 1
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "locklog doctor:", err)
		return 1
	}
	ps, _, err := config.Load(cwd)
	if err != nil {
		// A broken config is the console's to report; doctor still checks
		// the account, and treats it as production (fail safe).
		fmt.Fprintln(stderr, "locklog doctor: warning:", err, "(checked as a production profile)")
		ps = map[string]config.Profile{"unreadable-config": {Name: "unreadable-config"}}
		p := ps["unreadable-config"]
		p.Production = true
		ps["unreadable-config"] = p
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	r, err := doctor.Run(ctx, doctor.Options{Facts: f, Profiles: ps, Profile: *profile, Landlock: landlock.ABI})
	if err != nil {
		fmt.Fprintln(stderr, "locklog", err)
		return 2
	}
	return doctor.Print(stdout, r)
}
