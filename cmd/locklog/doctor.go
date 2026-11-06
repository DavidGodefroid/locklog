package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockkit/agentwire"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/locklog/internal/agentassets"
	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/doctor"
	"github.com/DavidGodefroid/locklog/internal/landlock"
	"github.com/DavidGodefroid/locklog/internal/product"
)

const doctorUsage = "usage: locklog doctor [--profile P] [--fix [--yes]] [--json]"

// doctorCmd is `locklog doctor`, the launcher verb of lockkit's GUIDE.md
// §14: what the agent's account can reach where it runs (advisory), and
// whether the agents found here are wired to locklog in this project.
// --fix wires the ones that are not (the only repair it makes), asking
// before each unless --yes. Through the launcher, the account's facts are
// the host's (--facts); the probes and Landlock are read here.
func doctorCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	jsonWanted := verbs.WantsJSON(args)
	refuse := func(err error) int {
		if jsonWanted {
			if werr := verbs.WriteJSON(stdout, verbs.Error{Lock: product.P.Name, Code: verbs.CodeUsage, Error: err.Error()}); werr != nil {
				return 1
			}
			return 2
		}
		fmt.Fprintln(stderr, "locklog doctor:", err)
		fmt.Fprintln(stderr, doctorUsage)
		return 2
	}
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "check against one profile")
	facts := fs.String("facts", "", "the host's facts (written by the launcher; - for the input)")
	fix := fs.Bool(verbs.FlagFix, false, "wire the agents found here that are not wired yet (nothing else)")
	yes := fs.Bool(verbs.FlagYes, false, "with --fix: repair without asking")
	asJSON := fs.Bool(verbs.FlagJSON, false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return refuse(errors.New("bad or unknown flag"))
	}
	if fs.NArg() != 0 {
		return refuse(errors.New("doctor takes no argument"))
	}
	jsonWanted = *asJSON
	if *yes && !*fix {
		return refuse(fmt.Errorf("--%s goes with --%s", verbs.FlagYes, verbs.FlagFix))
	}
	// With --facts -, the input carries the facts: the answers cannot.
	if *fix && !*yes && (*facts == "-" || !isTerminal(stdin)) {
		return refuse(fmt.Errorf("--%s asks before each repair: run it in a terminal, or add --%s", verbs.FlagFix, verbs.FlagYes))
	}
	f, err := loadFacts(*facts, stdin, os.Getenv)
	if err != nil {
		return refuse(fmt.Errorf("the facts: %w", err))
	}
	cwd, err := os.Getwd()
	if err != nil {
		return refuse(err)
	}
	human := stdout
	if *asJSON {
		human = stderr
	}

	// The agents found here: wired, or wired by --fix.
	in := bufio.NewReader(stdin)
	var fixed []string
	var wiring []verbs.Check
	for _, a := range f.Agents {
		if !isAgent(a) {
			continue
		}
		if !agentassets.Wired(cwd, a) && *fix {
			ok := *yes
			if !ok {
				fmt.Fprintf(stderr, "wire %s to locklog in this project (locklog init %s)? [y/N] ", a, a)
				line, _ := in.ReadString('\n')
				line = strings.TrimSpace(line)
				ok = strings.EqualFold(line, "y") || strings.EqualFold(line, "yes")
			}
			if ok {
				res, err := agentassets.InitProject(cwd, a)
				if err != nil {
					fmt.Fprintf(human, "locklog doctor: wiring %s: %v\n", a, err)
				} else {
					agentassets.Report(human, res)
					fixed = append(fixed, "wired "+a+" (locklog init "+a+")")
				}
			}
		}
		c := verbs.Check{Check: "agent " + a, Status: verbs.StatusOK, Detail: a + " is wired to locklog in this project"}
		if !agentassets.Wired(cwd, a) {
			c.Status, c.Detail, c.Fix = verbs.StatusWarn, a+" is installed here but not wired to locklog in this project", "locklog init "+a
		}
		wiring = append(wiring, c)
	}

	ps, root, err := config.Load(cwd)
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
	r, err := doctor.Run(ctx, doctor.Options{Facts: f, Profiles: ps, Profile: *profile, Landlock: landlock.ABI, Project: root})
	if err != nil {
		return refuse(errors.New(strings.TrimPrefix(err.Error(), "doctor: ")))
	}
	if *asJSON {
		d := verbs.NewDoctor(product.P, append(checks(r), wiring...), fixed)
		if err := verbs.WriteJSON(stdout, d); err != nil {
			return 1
		}
		if !d.OK {
			return 1
		}
		return 0
	}
	code := doctor.Print(stdout, r)
	for _, c := range wiring {
		mark := "ok  "
		if c.Status != verbs.StatusOK {
			mark = "warn"
		}
		fmt.Fprintf(stdout, "  %s  %s\n", mark, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(stdout, "        fix: %s (or locklog doctor --fix)\n", c.Fix)
		}
	}
	return code
}

// isAgent reports whether a is an agent locklog can wire.
func isAgent(a string) bool {
	for _, x := range agentwire.Agents() {
		if a == x {
			return true
		}
	}
	return false
}

// checks is the doctor's report as lockkit's verbs.Check lines: a finding
// fails on a production profile (the residuals, the console's own guards,
// only warn), warns otherwise; an unknown is a warning.
func checks(r doctor.Report) []verbs.Check {
	var out []verbs.Check
	add := func(items []doctor.Item, residual bool) {
		for _, it := range items {
			c := verbs.Check{Check: "account", Status: verbs.StatusOK, Detail: it.Text}
			if residual {
				c.Check = "residual"
			}
			switch {
			case it.Finding && r.Production && !residual:
				c.Status, c.Fix = verbs.StatusFail, it.Remedy
			case it.Finding:
				c.Status, c.Fix = verbs.StatusWarn, it.Remedy
			case it.Unknown:
				c.Status = verbs.StatusWarn
			}
			out = append(out, c)
		}
	}
	add(r.Findings, false)
	add(r.Residuals, true)
	return out
}
