package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	kconfig "github.com/DavidGodefroid/lockkit/config"
	"github.com/DavidGodefroid/lockkit/verbs"

	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/product"
)

const profileRulesUsage = `usage: locklog profile rules [--json] [--project DIR] [--profile NAME]`

// profileRules is one profile's auto rules as `lox run` reads them
// (`locklog profile rules --json`, #126): those of the policy the console
// approved when this account can read it (Source "approved"), else the
// project config's (Source "files": nothing approved yet, or the
// console's state is not readable here).
type profileRules struct {
	Profile    string                      `json:"profile"`
	Production bool                        `json:"production"`
	Preset     string                      `json:"preset,omitempty"`
	Rules      map[string]config.AutoValue `json:"rules"`
	// IDs name each action's rule as the lock audits it
	// ("auto.read = ask").
	IDs map[string]string `json:"ids"`
	// Source is where Rules come from: "approved" or "files".
	Source string `json:"source"`
	// PendingReview marks a config file whose rules differ from the
	// approved policy's: the console enforces the approved ones until the
	// human applies the change at :review. FileRules are the file's.
	PendingReview bool                        `json:"pending_review"`
	FileRules     map[string]config.AutoValue `json:"file_rules,omitempty"`
	text          string
}

// profileRulesOut is the --json output of `profile rules`.
type profileRulesOut struct {
	Lock     string         `json:"lock"`
	Actions  []string       `json:"actions"`
	Profiles []profileRules `json:"profiles"`
}

// Where the rules of `profile rules` come from.
const (
	sourceApproved = "approved"
	sourceFiles    = "files"
)

// profileRulesCmd is `locklog profile rules`: the effective auto rules
// (the defaults where a profile sets none) of the project's profiles,
// taken from the policy the console approved when this account can read
// it under stateBase, never from a file edit the human has not approved:
// the config file is in the project, which the agent may write. A file
// whose rules differ from the approved ones is flagged pending review.
// The console does not trust this output either: a ticket its rules leave
// to the human is signed never_auto, and an auto rule's approval of it
// is refused.
func profileRulesCmd(args []string, cwd, stateBase string, stdout, stderr io.Writer) int {
	asJSON := verbs.WantsJSON(args)
	fail := func(code string, exit int, err error) int {
		if asJSON {
			if werr := verbs.WriteJSON(stdout, verbs.Error{Lock: product.P.Name, Code: code, Error: err.Error()}); werr != nil {
				return 1
			}
			return exit
		}
		fmt.Fprintln(stderr, "locklog profile rules:", err)
		if code == verbs.CodeUsage {
			fmt.Fprintln(stderr, profileRulesUsage)
		}
		return exit
	}
	fs := flag.NewFlagSet("profile rules", flag.ContinueOnError)
	fs.Bool(verbs.FlagJSON, false, "one line of JSON on stdout")
	project := fs.String(verbs.FlagProject, "", "the project directory (default: the project of this directory)")
	name := fs.String(verbs.FlagProfile, "", "only this profile")
	if err := verbs.Parse(product.P, fs, args); err != nil {
		return fail(verbs.ErrorCode(err, verbs.CodeUsage), 2, err)
	}
	if fs.NArg() != 0 {
		return fail(verbs.CodeUsage, 2, errors.New("unexpected arguments"))
	}
	dir := cwd
	if *project != "" {
		abs, err := filepath.Abs(*project)
		if err != nil {
			return fail(verbs.CodeUsage, 2, errors.New("--project: not a usable path"))
		}
		dir = abs
	}
	root, ok := kconfig.FindProjectRoot(product.P, dir)
	if !ok {
		return fail(verbs.CodeFailed, 1, errors.New("no .locklog/ here or above: run locklog profile add first"))
	}
	ps, err := config.LoadFile(kconfig.ProjectConfigPath(product.P, root))
	if err != nil {
		return fail(verbs.CodeFailed, 1, err)
	}
	names := make([]string, 0, len(ps))
	for n := range ps {
		if *name == "" || n == *name {
			names = append(names, n)
		}
	}
	if *name != "" && len(names) == 0 {
		return fail(verbs.CodeUsage, 2, errors.New("no such profile in the project's config"))
	}
	sort.Strings(names)
	actions := make([]string, len(config.AutoActions))
	for i, a := range config.AutoActions {
		actions[i] = string(a)
	}
	out := profileRulesOut{Lock: product.P.Name, Actions: actions, Profiles: []profileRules{}}
	for _, n := range names {
		out.Profiles = append(out.Profiles, rulesOf(n, ps[n], approvedProfile(stateBase, root, n)))
	}
	if asJSON {
		if err := verbs.WriteJSON(stdout, out); err != nil {
			return 1
		}
		return 0
	}
	if len(out.Profiles) == 0 {
		fmt.Fprintln(stdout, "no profile in the project's config: add one with `locklog profile add`")
	}
	for _, pr := range out.Profiles {
		tag := ""
		if pr.Production {
			tag = " (production)"
		}
		note := " [approved]"
		switch {
		case pr.PendingReview:
			note = " [approved; the config file differs: pending :review]"
		case pr.Source != sourceApproved:
			note = " [config file: not approved yet]"
		}
		fmt.Fprintf(stdout, "%s%s: %s%s\n", pr.Profile, tag, pr.text, note)
	}
	return 0
}

// rulesOf is profile n's rules: the approved profile's when ap is not
// nil, the file's p otherwise, flagged when they differ.
func rulesOf(n string, p config.Profile, ap *config.Profile) profileRules {
	src, from := p, sourceFiles
	if ap != nil {
		src, from = *ap, sourceApproved
	}
	r := src.AutoRules()
	pr := profileRules{Profile: n, Production: src.Production || p.Production, Preset: r.Preset(), Rules: r.Map(),
		IDs: map[string]string{}, Source: from, text: r.String()}
	for _, a := range config.AutoActions {
		pr.IDs[string(a)] = r.RuleText(a)
	}
	if ap != nil {
		if files := p.AutoRules(); files != r {
			pr.PendingReview, pr.FileRules = true, files.Map()
		}
	}
	return pr
}

// approvedProfile is the profile of the policy the console approved for
// profile name of the project at root, nil when there is none or it
// cannot be read by this account (the console keeps it in its own state,
// the home volume `lox run` gives it).
func approvedProfile(stateBase, root, name string) *config.Profile {
	if stateBase == "" {
		return nil
	}
	var ap config.Policy
	ok, err := kconfig.LoadApproved(product.P, stateBase, kconfig.ApprovedKey(root, name), &ap)
	if err != nil || !ok || ap.Profile.Name != name {
		return nil
	}
	return &ap.Profile
}
