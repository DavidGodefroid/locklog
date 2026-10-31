// Package agentassets holds locklog's agent texts (skill, instructions,
// Cursor rule, example config) and their wiring through lockkit's
// agentwire.
package agentassets

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/DavidGodefroid/lockkit/agentwire"

	"github.com/DavidGodefroid/locklog/internal/mcptools"
	"github.com/DavidGodefroid/locklog/internal/product"
)

var (
	//go:embed skill.md
	Skill []byte
	//go:embed agents.md
	Instructions []byte
	//go:embed cursor-rule.mdc
	CursorFrontMatter []byte
	//go:embed config.toml
	ProjectConfig []byte
)

// ClaudeAllow are the calls Claude Code makes without a prompt: the free
// locklog tools only, which answer masked data within the budgets or only
// tighten the masking. An approved tool (a change request; later a scan,
// an unmask, an export) is never listed: Claude Code asks for it, and the
// console approves it.
func ClaudeAllow() []string {
	var out []string
	for _, n := range mcptools.FreeNames() {
		out = append(out, "mcp__"+product.P.Name+"__"+n)
	}
	return out
}

// wiring wires the agents to locklog. A project init of Claude Code also
// merges ClaudeAllow into the project's .claude/settings.local.json (the
// personal file; the shared .claude/settings.json is never written). It is
// unexported: a user-scope init goes through InitUser, which never writes
// the allow list.
var wiring = agentwire.Wiring{Product: product.P, Assets: agentwire.Assets{
	MCPCommand:         []string{"locklog", "mcp"},
	Skill:              Skill,
	Instructions:       Instructions,
	CursorFrontMatter:  CursorFrontMatter,
	ProjectConfig:      ProjectConfig,
	ClaudeAllow:        ClaudeAllow(),
	ClaudeAllowProject: true,
	ClaudeNote:         "The free locklog tools answer masked data within the budgets; anything beyond them (a policy change, a scan, an unmask) is approved in the locklog console.",
}}

// localSettings is Claude Code's personal settings file, relative to the
// project root: the only file the allow list is written to.
const localSettings = ".claude/settings.local.json"

// InitResult is what a project init did: agentwire's actions and notes,
// the allow entries this run added (a re-run adds back the ones the human
// removed, and says which), and warnings.
type InitResult struct {
	agentwire.Result
	// AllowAdded are the entries this run added to permissions.allow in
	// .claude/settings.local.json, in order.
	AllowAdded []string
	// Warnings are printed after the notes.
	Warnings []string
}

// InitProject wires agent into the project that holds cwd (agentwire's
// ProjectRoot): `locklog init <agent>`, and what `locklog setup --agent
// host` runs for each detected agent. The allow list is only ever written
// at project scope, never into the user's settings: a foreign project's
// server named "locklog" must not get its tools allowed.
func InitProject(cwd, agent string) (InitResult, error) {
	root := agentwire.ProjectRoot(product.P, cwd)
	claude := agent == "claude"
	var before []string
	if claude {
		before = allowEntries(filepath.Join(root, filepath.FromSlash(localSettings)))
	}
	res, err := wiring.Init(root, agent)
	out := InitResult{Result: res}
	if err != nil || !claude {
		return out, err
	}
	for _, a := range allowEntries(filepath.Join(root, filepath.FromSlash(localSettings))) {
		if !slices.Contains(before, a) && !slices.Contains(out.AllowAdded, a) {
			out.AllowAdded = append(out.AllowAdded, a)
		}
	}
	if ignored, known := gitIgnores(root, localSettings); known && !ignored {
		out.Warnings = append(out.Warnings, "warning: git does not ignore "+localSettings+
			" (personal settings, with the allow list above): add it to .gitignore, or it may be committed")
	}
	return out, nil
}

// userWiring is wiring without the allow list: at user scope it would
// apply to every project, so that a foreign project's .mcp.json with a
// server named "locklog" would get its tools allowed.
func userWiring() agentwire.Wiring {
	w := wiring
	w.Assets.ClaudeAllow = nil
	w.Assets.ClaudeAllowProject = false
	return w
}

// InitUser wires agent for the account (the skill and the user MCP
// server), never with an allow list: that is written only at project
// scope, by InitProject.
func InitUser(e agentwire.Env, agent string) (agentwire.Result, error) {
	return userWiring().InitUser(e, agent)
}

// allowEntries reads permissions.allow of a Claude Code settings file
// (none when it is missing or not of that shape: agentwire refuses it).
func allowEntries(file string) []string {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var s struct {
		Permissions struct {
			Allow []string `json:"allow"`
		} `json:"permissions"`
	}
	if json.Unmarshal(data, &s) != nil {
		return nil
	}
	return s.Permissions.Allow
}

// gitIgnores reports whether git ignores rel in the work tree at root;
// known is false when that cannot be told (no git, not a work tree).
// A tracked file is not ignored. A test's stub.
var gitIgnores = func(root, rel string) (ignored, known bool) {
	cmd := exec.Command("git", "-C", root, "check-ignore", "-q", "--", rel)
	err := cmd.Run()
	if err == nil {
		return true, true
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return false, true
	}
	return false, false
}

// Report prints what a wiring wrote, one line per file, the allow entries
// it added, then its notes and warnings.
func Report(w io.Writer, res InitResult) {
	for _, a := range res.Actions {
		line := a.Status + " " + a.Path
		if a.Detail != "" {
			line += " (" + a.Detail + ")"
		}
		fmt.Fprintln(w, line)
	}
	for _, a := range res.AllowAdded {
		fmt.Fprintf(w, "added to permissions.allow in %s: %s\n", localSettings, a)
	}
	if res.Notes != "" {
		fmt.Fprintln(w, res.Notes)
	}
	for _, m := range res.Warnings {
		fmt.Fprintln(w, m)
	}
}
