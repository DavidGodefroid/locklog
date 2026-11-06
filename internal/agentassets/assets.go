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
	"strings"

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
	ClaudeNote:         "The free locklog tools answer masked data within the budgets; anything beyond them (a scan, an unmask, a policy change) is approved by the human: a ticket at lox run, or the console's :review.",
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
// ProjectRoot): `locklog init <agent>`, and what `locklog doctor --fix`
// runs for each detected agent not wired yet. The allow list is only ever written
// at project scope, never into the user's settings: a foreign project's
// server named "locklog" must not get its tools allowed.
func InitProject(cwd, agent string) (InitResult, error) {
	root := agentwire.ProjectRoot(product.P, cwd)
	if err := notUserScope(root); err != nil {
		return InitResult{}, err
	}
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

// notUserScope refuses a project root that is the home directory (a
// dotfiles repository, or no project around cwd), or whose .claude is the
// user's Claude Code directory (CLAUDE_CONFIG_DIR, else ~/.claude): a
// project init there would write the allow list and the MCP server at
// user scope, for every project.
func notUserScope(root string) error {
	home, err := os.UserHomeDir()
	if err == nil && home != "" && sameDir(root, home) {
		return fmt.Errorf("the project root %s is your home directory: run locklog init inside a project (or use the user-scope init)", root)
	}
	userClaude := os.Getenv("CLAUDE_CONFIG_DIR")
	if userClaude == "" && home != "" {
		userClaude = filepath.Join(home, ".claude")
	}
	if userClaude != "" && sameDir(filepath.Join(root, ".claude"), userClaude) {
		return fmt.Errorf("%s is your Claude Code user directory: run locklog init inside a project", filepath.Join(root, ".claude"))
	}
	return nil
}

// sameDir reports whether a and b name the same existing directory (links
// resolved).
func sameDir(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && fa.IsDir() && os.SameFile(fa, fb)
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

// Wired reports whether agent is wired to locklog in the project that
// holds cwd: its MCP entry (or, for Codex, its AGENTS.md section) names
// locklog. It reads, never writes; a file it cannot read is not wired.
func Wired(cwd, agent string) bool {
	root := agentwire.ProjectRoot(product.P, cwd)
	mcpEntry := func(rel string) bool {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return false
		}
		var f struct {
			MCPServers map[string]json.RawMessage `json:"mcpServers"`
		}
		if json.Unmarshal(data, &f) != nil {
			return false
		}
		_, ok := f.MCPServers[product.P.Name]
		return ok
	}
	switch agent {
	case "claude":
		return mcpEntry(".mcp.json")
	case "cursor":
		return mcpEntry(".cursor/mcp.json")
	case "gemini":
		return mcpEntry(".gemini/settings.json")
	case "codex":
		data, err := os.ReadFile(filepath.Join(root, "AGENTS.md"))
		return err == nil && strings.Contains(string(data), "<!-- "+product.P.Name+":begin -->")
	}
	return false
}
