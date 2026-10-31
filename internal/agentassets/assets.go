// Package agentassets holds locklog's agent texts (skill, instructions,
// Cursor rule, example config) and their wiring through lockkit's
// agentwire.
package agentassets

import (
	_ "embed"
	"fmt"
	"io"

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

// Wiring wires the agents to locklog. A project init of Claude Code also
// merges ClaudeAllow into the project's .claude/settings.local.json (the
// personal file; the shared .claude/settings.json is never written).
var Wiring = agentwire.Wiring{Product: product.P, Assets: agentwire.Assets{
	MCPCommand:         []string{"locklog", "mcp"},
	Skill:              Skill,
	Instructions:       Instructions,
	CursorFrontMatter:  CursorFrontMatter,
	ProjectConfig:      ProjectConfig,
	ClaudeAllow:        ClaudeAllow(),
	ClaudeAllowProject: true,
	ClaudeNote:         "The free locklog tools answer masked data within the budgets; anything beyond them (a policy change, a scan, an unmask) is approved in the locklog console.",
}}

// InitProject wires agent into the project that holds cwd (agentwire's
// ProjectRoot): `locklog init <agent>`, and what `locklog setup --agent
// host` runs for each detected agent.
func InitProject(cwd, agent string) (agentwire.Result, error) {
	return Wiring.Init(agentwire.ProjectRoot(product.P, cwd), agent)
}

// Report prints what a wiring wrote, one line per file, then its notes.
func Report(w io.Writer, res agentwire.Result) {
	for _, a := range res.Actions {
		line := a.Status + " " + a.Path
		if a.Detail != "" {
			line += " (" + a.Detail + ")"
		}
		fmt.Fprintln(w, line)
	}
	if res.Notes != "" {
		fmt.Fprintln(w, res.Notes)
	}
}
