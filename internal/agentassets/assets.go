// Package agentassets holds locklog's agent texts (skill, instructions,
// Cursor rule, example config) and their wiring through lockkit's
// agentwire.
package agentassets

import (
	_ "embed"

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

// ClaudeAllow are the calls Claude Code makes without a prompt: every
// locklog tool. The free ones touch only masked data; the approved ones
// (scan, unmask, export, change requests) are approved at the console or
// the hub, not in Claude Code.
func ClaudeAllow() []string {
	var out []string
	for _, n := range mcptools.Names() {
		out = append(out, "mcp__locklog__"+n)
	}
	return append(out, "Bash(locklog status:*)", "Bash(locklog doctor:*)")
}

// Wiring wires the agents to locklog.
var Wiring = agentwire.Wiring{Product: product.P, Assets: agentwire.Assets{
	MCPCommand:        []string{"locklog", "mcp"},
	Skill:             Skill,
	Instructions:      Instructions,
	CursorFrontMatter: CursorFrontMatter,
	ProjectConfig:     ProjectConfig,
	ClaudeAllow:       ClaudeAllow(),
	ClaudeNote:        "Every locklog tool answers masked data; anything beyond the free budgets (a scan, an unmask) is approved in the locklog console, not in Claude Code.",
}}
