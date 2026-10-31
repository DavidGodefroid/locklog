package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockkit/agentwire"
	"github.com/DavidGodefroid/lockkit/mcpkit"

	"github.com/DavidGodefroid/locklog/internal/agentassets"
	"github.com/DavidGodefroid/locklog/internal/config"
	"github.com/DavidGodefroid/locklog/internal/mcptools"
)

// profileNames lists the configured profiles of cwd's project, sorted.
func profileNames(cwd string) ([]string, error) {
	ps, _, err := config.Load(cwd)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ps))
	for n := range ps {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// mcpCmd is `locklog mcp [--profile P]`: the agent's MCP server on stdin
// and stdout. LOCKLOG_HOST_AGENT (set by the launcher's mcp) makes it the
// host agent's: production profiles are refused.
func mcpCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "pin the server to one profile")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(stderr, "usage: locklog mcp [--profile P]")
		return 2
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "locklog mcp:", err)
		return 1
	}
	s := mcptools.New(mcptools.Options{
		Pinned:    *profile,
		Profiles:  func() ([]string, error) { return profileNames(cwd) },
		Dial:      mcptools.DialClient(cwd, version),
		Version:   version,
		HostAgent: os.Getenv("LOCKLOG_HOST_AGENT") == "1",
	})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := mcpkit.Serve(ctx, s, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "locklog mcp: %v\n", err)
		return 1
	}
	return 0
}

// initCmd is `locklog init <agent>`: the project's agent files (MCP
// server, skill, instructions, Cursor rule, an example .locklog/config.toml;
// for Claude Code, the free tools in .claude/settings.local.json).
func initCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: locklog init <%s>\n", strings.Join(agentwire.Agents(), "|"))
		return 2
	}
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, "locklog init:", err)
		return 1
	}
	res, err := agentassets.InitProject(cwd, args[0])
	if err != nil {
		fmt.Fprintln(stderr, "locklog init:", err)
		return 2
	}
	agentassets.Report(stdout, res)
	return 0
}
