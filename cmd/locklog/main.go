// Command locklog lets an AI agent search and count across logs it never
// reads in clear: a console held by a human reads the logs, and the agent
// gets masked, bounded answers over MCP.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

const usage = `usage: locklog <command>

Commands:
  version                 print the version
  init <agent>            wire an agent (claude, codex, cursor, gemini) to locklog in this project
  profile add [--non-interactive] [--json] [--profile NAME] [--production] ...
                          add a profile to .locklog/config.toml from this host's logs
                          (never a secret: the console asks at start, or Vault)
  profile rules [--json] [--project DIR] [--profile NAME]
                          the auto mode of each profile, as lox run applies it
                          (read, unmask, lookup: auto, ask or deny)
  doctor [--profile P] [--fix [--yes]] [--json]
                          check what the agent's account can reach (advisory), and the agents' wiring
  managed show            the company's managed configuration (managed.toml): its
                          fingerprint, bounds, defaults, PII rules and profiles
  managed check [--profile NAME] [--project DIR]
                          check the profiles against its bounds, as the console
                          does at start (exit 3 when one is blocked)
  mcp [--profile P] [--instance NAME]
                          the agent's MCP server (stdin and stdout)
  console --hub URL ...   the console of a profile, hub-attached (started by lox run only)
  mounts [--profile P]    print the mount plan of a profile (read by lox run)
  hub-key --instance NAME print the console's instance key for lockhub to pin (lox run)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one command and returns the process exit code: 0 on
// success, 1 on a failure, 2 on a usage error, 3 on a refusal of the
// company's managed configuration (managed, console).
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		if len(args) > 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		fmt.Fprintf(stdout, "locklog %s\n", version)
		return 0
	case "mcp":
		return mcpCmd(args[1:], os.Stdin, stdout, stderr)
	case "profile":
		return profileCmd(args[1:], os.Stdin, stdout, stderr)
	case "doctor":
		return doctorCmd(args[1:], os.Stdin, stdout, stderr)
	case "init":
		return initCmd(args[1:], stdout, stderr)
	case "managed":
		return managedCmd(args[1:], stdout, stderr)
	case "console":
		return consoleCmd(args[1:], stdout, stderr)
	case "mounts":
		return mounts(args[1:], stdout, stderr)
	case "hub-key":
		return hubKeyCmd(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		if len(args) > 1 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "locklog: unknown command %q\n%s", args[0], usage)
		return 2
	}
}
