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
  version   print the version
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one command and returns the process exit code: 0 on
// success, 2 on a usage error.
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
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "locklog: unknown command %q\n%s", args[0], usage)
		return 2
	}
}
