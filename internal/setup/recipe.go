package setup

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/DavidGodefroid/locklog/internal/product"
)

// RecipeOptions describe the agent's own image.
type RecipeOptions struct {
	// Image is the locklog image to copy from: a digest reference
	// (registry@sha256:...) for a release, or a local tag.
	Image string
	// AgentUID is the agent user's uid in its image (default 10052, the
	// locklog image's agent account, which the console already admits).
	AgentUID int
	// Profile is the profile the console serves (for the run lines).
	Profile string
}

// pinned reports whether ref names an image by digest.
func pinned(ref string) bool {
	_, d, ok := strings.Cut(ref, "@sha256:")
	return ok && len(d) == 64 && strings.Trim(d, "0123456789abcdef") == ""
}

// ContainerRecipe prints the own-container recipe: the Dockerfile snippet
// of the agent's image (a non-root agent user without sudo in the clients
// group, the locklog binary and a root-owned system file copied from the
// locklog image by digest), the run lines, and the console's
// --allowed-uids when the agent's uid is not one the console's image knows.
func ContainerRecipe(w io.Writer, o RecipeOptions) {
	if o.AgentUID == 0 {
		o.AgentUID = product.AgentUID
	}
	uid := strconv.Itoa(o.AgentUID)
	gid := strconv.Itoa(product.ClientsGID)
	img := o.Image
	fmt.Fprintf(w, `# The own-container recipe: your agent runs in an image of yours, as a
# non-root user without sudo, and reaches the console only through its
# socket (the locklog-run volume). It never sees the logs, the keys or the
# console's terminal.
#
# 1. Add this to your agent's Dockerfile, after its packages are installed:

`)
	if !pinned(img) {
		fmt.Fprintf(w, "# %s is not pinned by digest: pin it before you build (docker buildx imagetools inspect %s).\n", img, img)
	}
	fmt.Fprintf(w, `# locklog's client, its root-owned system file (the console account and
# the clients group the socket admits), and the accounts it names.
COPY --from=%[1]s --chown=root:root --chmod=0755 /usr/local/bin/locklog /usr/local/bin/locklog
COPY --from=%[1]s --chown=root:root /etc/locklog/system.toml /etc/locklog/system.toml
# The console account (%[4]d) only names the socket's owner, which the client
# checks: no shell, no home, no password, nothing runs as it here. The agent
# user is not root, has no sudo, and is in locklog-clients (%[3]s).
RUN set -eu; \
    if command -v useradd >/dev/null 2>&1; then \
      groupadd -g %[3]s locklog-clients; \
      useradd -M -N -u %[4]d -s /usr/sbin/nologin locklog; \
      useradd -m -u %[2]s -g locklog-clients -s /bin/sh agent; \
    else \
      addgroup -g %[3]s locklog-clients; \
      adduser -D -H -u %[4]d -s /sbin/nologin locklog; \
      adduser -D -u %[2]s -G locklog-clients -s /bin/sh agent; \
    fi; \
    chmod 0755 /etc/locklog; chmod 0644 /etc/locklog/system.toml; \
    if command -v sudo >/dev/null 2>&1; then echo "the agent image must not have sudo" >&2; exit 1; fi
USER %[2]s:%[3]s

`, img, uid, gid, product.ConsoleUID)
	fmt.Fprintf(w, `# 2. Start the console, in a terminal of yours, from the project:

  locklog console --profile %s`, o.Profile)
	if o.AgentUID != product.AgentUID {
		fmt.Fprintf(w, " --allowed-uids %s", uid)
	}
	fmt.Fprintf(w, `

# 3. Run the agent's container with the socket volume and the project at its
#    own path (the socket is named after the project's path):

  docker run --rm -it -v locklog-run:/run/locklog -v "$PWD:$PWD" -w "$PWD" your-agent-image

# In it, the agent's MCP server is `+"`locklog mcp`"+` (locklog init <agent> writes the
# project's MCP entry). Every agent whose container mounts this locklog-run
# volume reaches every console on it: one locklog-run volume is one trust
# domain. Give agents that must not share a console their own volume.
`)
	if o.AgentUID != product.AgentUID {
		fmt.Fprintf(w, `# The console's image knows uid %s by no account: --allowed-uids %s admits it
# (the console's start shows it).
`, uid, uid)
	}
}

// LeaRecipe prints where the lea placement stands.
func LeaRecipe(w io.Writer) {
	fmt.Fprint(w, `# The lea placement: lea runs the agent in a container of its own and
# reaches the locklog console like the own-container recipe does. No lea
# release supports it yet: use `+"`locklog setup --agent container`"+` meanwhile.
`)
}
