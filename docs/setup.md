# Setup: the launcher verbs

locklog takes the three verbs every lock of the Lock Family takes
(lockkit's GUIDE.md §14), which `lox add locklog <name>` (or `lox init`)
calls from the project:

    locklog profile add --non-interactive --json --profile NAME [--production] ...
    locklog init claude
    locklog doctor --fix --yes --json

You can run them yourself, in the project directory, in your own terminal.
The console is not one of them: `lox run` starts it, hub-attached, in a
terminal of its own (see the [usage](usage.md)).

## Install

The Lock Family's path is Homebrew, then `lox`:

```sh
brew trust davidgodefroid/tap                # Homebrew asks you to trust a third-party tap once
brew install davidgodefroid/tap/lockfamily   # or only this tool: brew install davidgodefroid/tap/locklog
cd ~/projects/shop                           # the project whose logs the agent investigates
lox add locklog logs                          # or: lox init
lox run                                       # in a terminal of its own, outside the agent
```

`lox add locklog` and the locklog console in `lox run` need the lockhub
release that adds the locklog type (lockhub#84, #86, #87; lockhub v0.9.0
does not know it), which the tap's `locklog` formula, and locklog in
`lockfamily`, come with. The alternative, without Homebrew, installs the
launcher alone, cosign-verified:

```sh
curl -fsSL https://locklog.dev/install.sh | sh   # or LOCKLOG_VERSION=vX.Y.Z
```

## `locklog profile add`

    locklog profile add [--non-interactive] [--json] [--project DIR] [--profile NAME] [--production]
                        [--only DIR,...] [--loki-proxy SERVICE [--loki-selector label=value]
                        [--credentials ask|vault [--vault-path P]]]

The launcher gathers the host's facts (the log files under `/var/log` and
`LOCKLOG_EXTRA_ROOTS`, the journal directories, `docker ps`) and runs it in
the image as you, with the project writable and no network. It writes:

- `.locklog/` (yours, 0755) and `.locklog/config.toml`: one source per log
  file family (`/var/log/nginx/access.log*` covers `access.log.1` and
  `access.log.2.gz`), the journal, and the running containers in a
  `<profile>-docker` profile (a docker source runs in a console of its own,
  so a lock of its own).
- When `config.toml` exists, the new profiles are appended to it; a profile
  already there is never rewritten (`exists`, nothing written).
- When it finds no log file and no journal, it writes nothing and fails:
  name the directories with `--only`, or write the sources by hand.

Nothing is read until the console shows the profile to you: `lox run`
reviews the profile directory, and the console reviews the policy again at
its first start, and every later loosening.

`--profile` names the profile (default: `prod` for a production profile,
`staging` otherwise); `--production` makes it a production profile (its
name is then typed for the console's own widenings). `--only /srv/app/logs`
proposes only the log files under that directory (no journal, no
container).

On a terminal, without `--non-interactive`, it asks what the flags did not
give: whether the profile is production (unanswered: **yes**), and whether
to put a detected Compose Loki behind a proxy. With `--non-interactive` it
never asks; without a terminal it refuses rather than wait. `--json`
prints one line (lockkit's `verbs.Profile`, or `verbs.Error` with the code
`usage`, `secret`, `exists` or `failed`); the human's text goes to stderr.

No form of `profile add` takes, asks for or writes a secret: a flag named
like a secret (`--password`, `--token`...), a value that embeds one
(`user:pw@host`, `password=`), a control character or a positional argument
is refused, never quoted. A remote source's credential is only ever `ask`
(the console asks at its start) or `vault` (the console reads it from Vault
with the Vault token it asks at its start).

CI checks this path end to end (job `five-minutes`): from `profile add` and
`init claude` to the first masked answer of an MCP client spawned from the
written `.mcp.json`, through a console started as `lox run` starts it, in
under 300 s, with the allow list holding the free tools only.

### A Compose Loki without auth

`locklog profile add --loki-proxy loki` (interactive only) generates an
authenticating TLS proxy (Caddy) for a Loki service of a running Compose
project:

- Caddy gets only a bcrypt hash of the read token;
- the token is shown once on your terminal (it refuses without one) and is
  written nowhere: the console asks for it at its start
  (`--credentials ask`, the default), or reads it from Vault
  (`--credentials vault --vault-path P`);
- the internal CA's private key is discarded once the server certificate is
  signed;
- the files go to `~/.config/locklog/proxy/<project>-<service>/` (0700,
  outside the project); only the CA certificate is copied to `.locklog/`,
  for the profile's `tls_ca`.

The source goes into a `<profile>-loki` profile, commented out until it has
a selector (`--loki-selector app=api`). The console reaches the proxy on
the Compose network, which no agent joins.

### Elasticsearch and OpenSearch

`profile add` detects no Elasticsearch or OpenSearch backend. It writes a
commented `<profile>-search` entry to fill in: `kind = "elastic"` or
`"opensearch"`, the `indices`, the keyword `trusted_fields`, `auth` and
`user`. Give the console a read-only key (`read` and `view_index_metadata`
on the indices, `monitor` on the cluster); at connection a production
profile refuses a key with any write or manage privilege and a backend that
answers without credentials.

### Remote sources connect at the console's start

A Loki, Elasticsearch or OpenSearch source connects when the console starts,
with you at its terminal: the console asks its secret (or the Vault token)
then. It does not yet wait for a `connect` ticket of `lox run` (lockkit's
`lazyconn`); until it does, `lox run` shows no connect ticket for locklog.

The backend check runs once per connection, before the agent can call; a
reconnection checks again. Off production, a failure that concerns the
scope refuses the profile too: a time field that is not a date, a selector
field that is not a plain keyword field (on a text field a term matches a
token, which widens the scope), mappings that cannot be read when the
source has a selector, or a check that failed before it could type-check
them (a wrong secret, an unreachable backend). Any other failure off
production leaves the source open with a note on `:status`: its terms are
matched locally and its counts scanned until a reconnection checks again.
A refusal quotes what the backend reported (its version, privilege, role,
index or field names) cut to 64 characters of a plain charset, and at most
eight privileges; never a response body.

Known limits:

- Scoped API keys (an Elasticsearch key with role descriptors) are judged
  by the privileges `_security/user/_privileges` reports; they are not yet
  tested against a production cluster.
- Without `tiebreaker`, more documents at one timestamp than one page
  holds is an error: the page cannot resume between them. It fails
  safe; set `tiebreaker` to a keyword field unique per document.

### TLS files of a remote source

The console reads only the project's `.locklog/` (read-only, readable by
agents too), its own home volume (at `/home/locklog`) and the image's
`/etc/ssl`. `locklog mounts` checks the paths, so a profile whose files the
console could not read is refused:

- `tls_ca` (a public certificate): under `<project>/.locklog/`, under
  `/home/locklog/`, or the image's `/etc/ssl/`;
- `tls_cert` and `tls_key` (mTLS): only under `/home/locklog/`, which agents
  never mount. A client key under the project would be readable by agents.
  Copy them into the console's home volume, owned by the console's account
  (10051) and private to it.

`locklog doctor` reports the same cases, and a `tls_ca` under `.locklog/`
that cannot be read.

## `locklog init <agent>`

    locklog init claude|codex|cursor|gemini

Writes the agent's files in the project (lockkit's agentwire): the MCP
server (`locklog mcp`), the skill or instructions, the Cursor rule, and an
example `.locklog/config.toml` when there is none. The Claude Code allow
list (the free tools only) goes to the project's
`.claude/settings.local.json` only, never to your user settings. It never
asks, and a second run changes nothing.

## `locklog doctor`

    locklog doctor [--profile P] [--fix [--yes]] [--json]

An advisory check of what the agent's account can reach where it runs. It is
not a boundary. Findings: the Docker engine (socket or `DOCKER_HOST`), the
groups `docker`, `adm` and `systemd-journal`, `sudo -n`, euid 0, a readable
`/var/log/journal` or `/var/lib/docker`, cloud credential files, a configured
backend that answers a read without credentials (Loki's label list, the
mappings of an Elasticsearch or OpenSearch source's indices), and the clouds' metadata
credential paths. Probes report a status code and whether the API was
recognised, never a response body. Residuals: Landlock, containers with
`IpcMode` shareable, swarm mode. It also checks that the agents installed
here are wired to locklog in this project.

Each finding prints a remedy. On a production profile the findings are red
and doctor exits 1. Before any profile (no `locklog profile add` yet), the
account is checked as for a production profile, with a warning that names
`locklog profile add`. The launcher runs it as the image's agent account with
the host's network and the host's facts, with the socket volume of the
lock `lox run` runs (read-only) when there is one.

`--fix` wires the agents installed here that are not wired yet (`locklog
init <agent>`, the only repair it makes), asking before each unless `--yes`;
it runs as you, with the project writable. `--yes` without `--fix` is a
usage error, and so is `--fix` without a terminal and without `--yes`.
`--json` prints one line (lockkit's `verbs.Doctor`): `ok`, the repairs made
and every check; the exit status is 0 exactly when no check fails.

## The own-container recipe

A host agent is the non-production trial: its MCP server refuses production
profiles (`E_PRODUCTION_HOST_AGENT`). For a production profile, run the
agent with lea, or in an image of its own, as a non-root user without sudo
that reaches the console only through its socket. Add this to the agent's
Dockerfile, after its packages are installed, with the locklog image
pinned by digest (`docker buildx imagetools inspect
ghcr.io/davidgodefroid/locklog:<version>`):

```dockerfile
# locklog's client, its root-owned system file (the console account and
# the clients group the socket admits), and the accounts it names.
COPY --from=ghcr.io/davidgodefroid/locklog@sha256:<digest> --chown=root:root --chmod=0755 /usr/local/bin/locklog /usr/local/bin/locklog
COPY --from=ghcr.io/davidgodefroid/locklog@sha256:<digest> --chown=root:root /etc/locklog/system.toml /etc/locklog/system.toml
# The console account (10051) only names the socket's owner, which the client
# checks: no shell, no home, no password, nothing runs as it here. The agent
# user is not root, has no sudo, and is in locklog-clients (10050).
RUN set -eu; \
    if command -v useradd >/dev/null 2>&1; then \
      groupadd -g 10050 locklog-clients; \
      useradd -M -N -u 10051 -s /usr/sbin/nologin locklog; \
      useradd -m -u 10052 -g locklog-clients -s /bin/sh agent; \
    else \
      addgroup -g 10050 locklog-clients; \
      adduser -D -H -u 10051 -s /sbin/nologin locklog; \
      adduser -D -u 10052 -G locklog-clients -s /bin/sh agent; \
    fi; \
    chmod 0755 /etc/locklog; chmod 0644 /etc/locklog/system.toml; \
    if command -v sudo >/dev/null 2>&1; then echo "the agent image must not have sudo" >&2; exit 1; fi
USER 10052:10050
```

Run the agent's container with the socket volume of the lock `lox run`
runs, read-only, and the project at its own path (the socket is named after
the project's path), without capabilities or a way to gain privileges:

    docker run --rm -it --cap-drop ALL --security-opt no-new-privileges \
      -v lockfamily-<hash>_<name>-run:/run/locklog:ro -v "$PWD:$PWD" -w "$PWD" your-agent-image

(`<hash>` and `<name>` as `.lockfamily/up.json` names the lock's
`socket_volume`.) In it, the agent's MCP server is `locklog mcp`. An agent
uid other than 10052 (change it in both places) needs `allowed_uids: [<uid>]`
on the lock in `lockfamily.yaml`, which `lox run` passes to the console as
`--allowed-uids`. Every agent whose container mounts the socket volume
reaches the console on it: one volume is one trust domain.

CI builds this snippet into an agent image and calls the console from it
(job `own-container recipe (e2e)`, for uid 10052 and for an uid admitted by
`--allowed-uids`).

The [HolmesGPT recipe](recipes/holmesgpt.md) applies it to HolmesGPT's CLI,
with locklog as its stdio MCP server.
