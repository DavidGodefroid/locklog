# Setup and doctor

## `locklog setup`

Run it in the project directory, in your own terminal:

    locklog setup

The launcher gathers the host's facts (the log files under `/var/log` and
`LOCKLOG_EXTRA_ROOTS`, the journal directories, `docker ps`, the installed
agents) and runs `setup` in the image as you, with the project writable and
no network. It writes:

- `.locklog/` (yours, 0755) and `.locklog/config.toml`: one source per log
  file family (`/var/log/nginx/access.log*` covers `access.log.1` and
  `access.log.2.gz`), the journal, and the running containers in a
  `<profile>-docker` profile (a docker source runs in a console of its own).
  An existing `config.toml` is kept. Nothing is read until the console shows
  the profile to you.
- the agent's wiring, for `--agent host`: `locklog init <agent>` for every
  agent found. The Claude Code allow list goes to the project's
  `.claude/settings.local.json` only, never to your user settings.

Questions:

- *Is this a production profile?* An unanswered question is **yes**.
- *Where does the agent run?* `host` (a non-production trial: the host
  agent's MCP server refuses production profiles with
  `E_PRODUCTION_HOST_AGENT`), `container` (an image of its own), or `lea`.

For scripts: `locklog setup --yes --no-production --agent host`, with
`--only /srv/app/logs` to propose only the log files under that directory
(no journal, no container).

CI checks this path end to end (job `five-minutes`): from `setup` to the
first masked answer of an MCP client spawned from the written `.mcp.json`
in under 300 s, with the allow list holding the free tools only. The jobs
`own-container recipe (e2e)` and `production guard (e2e)` build an agent
image from the printed snippet and check that a host agent is refused on a
production profile.

### The own-container recipe

`locklog setup --agent container` prints a Dockerfile snippet for your
agent's image: the locklog binary and the root-owned
`/etc/locklog/system.toml` copied from the locklog image by digest, a
non-root `agent` user without sudo in `locklog-clients` (10050), and the
`locklog` account (10051), which only names the socket's owner the client
checks. Run the agent's container with
`--cap-drop ALL --security-opt no-new-privileges -v locklog-run:/run/locklog -v "$PWD:$PWD" -w "$PWD"`. An agent uid other
than 10052 needs `locklog console --allowed-uids <uid>`. Every agent that
mounts one `locklog-run` volume reaches every console on it: one volume is
one trust domain.

### A Compose Loki without auth

`locklog setup --loki-proxy loki` generates an authenticating TLS proxy
(Caddy) for a Loki service of a running Compose project:

- Caddy gets only a bcrypt hash of the read token;
- the token is shown once on your terminal (setup refuses without one) and
  is written nowhere: the console asks for it, or reads it from Vault
  (`--vault-path`);
- the internal CA's private key is discarded once the server certificate is
  signed;
- the files go to `~/.config/locklog/proxy/<project>-<service>/` (0700,
  outside the project); only the CA certificate is copied to `.locklog/`,
  for the profile's `tls_ca`.

The source goes into a `<profile>-loki` profile, commented out until it has
a selector (`--loki-selector app=api`). The console reaches the proxy on the
Compose network: `LOCKLOG_NETWORK=<network> locklog console --profile
<profile>-loki`.

### Elasticsearch and OpenSearch

setup detects no Elasticsearch or OpenSearch backend. It writes a commented
`<profile>-search` entry to fill in: `kind = "elastic"` or `"opensearch"`,
the `indices`, the keyword `trusted_fields`, `auth` and `user`. Give the
console a read-only key (`read` and `view_index_metadata` on the indices,
`monitor` on the cluster); at connection a production profile refuses a key
with any write or manage privilege and a backend that answers without
credentials. A `tls_ca` must be readable in the console: put it in the
project's `.locklog/`. The console reaches the backend on a Docker network:
`LOCKLOG_NETWORK=<network> locklog console --profile <profile>-search`; the
launcher refuses a remote source without one.

## `locklog doctor`

    locklog doctor [--profile P]

An advisory check of what the agent's account can reach where it runs. It is
not a boundary. Findings: the Docker engine (socket or `DOCKER_HOST`), the
groups `docker`, `adm` and `systemd-journal`, `sudo -n`, euid 0, a readable
`/var/log/journal` or `/var/lib/docker`, cloud credential files, a configured
backend that answers a read without credentials (Loki's label list, the
mappings of an Elasticsearch or OpenSearch source's indices), and the clouds' metadata
credential paths. Probes report a status code and whether the API was
recognised, never a response body. Residuals: Landlock, containers with
`IpcMode` shareable, swarm mode.

Each finding prints a remedy. On a production profile the findings are red
and doctor exits 1. The launcher runs it as the image's agent account with
the host's network and the host's facts.
