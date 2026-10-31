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

For scripts: `locklog setup --yes --no-production --agent host`.

### The own-container recipe

`locklog setup --agent container` prints a Dockerfile snippet for your
agent's image: the locklog binary and the root-owned
`/etc/locklog/system.toml` copied from the locklog image by digest, a
non-root `agent` user without sudo in `locklog-clients` (10050), and the
`locklog` account (10051), which only names the socket's owner the client
checks. Run the agent's container with
`-v locklog-run:/run/locklog -v "$PWD:$PWD" -w "$PWD"`. An agent uid other
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

## `locklog doctor`

    locklog doctor [--profile P]

An advisory check of what the agent's account can reach where it runs. It is
not a boundary. Findings: the Docker engine (socket or `DOCKER_HOST`), the
groups `docker`, `adm` and `systemd-journal`, `sudo -n`, euid 0, a readable
`/var/log/journal` or `/var/lib/docker`, cloud credential files, a configured
backend that answers a read without credentials, and the clouds' metadata
credential paths. Probes report a status code and whether the API was
recognised, never a response body. Residuals: Landlock, containers with
`IpcMode` shareable, swarm mode.

Each finding prints a remedy. On a production profile the findings are red
and doctor exits 1. The launcher runs it as the image's agent account with
the host's network and the host's facts.
