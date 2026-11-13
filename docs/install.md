# Install locklog

locklog is a Lock of the [Lock Family](https://github.com/DavidGodefroid/lockfamily).
Its console is started by `lox run` (lockhub), which you keep open in a
terminal of its own, outside the agent: it starts the hub and the locks,
shows every ticket and decides it, by its rules or by you.

## Status

- locklog v0.2.1 is released: see the [CHANGELOG](../CHANGELOG.md).
- `lox add locklog` and the locklog console in `lox run` need lockhub
  v0.10.0 or later ([lockhub#84](https://github.com/DavidGodefroid/lockhub/issues/84),
  [#86](https://github.com/DavidGodefroid/lockhub/issues/86),
  [#87](https://github.com/DavidGodefroid/lockhub/issues/87)).
- The tap's `locklog` formula installs v0.2.1, and the `lockfamily` formula
  includes locklog.
- Without Homebrew, `scripts/install.sh` ([below](#without-homebrew))
  installs the launcher, whose verbs you can run yourself ([setup.md](setup.md)).

v0.1.0 shipped files, journald, Docker and Loki, and Elasticsearch and
OpenSearch as a preview. v0.2.0 makes the console hub-only, started by
`lox run`, with per-profile auto rules. v0.3.0 adds the Elasticsearch and
OpenSearch incident gates and the masked export.

## Prerequisites

- A Linux host with the logs.
- Docker ≥ 19.03.
- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/),
  to verify the release and the image.
- Homebrew, or (for `install.sh`) sudo for `/usr/local/bin`.

## With Homebrew

```sh
brew trust davidgodefroid/tap                # Homebrew asks you to trust a third-party tap once
brew install davidgodefroid/tap/lockfamily   # or only this tool: brew install davidgodefroid/tap/locklog
cd ~/projects/shop                           # the project whose logs the agent investigates
lox add locklog logs                          # or: lox init
lox run                                       # in a terminal of its own, kept open
```

`lox add locklog <name>` runs locklog's three launcher verbs from the
project ([setup.md](setup.md)):

- `locklog profile add --non-interactive --json --profile NAME`: a profile
  of `.locklog/config.toml` from the logs this host has (files, journald,
  containers); never a secret;
- `locklog init claude`: the agent's `.mcp.json`, skill and allow list (the
  free tools only). For another agent: `locklog init codex`, `cursor` or
  `gemini`;
- `locklog doctor --fix --yes --json`: what an agent here can reach.

`lox run` then reviews the profile, starts the console (attach with `lox
attach <name>` for its own questions: the policy review at its first
start) and decides the tickets.

Then, in another terminal, ask your agent: *"when did the 502s start?"*.
It calls `locklog_count`, `locklog_patterns` and `locklog_trace`: free,
masked, audited. A scan, an unmask or an approved lookup becomes a ticket
that `lox run` shows you and, with the default rules, never approves on
its own.

On the host, `locklog mcp` (the server `.mcp.json` names) refuses every
call on a production profile (`E_PRODUCTION_HOST_AGENT`): the host agent is
a trial for non-production data, since your agent runs on your own
account, where it could still read the logs directly. Without `lox run`,
it says to run `lox run` first.

## Without Homebrew

`install.sh` installs locklog's launcher alone:

```sh
curl -fsSL https://locklog.dev/install.sh | sh
```

It installs the latest **published** release, or `LOCKLOG_VERSION=vX.Y.Z`.
It verifies the release with cosign before it installs a root-owned
`/usr/local/bin/locklog`, and the launcher runs the image by its signed
digest. To read the script first:

```sh
curl -fsSLO https://locklog.dev/install.sh   # or raw.githubusercontent.com/DavidGodefroid/locklog/main/scripts/install.sh
less install.sh && sh install.sh
```

`locklog update` moves to another release; `locklog version` shows the
launcher's and the image's versions.

## The managed directory

When this machine has the Lock Family's managed directory
(`/etc/lockfamily` on Linux, `/Library/Application Support/lockfamily` on
macOS: [usage.md](usage.md#managed-configuration)), the launcher mounts it
read-only on `/etc/lockfamily` in every container it runs, the path the
image reads `managed.toml` from, as `lox run` mounts it in its locks. So
`locklog managed show`, `managed check`, `doctor`, `profile`, `init` and
`mcp` see the bounds the lock enforces. The whole directory is mounted:
the signature bundle, `signer.toml` and the `managed.toml.verified` stamp
come along. Ownership is checked in the container as on the host (a bind
mount keeps owner and mode): the file and the directory must be root's and
writable by root only. No directory: no mount, and locklog runs without a
managed policy. A path that is not a directory (a file, a dangling link)
or that holds a character a docker mount cannot carry (`:`, `,`, ...)
stops the launcher before it runs anything.

On macOS, Docker Desktop shares `/Users`, `/Volumes`, `/private`, `/tmp`
and `/var/folders` only: add `/Library/Application Support/lockfamily` in
Settings > Resources > File sharing, or the launcher's commands fail with
`mounts denied` (never without the policy).

## For production

On production the agent must not be able to read the logs, the Docker
socket or the backends itself (precondition P1 in
[security-model.md](security-model.md)). Run it:

- with [lea](https://github.com/DavidGodefroid/lea), which runs the agent
  in a container of its own with the lock's socket mounted;
- or in **its own container**: [setup.md](setup.md#the-own-container-recipe)
  has a tested Dockerfile snippet for your agent image and the `docker run`
  line. The agent user must not have sudo.

Your agent CLI's own login (Anthropic, OpenAI, Google, …) is yours to set
up. Then run `locklog doctor` where the agent runs: it checks the common
ways P1 fails, and on a production profile its findings are errors.
