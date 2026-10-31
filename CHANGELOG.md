# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Repository bootstrap: Go module, `locklog version`, CI (tests on Linux,
  macOS and Windows; hygiene, gofmt, vet, staticcheck, govulncheck).
- Configuration: `.locklog/config.toml` profiles (version 1) with file,
  journald, docker and Loki sources, masking modes, budgets and their
  ceilings, production rules, and the policy diff that marks every
  loosening for the console's review.
- The image (`ghcr.io/davidgodefroid/locklog`, accounts 10050-10052, `-vault`
  variant), the host launcher `scripts/locklog` (the console's confinement
  and read-only, non-recursive mount plan checked on the host; `mcp` as the
  agent account; `update`, `version`), `scripts/install.sh` (cosign-verified
  archive and image, root-owned launcher, snapshot release bases), and the
  release workflow (draft, signed images, anonymous pull, publish, pages).
- Egress for remote sources: an HTTP client pinned to the configured host
  and port (no proxy, no redirects, link-local addresses refused), the Loki
  read-only allowlist checked segment by segment, response caps, the tls
  modes, and the production check that refuses a backend answering a data
  read without credentials.
- The console (`locklog console`): the agent's log methods served through
  lockkit's console over a seam to the engine, the launcher's checks
  before any log is read (dev:inode of `.locklog` and of each mount root;
  no network for a local-only profile), an audit record per call written
  before the answer leaves (fail closed; never a predicate or a value), and
  `--allowed-uids`.
- The console opens the engine of the approved policy: a masker per source
  on one pseudonym epoch (rotated and pruned as the profile says), `K_ref`
  and the local index in the home volume (a missing or corrupt key refuses
  the start), the file, journald and docker sources given only the mount
  roots the launcher checked (every planned root must be in
  `LOCKLOG_EXPECT_ROOTS`, the containers root may be the launcher's "not
  checked from the host" case; a Loki source is refused until it is
  supported), the calibrated cost model, the profile's per-call budgets, and
  `log.status`/`log.sources`. In its image the console confines itself with
  Landlock before it opens any source, and a docker source on a production
  profile needs Landlock or openat2; `:status` shows the Landlock state.
  The mounts are checked again on every call, and a session lost under a
  call ends it with a connection-lost error (the next call reconnects).
- The MCP server (`locklog mcp`): `locklog_status`, `locklog_sources`,
  `locklog_search`, `locklog_count` (also `by_pattern`), `locklog_patterns`
  (the console now serves `log.patterns`), the PII rules and change requests, each
  a thin adapter over the console; a host agent (the launcher's `mcp`) is
  refused on production profiles, as the console's status reports them,
  with the structured refusal `E_PRODUCTION_HOST_AGENT` (and when the
  status does not say: the guard fails closed). Its status tool never
  shows that profile's status, and no tool's structured output carries
  more than its text. Inputs are bounded by their schemas; integers
  beyond 2^53 come back as decimal strings. The PII tools answer once
  the console serves PII rules. `locklog_pii_add` is free (it only masks
  more), on production too for an agent that is not a host agent.
  `locklog init <agent>` wires Claude Code, Codex, Cursor or Gemini CLI;
  for Claude Code it merges the free tools (never an approved one such as
  `locklog_request_change`) into the project's `.claude/settings.local.json`
  `permissions.allow`, keeping the human's entries; the shared
  `.claude/settings.json` and the user's own settings are never written.
  A re-run adds back the entries the human removed, and prints each entry
  it added (`added to permissions.allow in .claude/settings.local.json:
  <entry>`); remove an entry again to be asked for it. init warns when git
  does not ignore `.claude/settings.local.json`.
- The Docker source: containers' `json-file` logs (rotated `.N[.gz]` files
  included) read by name from the containers root through a name → id map,
  approved globs checked again at read time, console containers never served,
  no read across a mount point; the `docker-json` format, and an `attrs`
  allowlist on the `docker-json` frames. The launcher binds the containers root with gid 0, keeps the map
  current with a `docker events` loop, labels console containers, and gains
  `locklog refresh`. gid 0 applies to the whole console, so a docker source
  runs in a console of its own: the mount plan and the launcher refuse it
  beside a file or journald source.
- `internal/landlock`: a Landlock ruleset the console applies to itself
  (read-only beneath the log and containers roots, writes only to its
  volumes and /tmp, rights chosen by ABI), and the rule that a docker source
  on a production profile needs Landlock or openat2 with `RESOLVE_NO_XDEV`.
- Parsing: the `syslog` (RFC 5424 with structured data, RFC 3164 with or
  without PRI, rsyslog's RFC 3339 variant) and `combined` (NCSA
  common/combined access logs) formats, detected by `auto` after JSON and
  logfmt, and the `cri` and `docker-json` container frames (runtime time,
  stream, split lines joined, payload decoded with `auto`).
- Masking on lockkit v0.8.0: its secret detector (credentials, token
  shapes, private keys, URL userinfo) and `LooksSecret` names are step 1,
  always on and never a profile setting (`detectors = ["secret"]` is
  refused); public IP addresses (`ip`) join the default detectors;
  `person_name` and `phone_loose` are opt-in by naming them in a profile's
  `detectors`.
- Patterns (`log.patterns`): the top templates of the masked message text
  (pseudonyms keep their kind, `⟦email:…⟧`; digit-bearing parts become
  `<*>`), with first/last times, an optional `baseline` offset (the same
  window earlier: baseline counts, `new` and `gone` patterns, each granule
  read once, even when a file grows between the two plans; the baseline's
  patterns capped apart from the window's, `truncated` past the cap; with a
  remote source both windows fit its range budget), plan-based admission
  and free continuations; `count` gains `by_pattern`.
- `locklog setup`: the trusted `.locklog/` (yours, 0755, writable by no one
  else; checked again by the launcher afterwards) and a first
  `config.toml` from the host's facts, which the launcher gathers on the
  host (`internal/hostfacts`): log file families with their rotated and
  compressed siblings under one glob, the journal, the running containers
  (in a `-docker` profile of their own), never a console container. It
  asks whether the profile is production, and an unanswered question is
  yes; `--yes --no-production --agent host` for scripts. `--agent host`
  runs `agentassets.InitProject` for each detected agent (the Claude Code
  allow list in the project's `.claude/settings.local.json` only, nothing
  at user scope) and prints what it wrote; `--agent container` prints the
  own-container recipe (a Dockerfile snippet copying the binary and a
  root-owned `/etc/locklog/system.toml` from the image by digest, a
  non-root agent user without sudo in group 10050, the console account
  10051 kept only as the name the client checks the socket's owner
  against, the run line, `--allowed-uids` for another uid, one
  `locklog-run` volume = one trust domain); `--agent lea` says where lea
  stands. `--loki-proxy SERVICE` wires `internal/authproxy` for a Compose
  Loki: Caddy gets only a bcrypt hash, the token is shown once on the
  terminal (and refused without one), the CA key is discarded, the files go
  to `~/.config/locklog/proxy/` (0700, outside the project), and only the
  CA certificate is copied beside the config, for `tls_ca`.
- `locklog doctor` (advisory, not a boundary): the Docker engine and
  `DOCKER_HOST`, the groups `docker`, `adm` and `systemd-journal`, `sudo -n`,
  euid 0, a readable `/var/log/journal` or `/var/lib/docker`, cloud
  credential files, unauthenticated read probes of the configured backends
  and of the clouds' metadata credential paths (a status code and whether
  the API was recognised; never a response body), with a remedy for each
  finding; residuals: Landlock, containers with `IpcMode` shareable, swarm
  mode. On a production profile the findings are red and doctor exits 1.
  The launcher runs it as the agent account with the host's network.
- `locklog setup --only DIR,...`: detect only the log files under those
  directories (no journal, no container), for scripted runs.
- CI end to end on the LL-09b harness: `five-minutes` (the launcher on
  PATH, `setup --yes --no-production --agent host`, the console, and an
  MCP client spawning the server the written `.mcp.json` names: an exact
  count and a masked search under 300 s, and the written allow list equal
  to the free tools), `own-container recipe (e2e)` (an agent image built
  from the printed snippet calls the console as uid 10052, not root, no
  sudo), and `production guard (e2e)` (the launcher's `mcp` against a
  production console is refused with `E_PRODUCTION_HOST_AGENT`).

### Fixed

- A Loki time slice holding more than one call's byte budget is split into
  narrower epoch-aligned slices (down to 1 s) and paged with a cursor, in
  both orders, instead of being refused; a slice still over the budget at
  1 s is refused with a message that no longer speaks of compressed files.
- The launcher chooses the non-recursive bind option from the Docker CLI
  version, which parses it (`bind-recursive=disabled` from CLI 25), not from
  the engine's.
