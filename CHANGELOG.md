# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Hub mode (LL-23): `locklog console` takes lockkit's hub flags (`--hub`,
  `--hub-key-file`, `--instance`, `--hub-plain-http`, `--devices-file`,
  `--require-device`, `--seal-clear`, `--facade-keys-file`; with a devices
  file, `read-pii` requires a device by default), and `locklog hub-key
  --instance NAME` prints the instance key for `lox up`. A scan, an
  unmask or an approved lookup becomes a plan bound to the peer, the
  agent's token, the policy and the engine's keyed plan hash, pushed to
  lockhub with a masked screen; the clear screen, secrets redacted, goes
  sealed to the pinned devices only. The agent hears `pending` with the
  ticket id only (no plan hash, digest or policy fingerprint) and runs the
  same call with `ticket` once decided: the engine plans it again and it
  runs once if the keyed plan hash is the ticket's (`E_STALE` otherwise).
  A `read-pii` decision from a facade other than `tty`, `deck` or `mobile`
  is refused by the console. Expired tickets are renewed; decisions,
  renewals and reveals are audited; with the hub down, free reads go on.
  The launcher binds the hub files into the console and passes the hub
  flags to it only; `locklog_status` shows the hub mode and instance.
  The requester the hub shows is the kernel-verified peer uid, never a name
  the agent declares; an approved method without peer credentials is
  refused in hub mode. In hub mode a console reading only local logs
  accepts one network interface, the one it reaches lockhub on (`lox up`'s
  internal network), and still refuses any other. Built on lockkit v0.8.1.

- The console's clear view: with clear results on (Ctrl-O, lockkit's
  switch), the records an agent call returned are printed on the console's
  own terminal with their pseudonyms in clear (secrets, redactions and
  masked field names kept), counted in the audit (`shown_clear`), never
  sent to the agent; an unmask approval screen shows its record in clear
  there too, and says Ctrl-O shows it when the switch is off.
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
  checked from the host" case), the calibrated cost model, the profile's per-call budgets, and
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
- Engine read-around calls: `log.context` (the records around a ref, before
  and after up to 50, the ref's record checked by its keyed digest),
  `log.trace` (one clear id or pseudonym over a range, whole words of the
  masked view only, with search's plans, budgets and cursors) and `log.tail`
  (new records matching a filter for up to 50 s, at most 200), served by
  the console and as the `locklog_context`, `locklog_trace` and
  `locklog_tail` tools.
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
  against, the run line with `--cap-drop ALL --security-opt
  no-new-privileges`, `--allowed-uids` for another uid, one
  `locklog-run` volume = one trust domain); `--agent lea` says where lea
  stands. The home directory is never a project: setup refuses it, and the
  launcher's walk ignores a `~/.locklog/`. The facts file is 0600 (doctor,
  which runs as the agent account, gets it on its input). `--loki-proxy SERVICE` wires `internal/authproxy` for a Compose
  Loki: Caddy gets only a bcrypt hash, the token is shown once on the
  terminal (and refused without one), the CA key is discarded, the files go
  to `~/.config/locklog/proxy/` (0700, outside the project), and only the
  CA certificate is copied beside the config, for `tls_ca`.
- `locklog doctor` (advisory, not a boundary): the Docker engine and
  `DOCKER_HOST`, the groups `docker`, `adm` and `systemd-journal`, `sudo -n`,
  euid 0, a readable `/var/log/journal` or `/var/lib/docker`, cloud
  credential files, unauthenticated read probes of the configured backends
  and of the clouds' metadata paths, none of which issues a token (Azure:
  the instance document, "an identity may be available") (a status code and whether
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
- Rolling budgets (LL-19), per source and for the console: bytes processed
  per hour (plan-based, granule-rounded; remote: the bytes fetched),
  remote backend requests per minute (paced, refused past the call's
  deadline) and server-side metric queries per hour; search, count,
  patterns, trace, context re-reads, tail polls and continuations all draw
  on them and are refused with `E_OVER_BUDGET` and the estimate before
  touching data. `log.status` shows what is left.
- `log.scan` (`locklog_scan`): a search, count, patterns or trace over the
  free budgets, approved once (class `read`) for its whole plan. The plan
  hash is keyed (HMAC under `K_ref`) and binds the tool, the sources, the
  absolute range, the predicates, the budget and the policy fingerprint;
  the byte plan is frozen at the approval; continuations are free and
  need no new approval until the plan ends or the 30-minute TTL; the
  cursor is bound to the scan and the peer uid; a reissued scan with the
  same plan re-attaches; each call's deadline is min(240 s, what is left
  of 570 s since the request); a remote scan has its own request pacing,
  not the rolling per-minute budget.
- `log.unmask` (`locklog_unmask`): the clear values of exact pseudonyms of
  one record, once, on a `read-pii` approval auto mode never gives; the
  plan hash binds the ref, the record's keyed digest, the epoch and the
  exact spans, checked again after the approval (`E_STALE`); secrets and
  values that held a secret span are never revealed; `unmask = "never"`
  (the production default) refuses with `E_UNMASK_NEVER`.
- `log.lookup` (`locklog_lookup`): the pseudonyms of clear values of a
  detector kind (equality only), refused for secrets, field names and
  template tokens; limited by distinct values per hour per peer uid and per
  console; `lookup = "approved"` makes it a `read-pii` approval; audited by
  pseudonym only.
- Plan hashes, query and record digests and the policy fingerprint never
  reach the agent (#26): a scan is known by a random id.
- The Elasticsearch 8 / OpenSearch 2 source (`kind = "elastic"` or
  `"opensearch"`): allowlisted read routes on the source's own indices
  (`_search`, `_count`, `_field_caps`, `_mapping`, `_settings`, `/`,
  `_security/user/_privileges`, `_resolve/index`, OpenSearch's
  `authinfo`), each with its own query-parameter allowlist (the egress
  layer now checks parameters per route, Loki's included); typed query
  bodies (time range, `term`/`terms` on trusted keyword fields, sort with
  an optional tiebreaker, `search_after`, size and timeout caps,
  `date_histogram` and `terms` counts) with text matched locally,
  untrusted fields dropped, multi-valued fields and `!=` evaluated alike
  by the server and the engine (empty values kept local); the Loki paging
  and byte model (lazy slices, bytes counted per page against the call's
  limit, bounded Around and Reread, `MaxSlices`, `Split` of an
  over-budget slice); `auth = "api_key"` (Elasticsearch `ApiKey`). A
  production privilege check that fails closed: any grant beyond a
  read-only allowlist, on any pattern, alias or data stream, any
  OpenSearch role not known read-only (or vouched for in
  `read_only_roles`), an OpenSearch answer without a role, and a client
  certificate for OpenSearch are refused. Field checks over every index:
  trusted, selector and tiebreaker fields must be plain keyword fields
  (aliases judged by their target; normalizers, scripts, runtime fields
  and `copy_to` into them refused; dynamic templates accepted only when
  provably harmless; `dynamic` other than a boolean, true, false or
  strict refused); `ignore_above`, `null_value` and non-standard index
  modes keep terms local. Until the newest `Check` has succeeded, no
  trusted term is pushed and no count is served on the server, and a
  stream whose pushed term is no longer server-side is stale.

- The console opens Loki, Elasticsearch and OpenSearch sources (#96): the
  egress client of each (its allowlist, the credentials the console asked
  for or read from Vault, its tls mode), with the source's selector,
  trusted labels, metadata and fields, indices and time, message and
  tiebreaker fields. At connection the unauthenticated-read probe and, for
  Elasticsearch / OpenSearch, the privilege and mapping check run; a
  production profile is refused on either (an open endpoint, a
  write-capable key), with an error that quotes no credential or response
  body. Off production a failed check is noted on `:status` and the source
  matches its terms locally until the console reconnects. Remote sources
  use the remote budgets: their range, `limits.remote.count_range` for
  counts the server answers, and `limits.remote.requests_per_minute` for
  every call, `log.sources` included. The launcher refuses a profile with a
  remote source without `LOCKLOG_NETWORK`; `locklog doctor` probes
  Elasticsearch and OpenSearch mappings without credentials; `locklog
  setup` writes a commented Elasticsearch / OpenSearch profile entry.

### Fixed

- `locklog console --profile P --allowed-uids UID` (the own-container
  recipe's line for an agent uid the image does not know) works through
  the launcher: the mount plan (`locklog mounts`) gets the profile only.
- `unmask = "never"` refusals no longer name a `:reveal` command; they ask
  for the console's clear view (Ctrl-O). `locklog setup --agent host` with
  no agent found points to `--agents <agent>` instead of `locklog init`,
  which the host launcher cannot run.
- `Scanned.Bytes` counts the bytes a remote source fetched and the call
  dropped (out of a slice's range, past the call's byte limit, or more than
  the time left could mask), as the rolling budget charges them (#67).
- A call naming no source has the remote per-call byte budget when a
  remote source is configured.
- `locklog_request_change` bounds its text to the console's 500 bytes.
- A Loki time slice holding more than one call's byte budget is split into
  narrower epoch-aligned slices (down to 1 s) and paged with a cursor, in
  both orders, instead of being refused; a slice still over the budget at
  1 s is refused with a message that no longer speaks of compressed files.
- The launcher chooses the non-recursive bind option from the Docker CLI
  version, which parses it (`bind-recursive=disabled` from CLI 25), not from
  the engine's.
