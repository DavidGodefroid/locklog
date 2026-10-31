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

### Fixed

- The launcher chooses the non-recursive bind option from the Docker CLI
  version, which parses it (`bind-recursive=disabled` from CLI 25), not from
  the engine's.
