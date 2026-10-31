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
- The Docker source: containers' `json-file` logs (rotated `.N[.gz]` files
  included) read by name from the containers root through a name → id map,
  approved globs checked again at read time, console containers never served,
  no read across a mount point; the `docker-json` format with an `attrs`
  allowlist. The launcher binds the containers root (gid 0 for it only), keeps
  the map current with a `docker events` loop, labels console containers, and
  gains `locklog refresh`.

### Fixed

- The launcher chooses the non-recursive bind option from the Docker CLI
  version, which parses it (`bind-recursive=disabled` from CLI 25), not from
  the engine's.
