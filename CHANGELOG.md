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
- Parsing: the `syslog` (RFC 5424 with structured data, RFC 3164 with or
  without PRI, rsyslog's RFC 3339 variant) and `combined` (NCSA
  common/combined access logs) formats, detected by `auto` after JSON and
  logfmt, and the `cri` and `docker-json` container frames (runtime time,
  stream, split lines joined, payload decoded with `auto`).
