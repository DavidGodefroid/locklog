# Contributing to locklog

Thanks for your interest. Bug reports, fixes and new test cases are welcome.
For security issues, follow [SECURITY.md](SECURITY.md) instead of opening an
issue.

## Before you start

- For anything beyond a small fix, open an issue first to agree on the
  approach. locklog is a security tool: features that loosen a default, add
  a way around the masking or the console, or add a dependency need a clear
  case.
- Code, comments, docs and commit messages are in English.
- By contributing you agree that your work is licensed under the Apache
  License 2.0.

## Where the code lives

The product-neutral half of locklog (console socket and protocol, peer
checks, approvals, terminal, audit log, config lookup and the
approved-policy store, personal-data detectors, output caps, error
scrubbing, MCP plumbing, agent wiring) lives in
[lockkit](https://github.com/DavidGodefroid/lockkit), shared with the other
lock* tools; its GUIDE.md is the contract. This repository keeps what is
logs: the sources, the parsers, the masking pipeline, the query engine and
its budgets, locklog's console, its MCP tools and its agent texts.

Once locklog depends on lockkit, lockkit is pinned in `go.mod`. Do not copy a lockkit package here or work
around it: a change to a shared package is asked for and made in lockkit
first, then locklog pins the new lockkit version. To work on both at once,
add an uncommitted `go.work` (`use (. ../lockkit)`; `go.work` is ignored).

## Build

```sh
CGO_ENABLED=0 go build ./cmd/locklog
```

Requires Go 1.26 or later. Every target builds with `CGO_ENABLED=0`; keep
dependencies pure Go.

## Tests

locklog is developed test first: write the failing test, then the code that
makes it pass.

```sh
go vet ./...
go test ./...
```

The module also builds for Windows, and CI runs the unit tests on
`windows-latest`. A test file that needs Unix accounts, file modes, sockets
or terminals starts with `//go:build unix`; a single test skips with
`t.Skip` and the reason.

Never point a test at a real remote service or at real logs: tests use
generated corpora with synthetic values.

## Pull requests

- Write the failing test first, then the fix.
- Keep `gofmt`, `go vet`, `staticcheck` and `govulncheck` clean, and
  `sh scripts/hygiene.sh` passing.
- Keep the security invariants: every outgoing string goes through the
  masker; no secret in argv, environment, files, logs, the socket protocol
  or error strings; nothing writes to a log source or backend; fail closed
  on anything ambiguous.
- One logical change per pull request, with a commit message that explains
  why.

Pull requests target `main`, which is protected:

- the CI checks must pass and the branch must be up to date with `main`;
- every review thread must be resolved;
- pull requests are squash-merged: the title becomes the commit subject and
  the description its body, so write both for the history. Use a
  [conventional commit](https://www.conventionalcommits.org/) prefix
  (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, ...).

Workflows on pull requests from forks run after a maintainer approves them.
Participation is governed by the [code of conduct](CODE_OF_CONDUCT.md).

Every `uses:` in `.github/workflows/` names a full commit SHA with its
version as a comment (`actions/checkout@<sha> # v7.0.1`); Dependabot bumps
both.
