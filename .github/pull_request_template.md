## Why

<!-- The problem this solves. Link the issue: "Fixes #123". -->

## What changes

<!-- The approach, and anything a reviewer should look at first. -->

## Checklist

- [ ] A test fails without this change and passes with it.
- [ ] `gofmt`, `go vet ./...`, `go test ./...` and `staticcheck ./...` are clean, and `sh scripts/hygiene.sh` passes.
- [ ] No log content reaches the agent, the audit, an error or a screen without going through the masker.
- [ ] No secret can reach argv, the environment, a file, a log, the socket or an error message.
- [ ] No default is loosened and no way around the masking or the console is added (or the issue discusses it).
- [ ] Docs and `CHANGELOG.md` are updated if behaviour changes.
