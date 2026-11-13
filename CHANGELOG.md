# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The company's managed configuration (`/etc/lockfamily/managed.toml`, the
  Lock Family's `managed.toml`): locklog enforces its `[locklog]` section
  (#147). `[locklog.profiles.<name>]` are served as written and cannot be
  redefined in the config files; `[locklog.defaults]` fill the keys a
  profile leaves unset; `[locklog.bounds]` bound every profile (production,
  structured, text, unmask, lookup, strict, prefilter, user_journals,
  pseudonym rotation and max age, auto rules, every limit, and the
  allowlists kinds, hosts, paths, auth, credentials, tls, network,
  extra_roots): a profile beyond them is refused at the console's start
  and at every policy poll, with no prompt, citing the managed key, and no
  human can approve past it. Required `detectors` and
  `[[locklog.bounds.pii_mask]]` rules are always on; a project `[[allow]]`
  that could show what a managed mask hides is refused. `[family]
  vault.required` requires `credentials = "vault"`. Keys: docs/usage.md.
- `locklog managed show` and `locklog managed check [--profile NAME]
  [--project DIR]` (exit 3 on a violation, one `blocked by company policy:
  …` line each; `lox run` runs it before it starts the lock), a `managed`
  line in `locklog doctor`, and `locklog console` exits 3 when the managed
  configuration refuses it.

### Fixed

- MCP (#144): a docker source's `container` addressed as a field (`where`,
  `fields`, count `by`) was answered with nothing; it is now refused,
  naming the label to use. `locklog_count` takes `by_labels` (a docker
  source's container, Loki labels). A cursor continues when the range is
  left out (the first call's window), and a cursor given with other
  parameters is refused naming the ones that differ; the tool descriptions
  say to repeat them.
- JSON lines are decoded about 8 times faster (#150): locklog reads them
  with a scanner of its own instead of encoding/json's token reader,
  exactly as before (the same strings, numbers, member order, depth and
  key limits). An approved scan of JSON logs runs about 20 % faster.

### Changed

- lockkit v0.14.1 (from v0.13.1). `locklog console` without its hub flags
  now refuses with lockkit's "the console is launched by `lox run` only"
  (was `lox up`, lockkit#147); docs/usage.md quotes the new text.
- lockkit v0.19.0 (from v0.14.1, #147). The default value detectors mask
  more: a French NIR is recognised before a card number, `phone` is wider,
  `be_niss` is new and an e-mail address may hold an apostrophe. A URL
  holding a user (`https://u@host`) is now refused by lockkit's check
  ("url looks like it embeds a secret"), before locklog's own. The
  `locklog init` text says the allowed calls answer within the console's
  policy and budgets.

## [0.2.1] - 2026-11-07

Fixes and distribution: no new console method or profile setting.

### Changed

- Releases ask the Homebrew tap to bump the `locklog` formula once the
  release is published (`tap` job; needs the `TAP_DISPATCH_TOKEN` secret,
  skipped without it). The install docs lead with
  `brew install davidgodefroid/tap/lockfamily` and `lox add locklog` /
  `lox run`, with `install.sh` as the alternative (#134).
- `scripts/install.sh`'s last hint has lockfamily's wording: `lox add
  locklog` in your project, then `lox run` in a terminal of its own,
  outside the agent, where approvals live (#134).
- lockkit v0.13.1 (from v0.13.0).

### Fixed

- In hub mode, a console with local sources only accepts exactly lox run's
  internal hub network: one interface besides the loopback, the one its
  `--hub` address is routed through, with no default route and no route
  through a gateway. It refuses a second interface, a network with a route
  out, or a network the hub is not on. lox run passes nothing new (#136).
- The console audits the backend's `pii.add` refusals with the client's
  peer (lockkit v0.13.1), and locklog no longer records them a second time
  (lockkit#142).
- Tests: the leak suite no longer fails at random (about one run in five)
  when the random scan id held a 7-digit run of a corpus phone number; the
  whole-corpus scan blanks the scan id only in its exact 24-hex form
  (`TestLeakScannerScanID`). No production code changed (#138).

## [0.2.0] - 2026-11-06

Hub only: the console is started by `lox run` (lockhub) only, and locklog
takes the launcher verbs every lock of the Lock Family takes (#117).
lox run starts a locklog console once lockhub knows the `locklog` type
(lockhub#84, #86, #87); until then the e2e and CI jobs start it the way
lox run will, against lockkit's test hub.

### Added

- Hub mode (LL-23): `locklog console` takes lockkit's hub flags (`--hub`,
  `--hub-key-file`, `--instance`, `--hub-plain-http`, `--devices-file`,
  `--require-device`, `--seal-clear`, `--facade-keys-file`; with a devices
  file, `read-pii` requires a device by default), and `locklog hub-key
  --instance NAME` prints the instance key for `lox run` to pin. A scan, an
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
  `locklog_status` shows the hub mode and instance.
  The requester the hub shows is the kernel-verified peer uid, never a name
  the agent declares; an approved method without peer credentials is
  refused in hub mode. In hub mode a console reading only local logs
  accepts one network interface, the one it reaches lockhub on (`lox run`'s
  internal network), and still refuses any other.

- Tests (LL-16b): the leak, oracle, equivalence and injection suites run
  over a Loki source too (a fake Loki in unit runs, a real one in the CI
  `suites` job), and over the approval tools (approved scans and their
  continuations, unmask, lookup, change requests): no canary in any
  answer, refusal or approval screen (the clear view of an unmask screen,
  the human's own, holds no secret), and an unmask reveals only the span
  approved. `TestLokiIncident` (CI job `loki-incident`) runs job 1 against
  a real Loki with a dense incident hour over a 7-day background, with and
  without a `level` label, behind a latency proxy and on a slowed host;
  the ingest overrides it needs are in `docs/loki.md`. The approved-scan
  test (CI job `scan-volume`) scans 20 GiB of local files on one approval.
- A leak harness over the bytes leaving the console: the canary corpus
  served by a hub-attached console, its IPC socket replies, audit file, MCP
  outputs and hub ticket screens scanned in every encoding: 0 hits
  ([#86](https://github.com/DavidGodefroid/locklog/issues/86)).
- On a production profile without Landlock, `:status` and `doctor` name the
  residual: its local sources are read by an unconfined console
  ([#62](https://github.com/DavidGodefroid/locklog/issues/62)).
- Auto mode per profile for `lox run` (#126): `auto = "full-auto"`, or an
  `[profiles.P.auto]` table setting `read` (an approved scan), `unmask` and
  `lookup` (an approved lookup) to `auto`, `ask` or `deny` (default `ask`
  for all three: unchanged behaviour). `deny` is refused by the console
  before any ticket (`E_AUTO_DENY`; `lookup = "deny"` refuses free lookups
  too); `ask` tickets are signed `never_auto` and an auto rule's approval
  of one is refused; `auto` tickets are left to `lox run`'s auto mode. The
  rules are part of the fingerprinted policy (stored sparsely: approved
  policies keep their fingerprint); moving one toward `auto` is a reviewed
  loosening, with the typed profile name on production. Shown in the
  review, `:status` and `locklog_status` (`auto`); the audit records
  `auto_rule` and `decided_by`. New `locklog profile rules [--json]
  [--project DIR] [--profile NAME]`, which `lox run` reads.
- docs/recipes/holmesgpt.md: HolmesGPT's CLI in its own container with the
  locklog client and only the lock's socket volume from `up.json`, locklog
  as its stdio MCP server, `MCP_TOOL_CALL_TIMEOUT_SEC=600`; a test checks
  that the recipes' tools, ids and volume match the code
  ([#37](https://github.com/DavidGodefroid/locklog/issues/37)).
- `locklog_pii_list` and `locklog_pii_add` are served: an agent rule
  (`[pseudonym ]source:field`, a masked key by its `⟦key:ID⟧`) masks a
  field the agent was shown, from the next call on; it is capped by
  `pii_adds_per_hour` and `pii_rules_max`, stored as a keyed digest in the
  console's home volume only (never in `.locklog/pii.toml`), audited
  accepted or refused with that digest and never a name, and counted in
  `locklog_status` and `:status` (`agent_rules`)
  ([#64](https://github.com/DavidGodefroid/locklog/issues/64)).
- The allow rules of `.locklog/pii.toml` are part of the reviewed policy:
  an added or widened one is a loosening approved at `:review`, a removed
  one applies at once, and the engine applies only the approved ones
  ([#61](https://github.com/DavidGodefroid/locklog/issues/61)).

- The unmask approval screen shows, for each pseudonym, how many records
  holding it agents were given in this epoch (counted by the console from
  the calls it answered and audited, never from clear values;
  [#91](https://github.com/DavidGodefroid/locklog/issues/91)).
- `locklog_status` and `:status` show a docker source's containers map
  (`ok`, `none`, `invalid`), the containers served and the stale ones
  (removed, still mapped); and `budgets.lookups_left_peer`, the lookups
  left to the calling agent's uid.
- An approved scan re-attached after its last answered page says
  `"resumed": true`; a continuation with the cursor of a page answered
  already is refused saying so.

### Changed

- A log root at, beneath or above one of the console's writable
  directories (an extra root under `/tmp` or the home volume) is refused
  instead of losing its read-only Landlock rule
  ([#62](https://github.com/DavidGodefroid/locklog/issues/62)).
- Hub tickets are version 2 (lockkit's kind `read`, the profile as their
  subject), so that `lox run` can apply a profile's rules to them (#126).
- **Breaking.** lockkit v0.13.0 (from v0.8.1). `locklog console` without
  `--hub`, `--hub-key-file` and `--instance` refuses before it touches the
  terminal, the project or the config, with lockkit's "the console is
  launched by `lox up` only" (lockkit's text predates the `lox run` name).
  There is no standalone console and no auto mode.
- **Breaking.** The launcher runs no console: `locklog console` and
  `locklog hub-key` through it say that `lox run` runs them and exit 2.
  Its console path (the mount plan, the containers map and its `docker
  events` loop, `refresh`, the hub-file copies of #114) is gone: `lox run`
  mounts the plan (lockhub#86).
- **Breaking.** The launcher's `mcp` reaches the lock `lox run` runs: it
  finds `.lockfamily/up.json` up from the current directory (the user's, no
  link, not writable by group or others, at most 1 MiB, version 1, this
  workspace's), checks the socket volume's labels and the containers that
  mount it with Docker, and mounts it read-only on `/run/locklog`; with
  none it says to run `lox run` first and exits 2. `--instance NAME` picks
  one of several locklog locks (without it the error names them).
  `doctor` mounts the same volume when there is one.
- **Breaking.** `locklog setup` is replaced by the launcher verbs of
  lockkit's GUIDE.md §14: `locklog profile add [--non-interactive] [--json]
  [--project DIR] [--profile NAME] [--production] [--only DIR,...]
  [--loki-proxy SERVICE ...] [--credentials ask|vault [--vault-path P]]`
  (a profile from the host's logs, appended to an existing config, never
  rewriting one: `exists`; never a secret: lockkit's `verbs` checks),
  `locklog init <agent>` (now run as you, the project writable), and
  `locklog doctor [--fix [--yes]] [--json]` (also checks the agents' wiring;
  `--fix` wires the ones installed here). The own-container recipe and the
  lea placement are no longer printed: the recipe is in docs/setup.md.
- An approved scan's ticket is `never_auto` (still risk `read`, one
  approval for its whole plan), like an unmask's and an approved lookup's:
  `lox run`'s auto mode approves no locklog ticket, and the console refuses
  an auto rule's approval of one (lockkit's `ErrAuto`).
- `locklog mcp --instance NAME` (else `LOCKLOG_INSTANCE`, else the one lock
  lea lists in `LEA_LOCKLOG_INSTANCES`) dials one lock among several
  (lockkit's `client.DialInstance`).
- From lockkit v0.11 to v0.13: the console asks the Vault token at its start
  for a `credentials = "vault"` source (never `VAULT_TOKEN` or
  `~/.vault-token`); a production profile's widenings at the console (the
  policy review, a loosening at `:review`, `:unmask`) take the profile name
  typed exactly; the idle timeout counts only the human's input and the
  backend's methods.
- Remote sources still connect at the console's start (no `connect` ticket,
  lockkit's `lazyconn`, yet).
- CI: the five-minute, own-container, production-guard and e2e jobs start
  the console as `lox run` does, against lockkit's fake hub, until `lox run`
  knows locklog (lockhub#84, #86, #87); the docker-source job writes the
  containers map itself.
- In hub mode an approved scan is bound to the agent's token as well as
  its uid: another agent of the same uid neither re-attaches to it nor
  continues it ([#115](https://github.com/DavidGodefroid/locklog/issues/115)).
- An approved lookup (`lookup = "approved"`) is charged to the lookup
  budget once approved, not when asked: a denied or pending lookup uses
  none of it ([#98](https://github.com/DavidGodefroid/locklog/issues/98)).
- `log.sources` describe requests draw on the remote request budget (since
  0.1.0) and now have the call deadline: with the budget used up they are
  refused at once instead of waiting for the window.
- A free remote call whose request budget has no room before its deadline
  is refused before any request, with its estimate.
- A scan's reason is masked on its approval screen and in the audit, as an
  unmask's or a lookup's; a patterns scan against a baseline names the
  baseline window on its screen; a renewed scan ticket names its inputs
  unchecked instead of unchanged.

### Fixed

- A Loki call's `scanned.bytes` (and the bytes the rolling budget charges)
  leave out the `stats` block of Loki's answers, whose timings changed
  them from run to run (#111).
- A Loki count's boundary log fetches are charged as requests, not as
  server-side metric queries: a 7-day count by a trusted label costs 4 of
  the 120 hourly metric queries instead of up to 132 (#112).
- A count with only trusted fields and labels masks no record whose
  trusted values the masker leaves unchanged when it scans what the index
  does not hold: it counts them by those values, as the index does, at
  parsing speed (#94). Such records are no longer masked failures.
- Masking is about 2 to 2.5 times faster on JSON application logs: clean
  field names, clean trusted values and the decisions a leaf's name and
  path take are cached, values withheld whole (redact-unknown, redact
  rules) skip detection, agent-rule digests are memoized, and a group of
  records is masked while it is read (#104). Job 1 of the Loki incident
  without a `level` label answers within its 5 minutes (#110).
- An approved scan whose plan is long lives as long as its plan's bound
  (twice its time at the cost model's worst-case rate) instead of 30
  minutes, at most 4 hours; its approval screen and `expires_at` say so.
  A 20 GiB scan of local files then completes on its one approval (#104).
- The confined console resolves host names again: Landlock now grants
  `/etc/hosts`, `/etc/resolv.conf` and `/etc/nsswitch.conf`, which Go's
  resolver reads at every lookup (remote sources and the hub were dialled
  by name to `[::1]:53`), and the controlling terminal for a secret asked
  again ([#62](https://github.com/DavidGodefroid/locklog/issues/62)).
- A containers root the launcher could not check from the host is pinned by
  its device:inode at the first connection and checked on every call; a
  file, journald or docker source whose root is gone, stale or replaced
  ends the call as a lost session (`CodeConnLost`), not a refusal
  ([#62](https://github.com/DavidGodefroid/locklog/issues/62)).
- The MCP tools no longer echo what the agent sent in the SDK's argument
  errors (schema validation, an unknown tool's name): a fixed text names
  the argument and the rule ([#86](https://github.com/DavidGodefroid/locklog/issues/86)).
- `locklog doctor` before any profile checks the account as for a
  production profile (red, exit 1) and says to run `locklog profile add`;
  it exited 0 (#87).
- An AD/SSSD group with a space (`docker users@corp.example`) no longer
  reads as the docker group: the launcher's facts name each gid whole
  (`id -G`, `getent group`); without them, a matching piece stays a
  finding that says the name may be split (#87).
- Each cloud's metadata line and remedy are its own: Azure's speak of its
  metadata service, not of credentials, and only AWS's names IMDSv2 (#87).
- `profile add` writes `.locklog/` through the directory it opened and
  checked after the prompts: a `.locklog/` replaced by a link meanwhile is
  refused, never followed (#87). The launcher's log paths are
  NUL-delimited (`find -print0`): a newline in a name cannot forge a path.
- The engine runs at most `limits.max_calls` agent calls at once (default
  4); one more is refused at once with `E_BUSY` (#50). A call's deadline
  covers its planning: a plan cut by it is refused as over budget, and a
  call left no time stops before any work with its cursor (#49).
- The output cap bounds every answer: a record larger than it comes back
  as an `oversized` stub with its ref (#48), and a count whose groups do
  not fit is paged with a cursor (a partial one is marked `truncated`)
  (#47). A search without predicates whose matches outgrow the page cache
  continues with its cursor instead of being refused (#46).
- The split of an over-budget remote slice drops its narrower slices
  outside the query's range (a window's and its baseline's for patterns)
  before reading them: a dense second just outside the range no longer
  refuses it (#73).
- The combined (access log) format no longer refuses a valid line whose
  three leading fields, up to 255 runes of up to 4 bytes each, put the
  timestamp past byte 800 (#85).
- An agent rule added while the local index builds a granule redacts the
  records indexed after it: the index's memo of trusted values the masker
  leaves clear follows the rules' generation (#84).
- A descending journald search resumes the journal's entry-array walk at
  each granule instead of walking the journal from its head per granule
  (#51).
- Numeric terms (`status = 500`, `in [200, 5e2]`, `!=`) are served from the
  local index and prune its granules; a granule holding the number written
  otherwise (`2e2` for `200`, which matches as a JSON number and not as a
  string) is scanned. Trusted-only counts with them get the count range
  (#52).
- A source failure is printed on the console's terminal (method, source,
  the class the agent gets and the error, masked and sanitised; never a
  record); a stale stream is not (#54).
- A `kind = "file"` source in `cri` or `docker-json` format refuses a
  trusted `attrs` or `attrs.<key>`, which it never keeps (only a docker
  source does); its `stream` stays a trusted label by default (#55).
- The documentation says when `masked_failures` is not counted: a text
  search with the opt-in pre-filter (#53).
- Hub mode: an unaudited call withdraws only a ticket it submitted itself,
  never an earlier call's pending ticket it was lent; the plan of a
  ticket's run is finished even when the engine panics; a call without
  peer credentials that needs no approval (a free lookup) runs, one that
  needs an approval is refused with `E_APPROVAL`.
- An approved scan over several remote sources paces each source under its
  own name.

Not in this release: per-profile auto rules for `lox run`
([#126](https://github.com/DavidGodefroid/locklog/issues/126)).

## [0.1.0] - 2026-11-06

The first release: the console, the engine and the MCP server over files,
journald, Docker and Loki logs (Elasticsearch and OpenSearch as a preview),
with the masking pipeline, the local index, budgets and scan approvals, and
the site locklog.dev.

Still open in this release:
- The Loki and approval suites and `TestLokiIncident` (LL-16b,
  [#101](https://github.com/DavidGodefroid/locklog/pull/101)) are not
  merged; their runs so far found:
  - without a `level` label, the Loki incident's job 1 answers in 5m22s
    against its 5-minute gate
    ([#110](https://github.com/DavidGodefroid/locklog/issues/110));
  - one 7-day trusted Loki count uses 98 of the 120 hourly metric queries,
    so job 1's next count is refused over budget with the default budgets
    ([#112](https://github.com/DavidGodefroid/locklog/issues/112));
  - a 20 GiB approved scan does not finish within the 30-minute approval
    (about 4 MiB/s measured;
    [#104](https://github.com/DavidGodefroid/locklog/issues/104));
  - a Loki call's `scanned.bytes` varies between identical runs
    ([#111](https://github.com/DavidGodefroid/locklog/issues/111)).
- On a cold start (no local index yet) a trusted count scans the
  not-yet-indexed rest with full masking, which misses its gate on a loaded
  host ([#94](https://github.com/DavidGodefroid/locklog/issues/94)).
- `pii.list` and `pii.add` answer "none" until the console serves the PII
  backend ([#64](https://github.com/DavidGodefroid/locklog/issues/64)).
- Remote sources (Loki, Elasticsearch, OpenSearch) have open review
  follow-ups: off production a failed Elasticsearch check still pushes the
  configured selector, remote connections are not closed, refusals can
  quote strings the server sent, the connection checks are outside the
  request pacing and budgets, and relative or `~` TLS paths pass the config
  check when the console runs without the launcher
  ([#106](https://github.com/DavidGodefroid/locklog/issues/106)); the
  Elasticsearch check and scan liveness follow-ups of
  [#93](https://github.com/DavidGodefroid/locklog/issues/93).
- The leak harness checks every agent method's output; the bytes of the
  console socket, the audit and the MCP outputs are not scanned by it yet
  ([#86](https://github.com/DavidGodefroid/locklog/issues/86)).

### Added

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
  checked from the host" case), the calibrated cost model, the profile's
  per-call budgets, and
  `log.status`/`log.sources`. In its image the console confines itself with
  Landlock before it opens any source, and a docker source on a production
  profile needs Landlock or openat2; `:status` shows the Landlock state.
  The mounts are checked again on every call, and a session lost under a
  call ends it with a connection-lost error (the next call reconnects).
- The MCP server (`locklog mcp`): `locklog_status`, `locklog_sources`,
  `locklog_search`, `locklog_count` (also `by_pattern`), `locklog_patterns`
  (the console now serves `log.patterns`), the PII rules and change
  requests, each
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
  allowlist on the `docker-json` frames. The launcher binds the containers
  root with gid 0, keeps the map
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
  which runs as the agent account, gets it on its input). `--loki-proxy
  SERVICE` wires `internal/authproxy` for a Compose
  Loki: Caddy gets only a bcrypt hash, the token is shown once on the
  terminal (and refused without one), the CA key is discarded, the files go
  to `~/.config/locklog/proxy/` (0700, outside the project), and only the
  CA certificate is copied beside the config, for `tls_ca`.
- `locklog doctor` (advisory, not a boundary): the Docker engine and
  `DOCKER_HOST`, the groups `docker`, `adm` and `systemd-journal`, `sudo -n`,
  euid 0, a readable `/var/log/journal` or `/var/lib/docker`, cloud
  credential files, unauthenticated read probes of the configured backends
  and of the clouds' metadata paths, none of which issues a token (Azure:
  the instance document, "an identity may be available") (a status code and
  whether
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
  write-capable key), with an error that quotes no credential. Off
  production a failed check is noted on `:status` and the source
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

[Unreleased]: https://github.com/DavidGodefroid/locklog/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/DavidGodefroid/locklog/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/DavidGodefroid/locklog/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/DavidGodefroid/locklog/releases/tag/v0.1.0
