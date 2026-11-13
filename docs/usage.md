# Using locklog

This page covers the profile file, the sources, the agent's tools and the
budgets. The security model is in [security-model.md](security-model.md).

## The profile file

`locklog profile add` (which `lox add locklog <name>` calls) writes
`.locklog/config.toml` in your project. `lox run` reviews the profile
directory, and the console reviews the policy at its first start. After that it serves only the **approved**
copy. A change that loosens the policy waits for you at the console's
`:review`.

```toml
version = 1

[profiles.staging]
production = false          # profile add asks; an unanswered question means true

[profiles.staging.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]   # rotated and .gz/.zst files included
format = "combined"

[profiles.staging.sources.system]
kind = "journald"
units = ["nginx.service", "shop-*.service"]

# A docker source cannot share a profile with file or journald sources: it runs in a
# console of its own, so a lock of its own (profile add writes it as <profile>-docker).
[profiles.staging-docker]
production = false

[profiles.staging-docker.sources.api]
kind = "docker"
containers = ["shop-api-*"]
format = "json"
```

A Loki source:

```toml
[profiles.staging.sources.loki]
kind = "loki"
url = "https://loki.internal:3100"
selector = { namespace = "shop" }
trusted_labels = ["app", "level", "pod"]
auth = "bearer"
credentials = "ask"          # typed at the console, never written to disk
```

### Profile keys

| Key | Default | Meaning |
|---|---|---|
| `production` | `false` when the key is absent; `locklog profile add` asks (or takes `--production`), and an unanswered question means `true` | Turns on the production rules: `redact-unknown`, unmask `never` by default, authenticated backends over TLS, tighter rolling budgets, `prefilter` refused, the host-agent trial refused |
| `structured` | `redact-unknown` on production, else `detect` | How structured leaves are masked: `redact-unknown` redacts every leaf that is neither trusted nor allowed |
| `text` | `detect` | Free text: `detect`, or `template`. Accepted and reviewed, but not applied yet: free text is masked by the detectors in both |
| `detectors` | all default detectors | Value detectors to run |
| `unmask` | `never` on production, else `approved` | Whether the agent may ask you to unmask a value |
| `lookup` | `free` | `locklog_lookup` free and rate-limited, or `approved` (a ticket each time) |
| `strict` | `false` | Accepted and reviewed, but not applied yet (planned: every search and count becomes a ticket) |
| `prefilter` | `false` | Opt-in speed-up for non-production; reveals through latency how many records hold a clear substring, and turns off the `masked_failures` count of text searches (see The agent's tools) |
| `user_journals` | `false` | Also serve `user-*.journal` files |
| `pseudonym_rotation` | `7d` | Epoch length (`session` or a duration; `never` is refused on production) |
| `pseudonym_max_age` | `30d` | How long a replaced epoch key is kept; older ones are deleted when the console opens the profile |
| `limits` | see Budgets | Per-call and rolling budgets |
| `auto` | every action `ask` | The profile's auto mode for `lox run`: `"full-auto"`, or a table of `read`, `unmask`, `lookup` set to `auto`, `ask` or `deny` (see What `lox run` decides) |

Sources take `kind`, `format`, `multiline` (`none` or `indent`) and
`trusted` (fields shown in clear after the detectors, selectable and
countable), plus per kind:

| Kind | Keys |
|---|---|
| `file` | `paths` (absolute globs; `**` only with `recursive = true`, depth ≤ 4). In `cri` or `docker-json` format, the frame's `stream` is trusted by default, as a label; frame `attrs` are not kept (only a `docker` source keeps them), so trusting `attrs` or `attrs.<key>` is refused |
| `journald` | `units` (globs on `_SYSTEMD_UNIT`), `allow` (extra fields, reviewed; core dumps, command lines, executables, audit and `OBJECT_` fields can never be allowed) |
| `docker` | `containers` (name globs; a glob matching a locklog console is refused), `attrs` (json-file log-opt attributes to keep) |
| `loki` | `url`, `selector`, `trusted_labels`, `trusted_metadata`, `auth` (`none` refused on production, `basic`, `bearer`, `mtls`), `org_id`, `user` (basic), `credentials` (`ask` or `vault`, with `vault_path`), `tls`, `tls_ca`, `tls_cert` and `tls_key` (mtls) |
| `elastic`, `opensearch` (preview) | `url`, `selector`, `indices`, `trusted_fields`, `time_field`, `message_field`, `tiebreaker`, `read_only_roles` (OpenSearch only), `auth` (as `loki`, plus `api_key` for `elastic`), `user`, `credentials`, `vault_path`, `tls`, `tls_ca`, `tls_cert`, `tls_key` |

## Managed configuration

A company can bound every locklog of a machine with the Lock Family's
managed file, `/etc/lockfamily/managed.toml` on Linux and
`/Library/Application Support/lockfamily/managed.toml` on macOS (schema,
signing and deployment:
[lockfamily docs/managed.md](https://github.com/DavidGodefroid/lockfamily/blob/main/docs/managed.md)).
The file and its directory must be owned by root and writable by root
only; a badly owned, invalid or badly signed file is a refusal to start,
never a file ignored. locklog reads its `[locklog]` section:

```toml
version = 1
organisation = "Acme"

[locklog.bounds]                     # the loosest policy allowed
unmask = "never"
lookup = "approved"
kinds = ["file", "journald", "loki"]
hosts = ["*.logs.acme.internal"]
credentials = ["vault"]
tls = "verify-full"
network = []                         # no LOCKLOG_NETWORK
limits = { max_records = 100, max_session = "8h", remote = { range = "1d" } }
auto = { unmask = "ask" }
detectors = ["iban"]                 # always on, added to every profile

[[locklog.bounds.pii_mask]]          # always on, before the project's rules
sources = ["app-*"]
field = "user.email"

[locklog.defaults]                   # for the keys a profile leaves unset
structured = "redact-unknown"
limits = { max_records = 50 }

[locklog.profiles.prod-loki]         # served as written
production = true
[locklog.profiles.prod-loki.sources.loki]
kind = "loki"
url = "https://loki.logs.acme.internal"
selector = { env = "prod" }
auth = "bearer"
credentials = "vault"
vault_path = "secret/loki"
```

Precedence: hard-coded floor > managed bounds and profiles > project file >
user file > managed defaults > built-in defaults.

- **Profiles**: `[locklog.profiles.<name>]` takes every profile key,
  `sources`, `auto` and `limits` included, with the same checks as a
  profile of `.locklog/config.toml` (production rules too); the defaults
  fill what it leaves unset. A profile of the same name in the project or
  user config is refused at load, naming it: rename yours.
  `locklog profile rules` marks managed profiles `(managed)`.
- **Defaults**: `[locklog.defaults]` takes the scalar profile keys, `auto`
  and `limits.*`, not `sources`; a value of the config files wins over it.
- **Bounds**: the merged profile is checked against `[locklog.bounds]` at
  the console's start and at every policy poll (2 s). A profile beyond a
  bound is refused with no prompt, citing the key (`blocked by company
  policy: locklog.bounds.unmask = never (profile dev: unmask =
  approved)`), audited `refused-managed`, and no human can approve past it.
  A loosening edited in while the console runs is refused at the next poll,
  never pending. A duration or size beyond its bound is a violation, never
  clamped; the built-in default counts when the profile sets none. A
  managed default or a managed profile beyond the bounds is a load error.
- **PII**: `detectors` are added to every profile. `[[locklog.bounds.pii_mask]]`
  takes the keys of a `[[mask]]` rule of `pii.toml` (`sources`, which may be
  globs here, `field` or `label`, `mode`, `kind`): the rules are part of the
  policy, applied before the project's, and shown `(managed)` by the
  console's PII view and `locklog_pii_list`. A project `[[allow]]` that could
  show what one masks is refused at load, citing `locklog.bounds.pii_mask`.
- `[family] vault = { required = true }` acts as `credentials = ["vault"]`
  on every remote source whose `auth` is not `none` or `mtls`, cited as
  `family.vault.required`.
- `locklog managed show` prints the file's path, organisation, fingerprint
  and signature, the bounds, the defaults, the managed PII rules and the
  managed profiles (`no managed configuration` and exit 0 without a file,
  the error and exit 3 for a refused one). `locklog managed check [--profile
  NAME] [--project DIR]` checks the project's profiles as the console does,
  with the launch environment (`LOCKLOG_NETWORK`, `LOCKLOG_EXTRA_ROOTS`),
  without a connection, a log, a credential, a hub or a terminal: one
  `blocked by company policy: …` line per violation and exit 3, else `ok: …`
  and exit 0. `lox run` runs it before it starts the lock. `locklog doctor`
  has a `managed` line, and `locklog console` exits 3 on a refusal.
- The host launcher (`scripts/locklog`) mounts the machine's managed
  directory read-only on `/etc/lockfamily` in every container it runs, as
  `lox run` mounts it in its locks: `managed show`, `managed check`,
  `doctor`, `profile`, `init` and `mcp` run from the host see the bounds the
  console enforces ([install.md](install.md#the-managed-directory)).

| Bound key | Type | Looser (refused) |
|---|---|---|
| `production` | `true` | a profile that is not production |
| `structured` | `"redact-unknown"` | `detect` |
| `text` | `"template"` | `detect` |
| `unmask` | `"never"` | `approved` |
| `lookup` | `"approved"` | `free` |
| `strict` | `true` | `strict = false` |
| `prefilter`, `user_journals` | `false` | `true` |
| `pseudonym_rotation` | `session`, a duration or `never`, a ceiling (`session` < durations < `never`) | a longer rotation |
| `pseudonym_max_age` | duration ceiling | longer |
| `auto.<action>` (`read`, `unmask`, `lookup`) | `deny`, `ask` or `auto`, a ceiling; a preset (`auto = "full-auto"`) is refused in a bound | a looser rule (`deny` < `ask` < `auto`), the profile's preset included |
| `limits.local.*`, `limits.remote.*` (`range`, `count_range`, `max_bytes`, `bytes_per_hour`; remote also `metric_queries_per_hour`, `requests_per_minute`) | ceiling | a larger value |
| `limits.max_records`, `limits.max_output`, `limits.lookups_per_hour`, `limits.lookups_per_hour_per_uid`, `limits.pii_adds_per_hour`, `limits.pii_rules_max`, `limits.max_calls` | ceiling | a larger value |
| `limits.idle_timeout`, `limits.max_session` | duration ceiling | longer |
| `kinds` | allowed source kinds (`file`, `journald`, `docker`, `loki`, `elastic`, `opensearch`) | a source of another kind |
| `hosts` | host patterns (`*` any run) | a loki, elastic or opensearch `url` whose host matches none |
| `paths` | allowed directories | a `file` source path outside them |
| `auth` | allowed modes (`none`, `basic`, `bearer`, `mtls`, `api_key`) | another mode |
| `credentials` | allowed modes (`ask`, `vault`) | another mode |
| `tls` | a floor (`disable` < `prefer` < `require` < `verify-ca` < `verify-full`) | a weaker remote source |
| `network` | allowed `LOCKLOG_NETWORK` names; `[]` none | another network |
| `extra_roots` | allowed `LOCKLOG_EXTRA_ROOTS` directories; `[]` none | a root outside them |
| `detectors` | required detectors | none: added to every profile |
| `[[pii_mask]]` | mask rules, as `[[mask]]` | none: always on; an `[[allow]]` over one is refused |

A value outside an allowlist (`kinds` to `extra_roots`) is cited as
`blocked by company policy: locklog.bounds.<key> does not allow <field> =
<value> (profile <name>; allowed: …)`.

## Wiring an agent

`locklog init <agent>` wires an agent in the project (`lox add locklog`
runs `locklog init claude`; `locklog doctor --fix` wires every agent
installed here that is not wired yet). The launcher runs it in the image as
you, with the project writable. In an agent's own container, where the
recipe copies the `locklog` binary in, run `locklog init <agent>` there.
Every init also creates a commented `.locklog/config.toml` when the project
has none.

| Agent | What `locklog init` writes |
|---|---|
| `claude` | `.mcp.json` (the `locklog mcp` server), `.claude/skills/locklog/SKILL.md`, the allow list below |
| `codex` | a locklog section in `AGENTS.md`; it prints the `~/.codex/config.toml` table to add yourself (it writes no file outside the project) |
| `cursor` | `.cursor/mcp.json`, `.cursor/rules/locklog.mdc` |
| `gemini` | `.gemini/settings.json` (timeout 600 s, which covers the console's 5-minute approval timeout), a locklog section in `GEMINI.md` |

For Claude Code it also adds the **free** tools to `permissions.allow` in
`.claude/settings.local.json`, the personal file, so they do not prompt.
It never writes the shared `.claude/settings.json` or your user settings,
and it warns when git does not ignore the personal file. Tools that ask
the console (`locklog_request_change`, `locklog_scan`, `locklog_unmask`)
are never on that list. Remove an entry to be asked again; a re-run adds
it back and says so.

## The agent's tools

| Tool | What it does | Cost |
|---|---|---|
| `locklog_status` | consoles, profiles, sources, budgets left, the pseudonym epoch | free |
| `locklog_sources` | per source: kind, format, field and label names (masked names as `⟦key:ID⟧`), trusted values, coverage | free |
| `locklog_search` | masked records of a range: `where`, `text`, `regex`, `fields`, `limit ≤ 200`, cursor | free within budgets |
| `locklog_count` | histogram, `by` trusted or pseudonym fields and `by_labels` labels (≤ 2 in all), `first_last` | free within budgets |
| `locklog_patterns` | top templates of the masked text, `baseline` diff | free within budgets |
| `locklog_context` | records around a `ref` (≤ 50 each side) | free |
| `locklog_trace` | one id or pseudonym across sources, merged timeline | free within budgets |
| `locklog_tail` | new records for ≤ 50 s | free (rolling budgets) |
| `locklog_lookup` | a clear value → its pseudonym (detector kinds only) | free, rate-limited |
| `locklog_pii_list`, `locklog_pii_add` | the masking rules; add masking (never remove it): `[pseudonym ]source:field`, a masked key by its `⟦key:ID⟧`. Capped by `pii_adds_per_hour` and `pii_rules_max`; `locklog_status` counts the agent's rules | free, capped, audited |
| `locklog_request_change` | ask for a loosening | you decide at `:review` |
| `locklog_scan` | one call over a budget, approved for its whole plan | you approve |
| `locklog_unmask` | the clear value of up to 8 exact pseudonyms of one record, once, with a reason | you approve a ticket at `lox run`, the deck or a phone (automatically only with `auto.unmask = "auto"`); off by default on production |

Every result carries the pseudonym `epoch`. A result with
`complete: false` has a `cursor`: passing it back with the same parameters
continues the same plan for free (the range may be left out: the cursor
holds the first call's window). Other parameters are refused with
`E_STALE`, naming the ones that differ. A docker source's `container` is a
label, not a field: `where` takes `{label: "container"}` and `locklog_count`
`by_labels`; as a field it is refused, naming the label. A record the masker fails on is withheld whole and counted in
`masked_failures`. One exception: with `prefilter = true`, a search whose
query has `text` or a `contains` predicate masks only the records whose
clear text holds those needles, so counting the failures would tell whether
a failing record holds them. Such a search does not count failures:
`masked_failures` is absent (0) although failing records are still
withheld. Counts, patterns, context, trace and tail are not pre-filtered
and always count them. Log lines are untrusted data. The skill installed by `locklog
init` tells the agent so, and tells it to start with `locklog_count` on
trusted fields.

### Query model

```json
{ "sources": ["nginx"], "from": "2026-10-30T13:00:00Z", "to": "2026-10-30T15:00:00Z",
  "where": [ {"field": "status", "op": ">=", "value": 500},
             {"field": "remote_addr", "op": "=", "value": "⟦ip:K2M9ZDQ81RTA⟧"} ],
  "text": "/api/orders/", "limit": 100 }
```

- `= != in exists` on any field. `< <= > >=` only on trusted fields: ordering
  on a masked field would reveal it.
- `contains` and `matches` (RE2, ≤ 256 bytes) run on the **masked** view. They
  never match inside a placeholder.
- A predicate value the detectors flag as personal is refused with
  `E_PII_IN_QUERY`. Use `locklog_lookup` to get its pseudonym.

### Context, trace and tail: known limits

These never give `complete: true` with a lost or repeated new record; some
cases are pessimistic on purpose.

- `locklog_tail` says `complete: false` (it cannot vouch for every new
  record) when a file was empty at the start and then grows (common right
  after a logrotate `create`), when a rotated copy is compressed during the
  tail (`.1` to `.1.gz`), when two unrelated streams hold the same records
  at the same offsets (a copy cannot be told from them), or when streams
  keep changing for many polls.
- A file truncated and rewritten with the same first 64 KiB keeps its
  stream identity, as for the file source.
- A multi-line record still receiving continuation lines when the tail
  ends is evaluated as it stands then.
- A tail plans every local stream at each poll; that work is not charged
  to the rolling budgets. While a tail runs (up to 50 s), the other tool
  calls of the same profile wait for it.
- `locklog_context` on a file reads back at most 16 granules before its
  record: it can return fewer `before` records than asked with
  `complete: true` (the start of what it read). The target record is
  always returned, even alone over the output cap. A ref from before a
  policy change is refused with `E_POLICY_CHANGED`, one from an older
  pseudonym epoch with `E_STALE`.
- `locklog_trace` matches a pseudonym in values, not in a masked field
  name (`⟦key:ID⟧`).

## Budgets

| Per call | Local (files, journald, Docker) | Remote (Loki) | Ceiling |
|---|---|---|---|
| range with text, regex or masked-field predicates | 7 d | 24 h | 400 d |
| range of trusted-field-only counts | 30 d | 30 d | 400 d |
| bytes admitted | 512 MiB | 512 MiB (decompressed responses) | 64 GiB |
| records / output | 200 / 64 KiB | 200 / 64 KiB | 1,000 / 1 MiB |

| Rolling | Local | Remote (non-production / production) |
|---|---|---|
| bytes per hour | 40 GiB | 20 GiB / 10 GiB |
| backend requests per minute | — | 600 / 240 |
| server-side metric queries per hour | — | 120 / 60 |
| `lookup` distinct values per hour | 50 per console, 20 per uid (production: 10 per console) | same |
| agent `pii.add` | 10 per hour, 50 rules | same |

The connection checks of a remote source are not charged to these
budgets: they run once per connection, before the agent can call (up to 2
requests for Loki, up to 8 for Elasticsearch or OpenSearch).

A call over a budget is refused with `E_OVER_BUDGET` and the estimate,
before it touches any data. `locklog_scan` is the only way past. A call
also stops at its deadline (30 s, its planning included) and returns
`complete: false` with a cursor. The numbers behind these defaults are in
[performance.md](performance.md).

The console runs at most `limits.max_calls` agent calls at once (default
4, ceiling 64): parallel calls would otherwise multiply the per-call
budgets. One more is refused at once with `E_BUSY`, before any work; the
agent sends it again once one of its calls answered. A tail holds its slot
for its whole duration. A scan waits for its approval without a slot and
takes one once approved; an unmask or a lookup takes none.

The output cap applies to every answer:

- A record whose masked rendering alone exceeds it comes back as a stub:
  its `source`, `ref` and `ts`, `"oversized": true` and the `bytes` of its
  rendering. Ask for some of its fields (`fields`), or for its context.
- A whole count whose groups do not fit is paged: each page holds the next
  groups in order (`groups_from` of `groups_total`) and a `cursor` to the
  rest, for free; the last page is `complete`. A partial count (its scan
  continues) shows the first groups that fit, with `"truncated": true`,
  `omitted_groups` and `omitted_n` (the records in the groups left out for
  now).
- A search keeps the matches its page cannot hold for the next pages.
  When one call's matches outgrow that cache (64 MiB for the console), a
  query without predicates (browsing a range) stops before the part that
  did and continues from there with its cursor (it reads local logs in
  parts small enough for this; a single remote slice whose matches alone
  outgrow the cache is still refused). A query with predicates is
  refused with `E_OVER_BUDGET` ("too many matching records in one call to
  page through"): where a call stops never depends on what its predicates
  match. Narrow its range, sources or `fields`, or make a predicate more
  selective.

## Starting: `lox run`

The console is started by `lox run` only (from lockhub v0.10.0, the first
release that knows the locklog type: lockhub#84, #86, #87), hub
attached: `locklog console` without its hub flags refuses with lockkit's
"the console is launched by `lox run` only". The journey:

```sh
brew trust davidgodefroid/tap
brew install davidgodefroid/tap/lockfamily   # or: brew install davidgodefroid/tap/locklog
lox init                      # or: lox add locklog logs
lox run                       # in a terminal of its own, kept open
```

`lox add locklog <name>` runs the three launcher verbs ([setup.md](setup.md))
from the project, `lox run` starts the hub and the console, with the log
directories of the profile's mount plan bound read-only, and shows every
ticket and decides it, by its rules or by you. A host agent (Claude Code,
Codex...) reaches the console through the launcher's `locklog mcp`, which
`.mcp.json` names: the launcher finds `.lockfamily/up.json` up from the
current directory and mounts the socket volume of the locklog lock it
names, read-only. Without `up.json`, or without a locklog lock in it, it
says to run `lox run` first and exits 2. With several locklog locks,
`--instance NAME` picks one (`"args": ["mcp", "--instance", "NAME"]` in
`.mcp.json`); without it the error names them. lea's agents reach the
socket the same way, mounted by lea.

### What `lox run` decides, and what it asks

A scan, an unmask or an approved lookup becomes a ticket on lockhub. A
scan is risk `read` (one approval covers its whole plan, its continuations
need no ticket); an unmask and an approved lookup are `read-pii`, which
only the terminal, the deck or a phone approve, never a chat facade. The
free tools (search, count, patterns, context, trace, tail, a free lookup)
need no ticket. The tickets are version 2 (lockkit's kind `read`, the
profile as their subject), so that `lox run` can apply the profile's rules.

Each profile has an auto mode, one rule per action that becomes a ticket:

| Action | Ticket | Default |
|---|---|---|
| `read` | an approved scan (`locklog_scan`) | `ask` |
| `unmask` | an unmask (`locklog_unmask`) | `ask` |
| `lookup` | an approved lookup (`lookup = "approved"`) | `ask` |

```toml
[profiles.local]
auto = "full-auto"      # every action auto

[profiles.prod.auto]
read = "auto"           # scans left to lox run's auto mode
unmask = "deny"         # never, even with your approval
# lookup = "ask"        # the default
```

A table may start from a preset (`preset = "full-auto"` or `"default"`)
and override actions. Unknown keys and values are refused, with the
profile named and the value never quoted. The console holds its side,
whatever `lox run` does:

- `deny`: the console refuses the call before any ticket (`E_AUTO_DENY`,
  retry `ask_user`), in both of `lox run`'s modes. `lookup = "deny"`
  refuses free lookups too; the free tools are not affected by `read`.
- `ask`: the ticket is signed `never_auto`. `lox run` asks you; an auto
  rule's approval of it is refused by the console (lockkit's `ErrAuto`):
  nothing runs, the agent hears that the ticket waits for you, and your
  approval then runs it.
- `auto`: the ticket is left to `lox run`'s auto mode, which may approve
  it without a question (manual mode still asks).

The rules belong to the approved policy (its fingerprint; the defaults
are stored sparsely, so a policy approved before the rules existed keeps
its fingerprint). Moving a rule toward `auto` (`deny` → `ask` → `auto`)
is a loosening: the console applies it only once you accept it at its
start or at `:review`, with the profile's name typed on a production
profile. A move toward `deny` applies at once; a ticket asked before it
is then refused and withdrawn. The rules in force show in the review, in
`:status`, and in `locklog_status` (`auto`).

`locklog profile rules [--json] [--project DIR] [--profile NAME]` prints
each profile's effective rules, the defaults filled in; this is what `lox
run` reads. With the console's state readable (beside the console), the
rules are those of the approved policy (`"source": "approved"`), and a
config file whose rules differ is flagged `pending_review` with its
`file_rules`; elsewhere they are the config file's (`"source": "files"`).

The audit records the rule in force (`auto_rule`, such as `"auto.read =
ask"`) on a ticket's pending, approved, refused and run records and on a
denied call, and what decided a ticket (`decided_by`: `human`, or
`auto:<rule id>` from `lox run`'s decision).

## The console

The console prints nothing for a free call (the audit records it), unless
clear results are on (Ctrl-O, below) or a source fails: then it prints one
line with the method, the source, the class of failure the agent gets
(`E_SOURCE`) and the error, masked and sanitised (a file path, a backend's
status; never a record). A stale stream, which the agent just runs again,
is not printed. It never asks about an agent's request: those are tickets
on lockhub. It still decides its own widenings at its terminal (`lox attach
<name>`): the policy review at its first start and every loosening at
`:review` (`y`; on a production profile, the profile's name typed exactly),
and `:unmask`.

| Command | What it does |
|---|---|
| `:status` | the profile, session, pending changes, sources, budgets and hub |
| `:review` | the policy change and change requests waiting for you |
| `:unmask` | allow clients to ask for unmasked output (`y`; on production, the profile's name) |
| Ctrl-O (`:results`) | clear results on or off: the records each agent call returns are printed in clear on this terminal only, never to the agent (see below) |
| `:quit` | end the console |

An unmask ticket's screen shows the record masked, the asked spans marked `» «`,
the agent's reason, how many records holding each pseudonym agents were
given in this epoch (counted by the console from the calls it answered and
audited, by pseudonym only, since the console started), and two warnings:
the agent receives these clear values once, and can link them to every
record with the same pseudonym in the epoch. After a yes the record is read again, and the unmask is refused
(`E_STALE`) if the record, the epoch or the policy changed.

With clear results on (Ctrl-O), the console prints, after each agent call,
the records it returned with their pseudonyms in clear; secrets,
`⟦redacted⟧` values and masked field names stay as they are. The agent
still gets the masked result. The records are taken from the call itself
(a remote record is never fetched again for this; a page served from the
result cache is read again from a local source). The audit counts them
(`shown_clear`), never their content. An unmask screen opened while clear
results are on also shows its record in clear. lockkit refuses Ctrl-O at
desktop levels 1 and 2 and warns on a production profile. On a production
profile, where `unmask = "never"`, this is how you read a record the agent
points you to.

## Tickets on lockhub

- The hub shows a ticket's screen masked; with `--seal-clear` (lox run
  passes it from `hub.mobile`) the clear screen (the record in clear,
  secrets still redacted) goes sealed to your pinned devices only. The
  agent hears `pending` with the ticket id, nothing else, and calls the
  same tool again with the ticket once you decided.
- The run plans the call again: another record, other pseudonyms or spans,
  another scan or a changed policy is refused (`E_STALE`), and asking
  again is a new ticket. A ticket runs once; a scan's ticket covers its
  whole plan, and its continuations need none.
- A `read-pii` decision taken on a chat facade is refused by the console:
  only the terminal, the deck or a phone approve an unmask or an approved
  lookup.
- The hub shows the requester as the console's peer credentials name it
  (`uid N`, or `agent` for the image's agent account), never a name the
  agent declares; the agent's lea token only binds the ticket to it.
- A ticket waits 24 hours; its run after that asks again (a renewal, which
  says the record could not be checked before the run).
- With the hub down, free reads go on; approvals stay pending and go out
  when it answers. `locklog_status` shows the hub and the instance.
- Decisions (who, on which facade, the hub's signature), renewals and
  reveals are audited.
