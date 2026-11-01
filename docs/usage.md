# Using locklog

This page covers the profile file, the sources, the agent's tools and the
budgets. The security model is in [security-model.md](security-model.md).

## The profile file

`locklog setup` writes `.locklog/config.toml` in your project. The console
reviews it at its first start. After that it serves only the **approved**
copy. A change that loosens the policy waits for you at the console's
`:review`.

```toml
version = 1

[profiles.staging]
production = false          # setup asks; an unanswered question means true

[profiles.staging.sources.nginx]
kind = "file"
paths = ["/var/log/nginx/access.log*"]   # rotated and .gz/.zst files included
format = "combined"

[profiles.staging.sources.system]
kind = "journald"
units = ["nginx.service", "shop-*.service"]

# A docker source cannot share a profile with file or journald sources: it runs in a
# console of its own (setup writes it as <profile>-docker).
[profiles.staging-docker]
production = false

[profiles.staging-docker.sources.api]
kind = "docker"
containers = ["shop-api-*"]
format = "json"
```

A Loki source, once the console opens remote sources
([#97](https://github.com/DavidGodefroid/locklog/pull/97)):

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
| `production` | `false` when the key is absent; `locklog setup` asks, and an unanswered question means `true` | Turns on the production rules: `redact-unknown`, unmask `never` by default, authenticated backends over TLS, tighter rolling budgets, `prefilter` refused, the host-agent trial refused |
| `structured` | `redact-unknown` on production, else `detect` | How structured leaves are masked: `redact-unknown` redacts every leaf that is neither trusted nor allowed |
| `text` | `detect` | Free text: `detect`, or `template`. Accepted and reviewed, but not applied yet: free text is masked by the detectors in both |
| `detectors` | all default detectors | Value detectors to run |
| `unmask` | `never` on production, else `approved` | Whether the agent may ask you to unmask a value |
| `lookup` | `free` | `locklog_lookup` free and rate-limited, or `approved` (a ticket each time) |
| `strict` | `false` | Accepted and reviewed, but not applied yet (planned: every search and count becomes a ticket) |
| `prefilter` | `false` | Opt-in speed-up for non-production; reveals through latency how many records hold a clear substring |
| `user_journals` | `false` | Also serve `user-*.journal` files |
| `pseudonym_rotation` | `7d` | Epoch length (`session` or a duration; `never` is refused on production) |
| `pseudonym_max_age` | `30d` | How long a replaced epoch key is kept; older ones are deleted when the console opens the profile |
| `limits` | see Budgets | Per-call and rolling budgets |

Sources take `kind`, `format`, `multiline` (`none` or `indent`) and
`trusted` (fields shown in clear after the detectors, selectable and
countable), plus per kind:

| Kind | Keys |
|---|---|
| `file` | `paths` (absolute globs; `**` only with `recursive = true`, depth ≤ 4) |
| `journald` | `units` (globs on `_SYSTEMD_UNIT`), `allow` (extra fields, reviewed; core dumps, command lines, executables, audit and `OBJECT_` fields can never be allowed) |
| `docker` | `containers` (name globs; a glob matching a locklog console is refused), `attrs` (json-file log-opt attributes to keep) |
| `loki` | `url`, `selector`, `trusted_labels`, `trusted_metadata`, `auth` (`none` refused on production, `basic`, `bearer`, `mtls`), `org_id`, `user` (basic), `credentials` (`ask` or `vault`, with `vault_path`), `tls`, `tls_ca`, `tls_cert` and `tls_key` (mtls) |

The console opens `loki`, `elastic` and `opensearch` sources from the
profile once [#97](https://github.com/DavidGodefroid/locklog/pull/97) is
merged; until then the console refuses a profile that holds one (this build
"does not read yet" that kind) before it opens anything.

## Wiring an agent

`locklog setup --agent host` wires the agents it detects in the project
(`--agents claude,codex` to choose). It runs `locklog init <agent>` for each,
in a container that writes the project as you. In an agent's own container,
where the recipe copies the `locklog` binary in, run `locklog init <agent>`
there. The launcher on the host does not run `init` itself: it mounts the
project read-only. Every init also creates a commented `.locklog/config.toml` when the
project has none.

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
| `locklog_count` | histogram, `by` ≤ 2 trusted or pseudonym fields, `first_last` | free within budgets |
| `locklog_patterns` | top templates of the masked text, `baseline` diff | free within budgets |
| `locklog_context` | records around a `ref` (≤ 50 each side) | free |
| `locklog_trace` | one id or pseudonym across sources, merged timeline | free within budgets |
| `locklog_tail` | new records for ≤ 50 s | free (rolling budgets) |
| `locklog_lookup` | a clear value → its pseudonym (detector kinds only) | free, rate-limited |
| `locklog_pii_list`, `locklog_pii_add` | the masking rules; add masking (never remove it). Until the console serves PII rules ([#64](https://github.com/DavidGodefroid/locklog/issues/64)) they answer that there are none | free, capped |
| `locklog_request_change` | ask for a loosening | you decide at `:review` |
| `locklog_scan` | one call over a budget, approved for its whole plan | you approve |
| `locklog_unmask` | the clear value of up to 8 exact pseudonyms of one record, once, with a reason | you approve at the console, never automatically; off by default on production |

Every result carries the pseudonym `epoch`. A result with
`complete: false` has a `cursor`: passing it back continues the same plan
for free. Log lines are untrusted data. The skill installed by `locklog
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

A call over a budget is refused with `E_OVER_BUDGET` and the estimate,
before it touches any data. `locklog_scan` is the only way past. A call
also stops at its deadline (30 s) and returns `complete: false` with a
cursor. The numbers behind these defaults are in
[performance.md](performance.md).

## The console

`locklog console` prints nothing for a free call (the audit records it),
unless clear results are on (Ctrl-O, below). It
opens an approval screen for scans, unmasks, approved lookups and change
requests: you answer `y` (on production, the profile's name) or `n`. An
unanswered screen times out after 5 minutes and the agent is told not to
retry unless asked.

| Command | What it does |
|---|---|
| `:status` | the profile, mode, session, pending changes, sources and budgets |
| `:review` | the policy change and change requests waiting for you |
| `:mode` (Shift+Tab) | manual or auto mode; auto approves scans on a non-production profile, never an unmask or a lookup; production stays manual |
| Ctrl-O (`:results`) | clear results on or off: the records each agent call returns are printed in clear on this terminal only, never to the agent (see below) |
| `:quit` | end the console |

The unmask screen shows the record masked, the asked spans marked `» «`,
the agent's reason, and two warnings: the agent receives these clear values
once, and can link them to every record with the same pseudonym in the
epoch. After a yes the record is read again, and the unmask is refused
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
