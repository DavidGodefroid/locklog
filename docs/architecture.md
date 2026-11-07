# Architecture: how locklog works

The process layout, the life of a call, who decides what, the sources and
the masking benchmark. The threat model, the invariants and what is not
masked are in [security-model.md](security-model.md); the profile keys,
the tools and the budgets in [usage.md](usage.md).

## How it works

```
 host (you)
   lox run (lockhub): the hub and the decisions, in a terminal of its own
     └─ console container (one per lock)   uid 10051 "locklog", no capability,
          read-only root, cpus min(2,nproc), memory 1g, logging none, hub-attached
          read-only, non-recursive binds of the approved log directories
          home volume:   pseudonym keys, local index, audit, rules (console only)
          socket volume: /run/locklog (2750 locklog:locklog-clients), one socket
                         per project and profile, <project-hash>-<profile>.sock (0660)
          network: the hub's; and the lock's egress network for Loki, Elasticsearch

 agent (yours: lea, your own container, or the host for the trial)
   MCP server `locklog mcp` → its project's socket, the lock's socket volume
   read-only (peer uid checked by the kernel)
```

1. The console reads the approved sources, and only those. The sources are
   reviewed at the console's first start and on every loosening.
2. For each call it builds a **byte plan** from the time range and the
   trusted selectors only (local index, Loki label stats, ES `_count`).
   Admission, cursors and stopping points depend on the plan, never on what
   matched.
3. Every record of a planned chunk is **masked first**: secrets
   (`⟦secret⟧`, final), then your rules, personal field names, value
   detectors (email, phone, IBAN, card, BE/FR/NL/US national ids, public IP;
   person names and loose phone numbers opt-in) and the structured or text
   mode. Then the agent's
   predicates run on the masked view.
4. The answer leaves through `render` caps as JSON under an "untrusted
   content" header, with the pseudonym `epoch` and a sealed cursor to
   continue for free.

| Operation | Who decides |
|---|---|
| `status`, `sources`, `search`, `count`, `patterns`, `context`, `trace`, `tail` within budgets | free, audited |
| `lookup` (clear value → pseudonym, detector kinds only) | free, rate-limited, audited; or approved each time with `lookup = "approved"` |
| `pii_list` / `pii_add` (agent masking rules, tighten only) | free, capped, audited |
| `locklog_scan` (beyond a budget, approved once for its whole plan; its cursor continues free for 30 minutes, or its plan's bound when longer, at most 4 hours) | you, a ticket at `lox run` (or the deck, a phone); auto-approved only if the profile's auto rules say so (`auto.read`) |
| `locklog_unmask` (the clear value of exact spans of one record, once) | you, a ticket at `lox run`, the deck or a phone; auto-approved only if the profile's auto rules say so (`auto.unmask`); **off by default on production** |
| `locklog_request_change` (any loosening) | you, at the console's `:review` |
| write, delete, admin | does not exist |

An unmask ticket shows the record **masked**, with the asked spans marked
`» «`, the agent's reason and what a yes lets the agent link. To read a
record yourself without sending anything to the agent, turn clear results
on with Ctrl-O at the console (`lox attach <name>`): the records the
agent's calls return are then printed in clear on the console's terminal
(secrets kept redacted). Secrets are never unmasked. By default `lox run`'s
auto mode approves no locklog ticket: scans, unmasks and approved lookups
wait for you. A profile's auto rules (`auto = "full-auto"`, or `read`,
`unmask`, `lookup` set to `auto`, `ask` or `deny`) change that, as a
policy loosening you review; see
[usage.md](usage.md#what-lox-run-decides-and-what-it-asks).

## Sources

| Source | Since | Notes |
|---|---|---|
| Files | v0.1.0 | globs under approved roots, rotation, `.gz`, `.zst`; formats `auto`, `json`, `logfmt`, `syslog`, `cri`, `docker-json`, `combined`, `plain`; multi-line events |
| journald | v0.1.0 | pure-Go reader, field allowlist; core dumps, command lines and audit fields are never served |
| Docker containers | v0.1.0 | `json-file` logs by container name glob; the `journald` driver through journald. Podman through journald |
| Loki | v0.1.0 | trusted labels and structured metadata, server-side metric counts; text never sent to Loki |
| Elasticsearch, OpenSearch | v0.1.0 (preview) | trusted keyword fields, `search_after`, a read-only privilege check; their incident gates come with v0.3.0 |

`docker compose up` deletes a recreated container's `json-file` logs: use
the journald driver or Loki for history across deploys.

Loki 3 users: see [loki.md](loki.md) on the default
`detected_level` field: what Loki puts in it, and how locklog selects on it
(locally, never as a Loki filter).

## Masking benchmark

The leak harness plants canaries of every detected kind, in every format
and position and in encoded forms (percent, JSON `\u`, HTML entities,
look-alikes, zero-width characters), and checks every byte that leaves the
console: what the engine returns (CI job `suites`, with the oracle and
equivalence suites), and the IPC socket's replies, the audit file, the MCP
tools' outputs and the hub tickets' screens (`test/hub`). **0 leaks**,
checked on every pull request. Throughput and the budgets derived from
it are in [performance.md](performance.md).

## Highlights in full

- **Masked by construction.** Every record is masked inside the console
  before any predicate runs, and a predicate holding a clear email is
  refused (`E_PII_IN_QUERY`): the agent only ever works on the masked view. Equality on a
  pseudonym works, so "every record of this user" still does. (The opt-in
  `prefilter`, refused on production, is the documented exception.)
- **Investigation tools, not a query language.** `locklog_count` (with
  buckets and `first_last`), `locklog_patterns` (new templates against a
  baseline), `locklog_trace` (one request across sources),
  `locklog_context`, `locklog_search`, `locklog_tail`. Text never goes to a
  backend.
- **Free within budgets, approved beyond.** Reads are bounded per call and
  per hour. A call over a budget is refused before it touches data, and
  `locklog_scan` asks you once for the whole plan.
- **Your sources.** Files (globs, rotation, gzip, zstd), journald (a pure-Go
  reader), Docker container logs and Loki; Elasticsearch and OpenSearch as a
  preview (their incident gates come with v0.3.0).
- **Read-only.** Read-only mounts, a read-only root filesystem, an allowlist
  of backend endpoints, no Docker socket in any locklog container, no write
  path to any backend.

## Compared with other ways to read logs

Logs are where personal data hides in free text: an email in an error
message, a client IP in an access log, a token in a header someone logged.
An agent that runs `journalctl`, `docker logs` or `grep`, or queries Loki
with its own credentials, sends all of it to the model provider.

| | Agent reads logs directly | Agent with a log backend's own AI | locklog |
|---|:---:|:---:|:---:|
| The agent can answer "when did it start?" | ✅ | ✅ | ✅ |
| Personal values and secrets masked before the model | ❌ | rarely | ✅ |
| The agent never holds the log backend's credentials | ❌ | ✅ | ✅ |
| Self-hosted, any agent that speaks MCP | ✅ | ❌ | ✅ |
| A clear value reaches the agent only with your approval | ❌ | ❌ | ✅ |
| Every call audited, without clear values | ❌ | varies | ✅ |
