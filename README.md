<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="site/assets/banner-dark.svg">
    <img alt="locklog — Your AI reads the logs, not the people in them." src="site/assets/banner-light.svg" width="600">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/DavidGodefroid/locklog/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/DavidGodefroid/locklog/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/DavidGodefroid/locklog/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/DavidGodefroid/locklog?include_prereleases&color=0EA5E9"></a>
  <img alt="Go 1.26+" src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white">
  <a href="LICENSE"><img alt="Apache 2.0" src="https://img.shields.io/badge/license-Apache%202.0-0EA5E9"></a>
</p>

<p align="center">
  <b>Let Claude Code, Codex, Cursor or Gemini CLI investigate your production logs.<br>
  The personal data and secrets locklog detects never reach the model without your approval.</b>
</p>

<p align="center">
  <img src="site/assets/demo.svg" alt="Claude Code asks when the PDF errors started on a staging profile. locklog_count shows the step at 14:02, locklog_patterns finds the new pattern with the email and the IP masked, and locklog_trace follows order 4812: all free and masked. The agent then asks locklog_unmask for the email. The locklog console, in its own account and container, shows the read-pii approval screen with the masked record and the span marked; the human answers n. The agent gets denied and carries on without the address; the audit records every call with pseudonyms only." width="900">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#safety-model">Safety model</a> ·
  <a href="#what-is-not-masked">What is not masked</a> ·
  <a href="#sources">Sources</a> ·
  <a href="#install">Install</a> ·
  <a href="docs/usage.md">Docs</a> ·
  <a href="https://locklog.dev">Website</a>
</p>

---

locklog lets an AI agent find **when** and **where** something broke in your
logs without reading them in clear. A console held by a human, in its own
account and container, reads the logs. The agent asks over MCP and gets
masked, bounded, typed answers: counts, patterns, traces, lines around a
hit. Emails, IPs, card numbers, national ids and the other values locklog
detects become **pseudonyms** (`⟦email:7F3KQ2M9ZD4X⟧`), and secrets become
`⟦secret⟧`, before anything leaves the console. Reads are free. Handing a
clear value to the agent waits for your approval at the console and is off
by default on production.

> [!NOTE]
> **Early release.** v0.1.0 is the first release: see the
> [CHANGELOG](CHANGELOG.md) for what it holds and what is still open.
> Built on [lockkit](https://github.com/DavidGodefroid/lockkit).
> The design is public in [docs/security-model.md](docs/security-model.md);
> what the spikes measured is in [docs/sources.md](docs/sources.md) and
> [docs/performance.md](docs/performance.md).

## Why locklog?

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

## Highlights

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

## Quick start

**Prerequisites:** a Linux host with the logs, Docker ≥ 19.03,
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/), and
sudo for `/usr/local/bin`. The trial below takes about five minutes. Run it
on a **non-production** profile: your agent runs on your own account, where
it could still read the logs directly.

```sh
# 1. Install the launcher (it verifies the release and the image with cosign)
curl -fsSL https://locklog.dev/install.sh | sh

# 2. Describe your logs: setup detects files, journald and containers,
#    asks whether the profile is production (answer "no" for the trial),
#    and wires the detected agents (Claude Code, Codex, Cursor, Gemini CLI)
locklog setup --agent host     # or only some agents: --agents claude

# 3. The console, in a terminal you keep in view (setup prints the line;
#    containers get a profile of their own, <profile>-docker)
locklog console --profile <profile>
```

Then, in another terminal, ask your agent: *"when did the 502s start?"*.
It calls `locklog_count`, `locklog_patterns` and `locklog_trace`; the
console audits every call and asks you only when the agent wants more than
the free budgets or a value in clear. On the host, `locklog mcp` refuses
every call on a production profile (`E_PRODUCTION_HOST_AGENT`): the host
agent is the trial.

### For production

On production the agent must not be able to read the logs, the Docker
socket or the backends itself (precondition P1 below). Run it:

- in **its own container**: `locklog setup --agent container` prints a
  tested Dockerfile snippet for your agent image and the `docker run` line.
  The agent user must not have sudo. See [docs/setup.md](docs/setup.md).

Support in [lea](https://github.com/DavidGodefroid/lea) is planned; no lea
release supports it yet (`locklog setup --agent lea` says so).

Your agent CLI's own login (Anthropic, OpenAI, Google) is yours to set up.

## How it works

```
 host (you)
   locklog launcher
     ├─ console container  locklog-console-<n>   uid 10051 "locklog", no capability,
     │    read-only root, --cpus min(2,nproc), --memory 1g, --log-driver none
     │    read-only, non-recursive binds of the approved log directories
     │    volume locklog-home: pseudonym keys, local index, audit, rules (console only)
     │    volume locklog-run:  /run/locklog (2750 locklog:locklog-clients), one socket
     │                         per project and profile, <project-hash>-<profile>.sock (0660)
     │    network: none, or the backend's network for Loki
     └─ map loop: docker events → container names and ids of the approved globs

 agent (yours: your own container, or the host for the trial; lea planned)
   MCP server `locklog mcp` → its project's socket in /run/locklog (peer uid checked by the kernel)
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
| `pii_list` / `pii_add` (agent masking rules, tighten only) | free, capped, audited (served once the console's PII backend lands, [#64](https://github.com/DavidGodefroid/locklog/issues/64)) |
| `locklog_scan` (beyond a budget, approved once for its whole plan; its cursor continues free for 30 minutes) | you, at the console |
| `locklog_unmask` (the clear value of exact spans of one record, once) | you, at the console, never auto-approved; **off by default on production** |
| `locklog_request_change` (any loosening) | you, at the console's `:review` |
| write, delete, admin | does not exist |

The unmask screen shows the record **masked**, with the asked spans marked
`» «`, the agent's reason and what a yes lets the agent link. To read a
record yourself without sending anything to the agent, turn clear results
on with Ctrl-O: the records the agent's calls return are then printed in
clear on the console's terminal (secrets kept redacted), and an unmask
screen shows its record in clear too. Secrets are
never unmasked. On a non-production profile, auto mode (Shift+Tab) can
approve scans for you; unmasks and approved lookups always wait for you, and
production stays in manual mode.

## Safety model

locklog enforces what it owns:

- the console's **peer check**: only the clients group (10050), the image's
  `agent` (10052) and the uids you list in `--allowed-uids` reach the
  socket, never root or `nobody` (the launcher does not pass
  `--allowed-uids` yet: [#102](https://github.com/DavidGodefroid/locklog/issues/102));
- its mounts (read-only, non-recursive), its network, and its image
  hardening; **no Docker socket** in any locklog container;
- on production, backends with **authentication over TLS**, and a refusal
  when an endpoint answers a read without credentials;
- the masking pipeline, the budgets, and approvals bound to the exact plan
  (single use; an unmask re-reads the record and is refused if anything
  moved since you approved it).

Like the other Locks, it relies on three **preconditions** it does not
enforce:

- **P1** The agent cannot read the logs, the Docker socket, the backends'
  unauthenticated ports or the cloud metadata service directly, cannot
  become the console's account, and cannot write your launcher state.
  That is lea's job, or your own container setup's.
- **P2** Agents of one uid are one trust domain.
- **P3** Backend read credentials are held only by the console. Log
  shippers use write-only tokens.

`locklog doctor`, run where the agent runs, checks the common ways P1
fails. It reports and never prints a response body. Details:
[docs/security-model.md](docs/security-model.md).

## What is not masked

locklog masks the values it **detects**. It does not detect:

- person names unless you enable the opt-in `person_name` detector (and
  names outside its heuristics when you do), usernames and logins in free
  text, postal addresses;
- private and loopback IPs (infrastructure, never detected), user agents and
  other quasi-identifiers;
- business ids (order and customer ids, kept so `trace` works);
- base64 or hex-encoded content;
- secrets without a known shape: short or low-entropy tokens, passwords in
  prose, session ids in URL paths, connection strings without userinfo.

It also leaks, by design:

- pseudonyms link a person's records within an epoch (7 days by default),
  and `lookup` or an approved unmask links a known value to them;
- how far a call got before its deadline reflects content density, rounded
  to plan granules, and so do aggregate byte volumes.

Pseudonymised data is still personal data under the GDPR: the model
provider receives pseudonyms, timestamps and the fields locklog does not
mask. Tighten with `redact-unknown` (the production default for structured
logs), your own rules, and `lookup = "approved"`.

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

Loki 3 users: see [docs/loki.md](docs/loki.md) on the default
`detected_level` field: what Loki puts in it, and how locklog selects on it
(locally, never as a Loki filter).

## Masking benchmark

The leak harness plants canaries of every detected kind, in every format
and position and in encoded forms (percent, JSON `\u`, HTML entities,
look-alikes, zero-width characters), and checks every byte that leaves the
console: **0 leaks**, checked on every pull request (CI job `suites`, with
the oracle and equivalence suites). Throughput and the budgets derived from
it are in [docs/performance.md](docs/performance.md).

## Install

```sh
curl -fsSL https://locklog.dev/install.sh | sh
```

`install.sh` installs the latest **published** release, or
`LOCKLOG_VERSION=vX.Y.Z`. It verifies the release with cosign before it
installs a root-owned `/usr/local/bin/locklog`, and the launcher runs the
image by its signed digest. To read the script first:

```sh
curl -fsSLO https://locklog.dev/install.sh   # or raw.githubusercontent.com/DavidGodefroid/locklog/main/scripts/install.sh
less install.sh && sh install.sh
```

`locklog update` moves to another release; `locklog version` shows the
launcher's and the image's versions.

## Status

v0.1.0, in active development: see the [CHANGELOG](CHANGELOG.md). It ships
files, journald, Docker and Loki with the standalone console, and
Elasticsearch and OpenSearch as a preview.
v0.2.0 adds the hub (`lock up`, `lock approve`), and v0.3.0 the
Elasticsearch and OpenSearch incident gates and the masked export.

## The Lock family

locklog is one of the [Locks](https://lockfamily.dev):
[locksql](https://github.com/DavidGodefroid/locksql) (databases),
[lockmq](https://github.com/DavidGodefroid/lockmq) (message queues),
[lockfile](https://github.com/DavidGodefroid/lockfile) (files),
[lockhttp](https://github.com/DavidGodefroid/lockhttp) (the web) and
locklog (logs), on the shared engine
[lockkit](https://github.com/DavidGodefroid/lockkit), with
[lockhub](https://github.com/DavidGodefroid/lockhub) to run them together
and [lea](https://github.com/DavidGodefroid/lea) to run the agents.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE).
The demo is generated by `python3 scripts/brand/demo.py > site/assets/demo.svg`.
