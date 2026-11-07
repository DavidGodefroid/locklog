# Security model

locklog lets an AI agent investigate logs without the model receiving the
personal data and secrets in them. This page states what locklog protects,
how, what it relies on, and what it does not do.

## What locklog protects

1. **Clear values.** Nothing unmasked leaves the console, except an unmask
   a human approves on lockhub (the exact spans, once). Secrets are
   never unmasked or pseudonymised.
2. **Clear-text oracles.** The agent cannot learn whether a clear value it
   chooses occurs in the logs, except through the documented residuals
   below.
3. **The log backends.** locklog reads, never writes. Backend credentials
   stay in the console.
4. **The record of what happened.** Every call is audited in a hash chain,
   without clear values.

## Trust boundaries

```
 host (the human)
   lox run (lockhub), in a terminal of its own: the hub, and the decisions
     └─ console  (compose, one per lock)  uid 10051, no capability, read-only root,
          cpus min(2,nproc), memory 1g, pids 256, logging none,
          --hub … --instance …, --allowed-uids …; read-only
          non-recursive binds of the approved roots
          volume <project>_<name>-home  keys, index, audit, PII rules      (console only)
          volume <project>_<name>-run   socket dir 2750 locklog:locklog-clients (10051:10050), socket 0660
          network: the hub's (local sources) | and the lock's egress network (remote sources)
   locklog launcher (root-owned /usr/local/bin/locklog): profile add, init,
     doctor, and the host agent's mcp on the socket volume up.json names, read-only

 agent (not locklog's): a lea container, the user's own agent container
   (gid 10050, its uid in allowed_uids when needed), or, for the trial,
   the host agent through `locklog mcp`
```

The console is the only component that reads logs, holds credentials, keeps
the pseudonym keys and decides what leaves.

## What locklog enforces

| # | Invariant | Mechanism |
|---|---|---|
| 1 | No locklog container has an engine socket | launcher; `lox run`'s compose |
| 2 | The console shares only its socket volume with agents, read-only; the home volume, the map directory and the hub network never | `lox run`; the launcher's and lea's checks of up.json and the volume's labels |
| 3 | Nothing unmasked leaves the console except an approved unmask; secrets never | masking pipeline, typed masked responses; canary harness |
| 4 | Agent predicates see only the masked view; every record is masked before any predicate; no text is sent to a backend; plans, charges and stopping points depend on the plan, never on matches; agent rules only tighten | engine, oracle and equivalence suites |
| 5 | Approved operations run only on a decision bound to the plan hash (exact spans for an unmask, the whole plan for a scan) and the policy fingerprint, once. Auto approval only where the approved policy's auto rule for the action is `auto` (default `ask` for scans, unmasks and approved lookups; moving a rule toward `auto` is a reviewed loosening, typed profile name on production): any other ticket is signed `never_auto` and an auto rule's approval of it is refused (`ErrAuto`); a `deny` rule refuses the call before any ticket (`E_AUTO_DENY`). `read-pii` only from `tty`, `deck` or `mobile` | lockkit plans and tickets; the console's auto rules and facade check |
| 6 | No approve or reveal method on the agent socket | lockkit |
| 7 | Hub unreachable ⇒ approvals wait; free reads continue with the local audit | hub client |
| 8 | No hub auto-discovery: the console runs only with the hub flags `lox run` gives it | lockkit (`ErrNoHub`) |
| 9 | Only approved sources are opened; the policy is the approved copy; `.locklog/` is read-only for lea agents (lea placement planned) | approved store, mount plan, dev/inode checks |
| 10 | Log content is untrusted text everywhere | JSON-escaped under an "untrusted" header, controls replaced; injection corpus |
| 11 | Resources are bounded | plans, rolling budgets, a queue, container limits, decompression, response and journal DATA caps, a 64 MiB result cache |
| 12 | Every call is audited, chained, without clear values (the console's clear view, Ctrl-O, is counted as `shown_clear`, never recorded) | lockkit audit |
| 13 | No egress except the configured backends; production backends authenticated over TLS | network none or a dedicated network; a console with local sources only has, in hub mode, one interface besides the loopback: the one its `--hub` address is routed through, with no default route and no route through a gateway (lox run's internal hub network), refused otherwise; a dialer pinned to host:port; no proxy environment, no redirects off-host; an unauthenticated-read check |
| 14 | Read-only by construction | read-only binds and root; `O_RDONLY` beneath-root opens; HTTP method and path allowlists |
| 15 | Pseudonym keys never leave the home volume; old epoch keys are deleted | files 0600, rotation |
| 16 | Only the clients group, the image's `agent`, the console's own uid and `--allowed-uids` reach the socket (never root or 65534) | kernel peer credentials, lockkit peer check |

## Preconditions (not enforced by locklog)

Like every Lock, locklog protects the logs only from an agent that cannot
reach them by another path.

- **P1** The agent cannot:
  - read the logs, the Docker socket, the backends' unauthenticated ports
    or the cloud metadata service directly;
  - become the console's account;
  - write `lox run`'s state (`.lockfamily/`, its state directory) or the
    environment the human starts `lox run` and the launcher with.

  A `.locklog/` outside lea is reviewed by `lox run` and by the console.
  Placing the agent is lea's job, or the job of your own agent container.
  Whether agents may join the hub's or the lock's egress network also
  falls under P1: they must not.
- **P2** Agents of one uid are one trust domain. In the own-container
  recipe, the agent user must not have sudo. Otherwise every agent that
  mounts one lock's socket volume is one domain.
- **P3** Backend read credentials are held only by the console. Log
  shippers use write-only tokens.

`locklog doctor`, run where the agent runs, checks the usual ways P1 fails
and never prints a response body. It looks at:

- whether the Docker socket or `DOCKER_HOST` is reachable;
- membership of the groups `docker`, `adm` and `systemd-journal`;
- `sudo -n` and euid 0;
- whether `/var/log/journal` and `/var/lib/docker` are readable;
- cloud credential files in the agent's account;
- unauthenticated reads of the configured backends;
- the cloud metadata credential paths.

Each finding prints a remedy. On a production profile its findings are
errors and it exits 1. It also lists residuals: whether Landlock confines
the console, containers with `IpcMode` shareable, and swarm mode. See
[setup.md](setup.md).

The **host-agent trial** (`locklog init <agent>`, `.mcp.json`'s `locklog mcp`) runs the MCP server
as the image's `agent` account, launched from your own account. Your agent
there can still read whatever your account can, so the trial is for
non-production data. The launcher's `mcp` refuses production profiles.

## The masking pipeline

Order, fixed, per record and per field:

1. **Secret detectors** and secret-looking names → `⟦secret⟧`. This step
   is final: later steps run on its output, so a rule that pseudonymises a
   whole field never hashes a secret.
2. **Rules**: field and label names in `.locklog/pii.toml`, and value lists
   and regexes in the console-held rule directory.
3. **Personal field names** → pseudonym.
4. **Value detectors** on a detection view (folded, NFKC, without
   zero-width characters, with percent, JSON `\u` and HTML entities
   decoded): email, phone, IBAN, card, Belgian/French/Dutch/US national ids,
   public IP; person names and loose phone numbers are opt-in (`detectors`)
   for their false positives.
5. **Structured mode** (`redact-unknown`, the production default, or
   `detect`). The `text = "template"` setting is accepted but not applied
   yet.

A pseudonym is `⟦kind:ID⟧`: 12 Crockford base32 characters (60 bits) of an
HMAC-SHA256 under a random per-epoch key. The key rotates every 7 days by
default (`pseudonym_rotation`); a replaced key is deleted once it has been
replaced for `pseudonym_max_age` (30 days by default), when the console
opens the profile. There is no pseudonym-to-value store. An unmask re-reads
the record by its sealed reference.

Agent rules (`locklog_pii_add`) only tighten: they add masking and never
remove it or change its kind. They name only fields the agent was shown,
are capped (`pii_adds_per_hour`, `pii_rules_max`) and are stored in the
console's home volume only, never in the project's `.locklog/`, each field
as a keyed digest: the console's audit, terminal and approved policy hold
that digest (`agent redact <digest>`), never a name, so a name the agent
was shown masked is written nowhere. Every add, accepted or refused, is
audited; `locklog_status` and `:status` count the rules and the adds of
the last hour.

The allow rules of `.locklog/pii.toml` loosen the masking: they are part
of the reviewed policy. An added or widened allow rule waits for `:review`;
the engine applies only the allow rules of the approved policy, and
`:status` says how many in the file are not applied. Removing one only
tightens and applies at once.

## What is not masked

Values locklog does not detect:

- person names, unless the opt-in `person_name` detector is on (and names
  outside its heuristics when it is);
- usernames and logins in free text;
- postal addresses;
- private and loopback IPs;
- user agents and other quasi-identifiers;
- business ids;
- base64 or hex-encoded content;
- secrets without a known shape (short or low-entropy tokens, passwords in
  prose, session ids in URL paths, connection strings without userinfo).

Residuals by design:

- pseudonyms link a person's records within an epoch;
- `lookup` (a clear value → its pseudonym, rate-limited and audited, or
  approval-gated with `lookup = "approved"`) and an approved unmask link a
  known value to its records. This is membership probing by equality;
- how far a call got before its deadline reflects the content's detector
  density, rounded to plan granules. Aggregate byte volume and record length
  are visible at granule level;
- with the opt-in `prefilter = true` (refused on production), latency
  reveals how many records contain a clear substring.

Pseudonymised data is personal data (GDPR recital 26). The model provider
receives pseudonyms, timestamps, the fields locklog does not mask and the
residuals above.

## Containers' logs and later mounts

Docker forces `rslave` propagation for a bind source inside its data root.
A mount created after the console started (the `/dev/shm` of an
`--ipc=shareable` container, swarm secrets) therefore appears inside the
console's read-only bind, and it appears **read-write**. The console opens
only `<id>/<id>-json.log[.N[.gz]]` for mapped ids, without crossing a mount
point. Where the kernel has Landlock, it denies itself writes beneath its
roots. Even so, a compromised console could read such propagated files.
`doctor` names shareable-IPC containers and swarm mode as a residual.
Measurements are in [sources.md](sources.md).

## The console's confinement and its mounts

In its image the console applies a Landlock ruleset to itself before it
opens any source. It reads beneath the checked log roots, the containers
root and its map, the project's `.locklog` and the system files it still
needs: accounts, zone info, CA bundle, `/proc`, `/sys/class/net` and the
files of Go's resolver (`/etc/hosts`, `/etc/resolv.conf`,
`/etc/nsswitch.conf`), read at every lookup because remote sources and the
hub are dialled by name. It writes only to its volumes and `/tmp`. It may
read, write and put in no-echo mode the controlling terminal `/dev/tty`,
for a secret asked again; it already holds that terminal as its standard
streams. A log root at, beneath or above a writable directory (an extra
root under `/tmp` or the home volume) is refused: the ruleset would let the
console write there. `/proc` is granted whole, because no Landlock rule
follows a peer's pid.

The mounts are checked again on every call. These are the device:inode of
`.locklog` and of each root the launcher checked, plus a containers root
the launcher could not stat from the host, pinned by the console at its
first connection. A source whose root is gone, stale (`ESTALE`) or
replaced since it first read it ends the call as a lost session
(`CodeConnLost`). The console drops the session, and the next call
reconnects and checks everything again. A swap during one long call is
caught by the next call.

Without Landlock (an old kernel, the LSM off, its syscalls blocked by
seccomp), the console still starts and says so in `:status`. On a
production profile with local sources, `:status` and `doctor` also name
the residual: those sources are read by an unconfined console, and the
read-only mounts are their only guard.

## Prompt injection

Log content is data. Results are JSON-escaped under an "untrusted log lines"
header, with control, bidi and zero-width characters replaced. Content
cannot make locklog do anything beyond the agent's call, and nothing the
agent does through locklog writes or unmasks without the human.

## Retention

| Data | Where | Kept |
|---|---|---|
| Audit (one chained line per call, plus one per approval decision) | home volume | until you delete it. It holds the method, the source names, the time range (or the relative `last`, and a patterns `baseline` offset), the decision, the peer and the pseudonyms an unmask revealed or a lookup resolved; not the predicates. The **reason the agent typed** for an approval is kept, masked by the detectors: a personal value in a form the detectors miss stays there |
| Plans and approved scans | console memory | until used or expired (an approved scan: 30 minutes, or its plan's bound when longer, at most 4 hours, shown on its approval screen); gone when the session ends |
| Result cache | console memory | ≤ 64 MiB, gone when the session ends (a policy change, the console's exit) |
| Local index | home volume | per file identity, rebuilt when a file changes; trusted field values masked at answer time |
| Pseudonym keys | home volume | the current epoch's key; a replaced key until it has been replaced for `pseudonym_max_age` (30 days by default), deleted when the console opens the profile |
