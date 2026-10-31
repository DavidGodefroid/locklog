# Security model

locklog lets an AI agent investigate logs without the model receiving the
personal data and secrets in them. This page states what locklog protects,
how, what it relies on, and what it does not do.

## What locklog protects

1. **Clear values.** Nothing unmasked leaves the console, except an unmask
   a human approves at the console (the exact spans, once). Secrets are
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
   locklog launcher (root-owned /usr/local/bin/locklog)
     ├─ console  locklog-console-<n>  uid 10051, no capability, read-only root,
     │    --cpus min(2,nproc) --memory 1g --pids-limit 256 --log-driver none,
     │    --allowed-uids …; read-only non-recursive binds of the approved roots
     │    volume locklog-home  keys, index, plans, audit, PII rules   (console only)
     │    volume locklog-run   socket dir 2750 locklog:locklog-clients (10051:10050), socket 0660
     │    network: none (local sources) | the backend's network | the hub's network
     └─ map loop  docker events → names and ids of the approved container globs

 agent (not locklog's): a lea container, the user's own agent container
   (gid 10050, its uid in --allowed-uids when needed), or, for the trial,
   the host agent through `locklog mcp`
```

The console is the only component that reads logs, holds credentials, keeps
the pseudonym keys and decides what leaves.

## What locklog enforces

| # | Invariant | Mechanism |
|---|---|---|
| 1 | No locklog container has an engine socket | launcher; goldens |
| 2 | The console shares only `locklog-run` with agents; the home volume, the map directory and the hub network never | launcher, `lock up`, lea's label check |
| 3 | Nothing unmasked leaves the console except an approved unmask; secrets never | masking pipeline, typed masked responses; canary harness |
| 4 | Agent predicates see only the masked view; every record is masked before any predicate; no text is sent to a backend; plans, charges and stopping points depend on the plan, never on matches; agent rules only tighten | engine, oracle and equivalence suites |
| 5 | Approved operations run only on a decision bound to the plan hash (exact spans for an unmask, the whole plan for a scan) and the policy fingerprint, once; never auto-approved for `read-pii`. With the hub (v0.2.0), `read-pii` only from `tty`, `deck` or `mobile` | lockkit plans and tickets; the facade check lands with the hub |
| 6 | No approve or reveal method on the agent socket | lockkit |
| 7 | Hub unreachable ⇒ approvals wait; free reads continue with the local audit | hub client |
| 8 | No hub auto-discovery | lockkit |
| 9 | Only approved sources are opened; the policy is the approved copy; `.locklog/` is read-only for lea agents | approved store, mount plan, dev/inode checks |
| 10 | Log content is untrusted text everywhere | JSON-escaped under an "untrusted" header, controls replaced; injection corpus |
| 11 | Resources are bounded | plans, rolling budgets, a queue, container limits, decompression, response and journal DATA caps, a 64 MiB result cache |
| 12 | Every call is audited, chained, without clear values | lockkit audit |
| 13 | No egress except the configured backends; production backends authenticated over TLS | network none or a dedicated network; a dialer pinned to host:port; no proxy environment, no redirects off-host; an unauthenticated-read check |
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
  - write the human's launcher state: `$XDG_RUNTIME_DIR/locklog`, or
    `~/.local/state/locklog` where there is no runtime directory, and the
    environment the human starts the launcher with.

  A standalone `.locklog/` outside lea is reviewed by the console. Placing
  the agent is lea's job, or the job of your own agent container. Whether
  agents may join `LOCKLOG_NETWORK` also falls under P1: they must not.
- **P2** Agents of one uid are one trust domain. In the own-container
  recipe, the agent user must not have sudo. Otherwise every agent that
  mounts one `locklog-run` is one domain.
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

The **host-agent trial** (`locklog setup --agent host`) runs the MCP server
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
remove it or change its kind. They will be stored in the console's home
volume, never in the project's `.locklog/`, once the console serves them
([#64](https://github.com/DavidGodefroid/locklog/issues/64)); until then the
tools answer that there are no rules.

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

## Prompt injection

Log content is data. Results are JSON-escaped under an "untrusted log lines"
header, with control, bidi and zero-width characters replaced. Content
cannot make locklog do anything beyond the agent's call, and nothing the
agent does through locklog writes or unmasks without the human.

## Retention

| Data | Where | Kept |
|---|---|---|
| Audit (one chained line per call) | home volume | until you delete it. It holds the method, the source names, the time range, the decision, the peer and the pseudonyms an unmask or lookup named; not the predicates. The **reason the agent typed** for an approval is kept, masked by the detectors: a personal value in a form the detectors miss stays there |
| Plans and approved scans | console memory | until used or expired (an approved scan: 30 minutes); gone when the session ends |
| Result cache | console memory | ≤ 64 MiB, gone when the session ends (a policy change, the console's exit) |
| Local index | home volume | per file identity, rebuilt when a file changes; trusted field values masked at answer time |
| Pseudonym keys | home volume | the current epoch's key; a replaced key until it has been replaced for `pseudonym_max_age` (30 days by default), deleted when the console opens the profile |
