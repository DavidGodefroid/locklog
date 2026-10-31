# Log sources: what the spikes measured

This page records what was checked on real systems before the source
adapters were written. Each row says how it was checked. Where a row could
not be checked here, it says so and names the source it relies on.

Spike date: 2026-10-31. Host: Ubuntu 24.04, kernel 7.0, Docker Engine and
CLI 29.7.2 (API 1.55), Docker Compose v5.4.0.

## journald (spike S1)

**Question.** Can a pure-Go reader return exactly what
`journalctl --file F -o json --all` returns, on the journal files that
current distributions write?

**Method.** Two kinds of fixture per distribution, made inside the stock
image (`debian:12`, `debian:trixie`, `ubuntu:24.04`, `fedora:41`):

- `systemd-journal-remote --split-mode=none` fed a seeded export-format
  stream of 2,000 synthetic entries (short and long messages, multi-line,
  UTF-8, binary fields, `COREDUMP*`, `_CMDLINE`, `_EXE`, `_AUDIT_*`,
  repeated values, past timestamps, three boots);
- a standalone `systemd-journald` fed through its native socket,
  `systemd-cat` and `logger` (503 entries, including long messages that
  journald compresses).

Then 16 more files from `systemd-journal-remote` on Ubuntu 24.04, one per
combination of `SYSTEMD_JOURNAL_COMPRESS` (`LZ4`, `XZ`, `ZSTD`, none),
`SYSTEMD_JOURNAL_COMPACT` (0/1) and `SYSTEMD_JOURNAL_KEYED_HASH` (0/1).
Finally, 10 real journal files from the spike host (system and user, active
and archived, up to 96 MiB and 187,000 entries). These were compared in
place and are not committed.

For every entry, the reader's fields (each value as a string, or as an
array of bytes when it is not printable UTF-8; a field that repeats becomes
an array), plus `__CURSOR`, `__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP`,
`_BOOT_ID`, `__SEQNUM` and `__SEQNUM_ID`, were compared as JSON values with
journalctl's output for the same entry. The reference is the journalctl of
the image that wrote the file (the host's 255.4 for the variants and the
real files). Debian 12's journalctl (252) does not print `__SEQNUM` and
`__SEQNUM_ID`, so those two were compared only where the reference has them.

| Distribution | systemd | Default file flags | remote fixture | native fixture |
|---|---|---|---|---|
| Debian 12 | 252.39 | ZSTD, KEYED-HASH, COMPACT | 2,000 / 0 mismatches | 503 / 0 |
| Debian 13 | 257.13 | ZSTD, KEYED-HASH, COMPACT (+ TAIL_ENTRY_BOOT_ID) | 2,000 / 0 | 503 / 0 |
| Ubuntu 24.04 | 255.4 | ZSTD, KEYED-HASH, COMPACT (+ TAIL_ENTRY_BOOT_ID) | 2,000 / 0 | 503 / 0 |
| Fedora 41 | 256.17 | ZSTD, KEYED-HASH, COMPACT (+ TAIL_ENTRY_BOOT_ID) | 2,000 / 0 | 503 / 0 |
| Ubuntu 24.04, 16 flag variants | 255.4 | LZ4 / XZ / ZSTD / none × compact × keyed hash | 16 × 2,000 / 0 | — |
| Ubuntu 24.04 host, 10 real files | 255.4 | ZSTD, KEYED-HASH, COMPACT | 551,290 entries / 0 | — |

**Result: exit criterion met.** The four distributions are field-identical, plus all flag variants.
LL-10 uses the pure-Go reader; the `-journal` fallback variant is not needed.

Notes for LL-10:

- Every current default is `COMPRESSED-ZSTD KEYED-HASH COMPACT`. LZ4 and XZ
  appear only in older files and on explicit configuration, but the reader
  handles both.
- Walking the entry-array chain from the header gives journalctl's order
  for one file. Unused trailing slots are 0. A file that is still online
  (being written) reads correctly.
- Speed: one core reads 275,000 entries/s (237 MB/s of field payload),
  with a small cache of DATA objects up to 512 bytes, keyed by offset.
  `journalctl -o export` on the same 96 MiB file runs at about 140 MB/s.
  Without the cache the reader is 5.6 times slower, because entries share
  their `_HOSTNAME`, `_SYSTEMD_UNIT`, … DATA objects.
- Caps are checked before allocation. For ZSTD, the frame header's content
  size when present, and in every case a decode limited to the cap (the
  size is optional and written by whoever wrote the file); for LZ4, the 8-byte size prefix; for XZ and uncompressed data, a
  limited read; on disk, the object size. A field over the 1 MiB DATA cap
  is dropped, not truncated.
- A DATA object holds the field name inside its (possibly compressed)
  payload. To skip a field that is not allowed (`COREDUMP*` and the rest)
  without decompressing all of it, decode only the first 65 bytes, a
  streaming decode for ZSTD and XZ. LZ4 blocks are decoded whole, under the
  cap.

## Docker and Podman containers (spike S2)

Checked on Docker Engine 29.7.2 with containers made for the spike
(`json-file` with `max-size=20k, max-file=4, compress=true` and a
`labels=team` log option). Modes were read with `stat` through a read-only
bind; no other container's log was read.

### Modes

| Path | Mode | Owner | Consequence |
|---|---|---|---|
| `/var/lib/docker/containers` (the containers root) | 0710 | root:root | gid 0 can traverse, not list: ids must come from the map, files are probed by name |
| `<root>/<id>/` | 0710 | root:root | same |
| `<id>-json.log` | 0640 | root:root | readable with `--group-add 0` |
| `<id>-json.log.1.gz` … `.3.gz` (with `max-file=4`) | 0640 | root:root | all rotated files are compressed (`.1` included), so N < max_file |
| `config.v2.json`, `hostconfig.json` | 0600 | root:root | unreadable with gid 0 (checked) |
| `hostname`, `hosts`, `resolv.conf`, `resolv.conf.hash` | 0644 | root:root | world-readable; the console never opens them |
| `<id>/checkpoints/` | 0700 | root:root | — |
| `<id>/mounts/` | 0710 | root:root | traversable with gid 0, see "Submounts" |

A json-file line with a `labels` log option looks like this:
`{"log":"…\n","stream":"stdout","attrs":{"team":"shop"},"time":"2026-10-31T01:20:40.732446205Z"}`.
That is why the `attrs` allowlist exists.

### Reading with `--group-add 0`, no capability

A container running as uid 10051 with `--group-add 0 --cap-drop ALL
--security-opt no-new-privileges` and a read-only bind of the containers
root:

- reads `<id>-json.log` and the rotated `.N.gz` by name;
- cannot list the root or `<id>/`, and cannot read `config.v2.json` or
  `hostconfig.json`;
- gets EROFS when it tries to write.

Without `--group-add 0`, the log is unreadable. The group grants read on
every container's json log whose id is known. Only the console's open
discipline keeps it to the mapped ids: names from the map, beneath-root
opens, nothing else opened. This is in-process, like the egress pin.

### Non-recursive binds

| Option | Engine 29 / CLI 29 | Result |
|---|---|---|
| `--mount type=bind,…,readonly,bind-recursive=disabled` | accepted | submounts that exist when the console starts are not visible |
| `--mount …,bind-nonrecursive=true` | **refused by CLI 29** before anything reaches the engine: "bind-nonrecursive is deprecated, use bind-recursive=disabled instead" | the CLI parses the option, so the launcher must choose it by the **client** version: `bind-recursive=disabled` needs CLI ≥ 25 *and* Engine ≥ 25 (API 1.44); `bind-nonrecursive=true` is known to work with CLI 19.03-24 (Docker's docs; not run here). CLI 25-28 were not run either: they may accept it with a deprecation warning [NV]. Until checked, the safe rule is to use `bind-recursive=disabled` when both are ≥ 25, `bind-nonrecursive=true` with a CLI < 25, and refuse a CLI ≥ 25 against an Engine < 25 unless CLI 25-28 are shown to accept the old form |
| `-v …:ro` (default, recursive) | accepted | an existing `mounts/shm` tmpfs of an `--ipc=shareable` container is visible |
| Compose: `volumes: [{type: bind, source, target, read_only: true, bind: {recursive: disabled}}]` | Compose v5.4.0, accepted | non-recursive, as with `--mount` |

### Submounts created after the console starts (finding)

Docker forces `rslave` propagation for any bind source inside its data
root. `bind-propagation=private`, `rprivate` and `slave` are each refused:
"must use either propagation mode rslave or rshared when mount source is
within the daemon root". `bind-recursive=disabled` hides only the submounts
that exist at start.

Check: we started a reader with a non-recursive read-only bind, then started
an `--ipc=shareable` container. Its `mounts/shm` tmpfs propagated into the
reader **read-write** (`rw,nosuid,nodev,noexec`, mode 1777). The reader,
uid 10051 with gid 0, could create a file in the other container's
`/dev/shm` (the file was removed after the check). The tmpfs is mode 1777,
so any uid that can reach it can write; gid 0 matters only for traversing
the 0710 `<id>/` and `mounts/` directories on the way. Swarm secrets
(`mounts/secrets`) would propagate the same way. That was not checked here:
the host is not a swarm manager.

Consequences, for LL-11 and LL-09a:

- Read-only by construction does not hold for paths that appear later under
  the containers root. Counter-measures, in order:
  1. the console opens only `<id>/<id>-json.log[.N[.gz]]` for mapped ids, with
     `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
     RESOLVE_NO_XDEV)`. `RESOLVE_NO_XDEV` refuses a path that crosses into a
     propagated mount. The fallback runs when `openat2` returns ENOSYS (kernel < 5.6)
     or EPERM (a seccomp profile without it): one `openat(O_NOFOLLOW)` per
     component, each checked against the root's mount, by mount id
     (`statx` `STATX_MNT_ID`) on kernel ≥ 5.8, otherwise by `st_dev` plus a
     check that no line of `/proc/self/mountinfo` has a mount point beneath
     the root. `st_dev` alone catches the tmpfs submounts observed (shm,
     secrets) but not a bind mount of the same filesystem;
  2. a Landlock ruleset (kernel ≥ 5.13), applied by the console to itself
     before it opens any source, grants only read rights beneath each mount
     root. A write to a propagated read-write mount then fails, even after a
     parser exploit. Landlock does **not** limit reads: beneath the root it
     grants read on propagated mounts too, and no Landlock rule can exclude a
     subdirectory of an allowed tree. After an exploit, the console could
     therefore read other containers' `/dev/shm` files (1777) and, on a swarm
     engine, `mounts/secrets` files (Docker's default 0444), traversing the
     0710 directories with gid 0. Only counter-measure 1 limits reads, and only
     while the process is not compromised;
  3. `doctor` names containers with `--ipc=shareable` and a swarm-mode
     engine as a residual: their shared memory and secrets are readable by a
     compromised console;
  4. `docs/security-model.md` states it.
- The `LL14` test "no submount" must start the console first, then start an
  `--ipc=shareable` container, and assert that the console cannot open or
  write anything under the propagated mount.

### `docker events` for the map loop

`docker events --filter type=container --format …` on create → start → die
→ rename → destroy gives one line per action. `Actor.Attributes.name` is the
name at the event (the new name on `rename`, which also carries `oldName`).
The loop needs `create`, `rename` and `destroy`. At start and after a
reconnect, it first subscribes to the events stream, then takes a full
`docker ps -a --no-trunc` snapshot, then applies the events buffered since
the subscription. In that order nothing between the snapshot and the
subscription is lost, and no `--since` replay is needed.

`docker compose up --force-recreate` gives a new id and **deletes the old
container directory with its logs**, checked. History across deploys needs
the journald driver or Loki, as `doctor` and the README say.

### Podman (5.8.9, nested in `quay.io/podman/stable`, rootful and rootless)

| Path (rootful) | Mode |
|---|---|
| `/var/lib/containers/storage` | 0700 root:root |
| `…/overlay-containers/<id>/` and `<id>/userdata/` | 0700 root:root |
| `…/userdata/ctr.log` (`k8s-file`) | 0640 root:root |

Rootless: the same layout under `~/.local/share/containers/storage`, owned by
the user, `userdata/` 0700 and `ctr.log` 0640.

**Rootful `k8s-file` logs are not readable without privilege.** `--group-add
0` does not help, because the directories are 0700. The plan's allowlisted
root `…/overlay-containers/<id>/userdata` cannot be traversed by uid 10051,
and locklog takes no `CAP_DAC_READ_SEARCH`. Supported Podman paths in v1:

- the `journald` log driver (Podman's default where journald runs), read by
  the journald source;
- `--log-opt path=/var/log/containers/<name>.log` with `k8s-file`, read by the
  file source with `format = "cri"`. The mode and owner Podman gives that file
  and its directory were **not** recorded [NV]; LL-11 must check that uid
  10051 with an allowlisted group can read it before calling this supported.

`doctor` must say so. The CRI line format was confirmed:
`2026-10-31T01:23:48.564078242+00:00 stdout F rootful line`.

### Not checked here

- `/var/log/pods` (kubelet). No cluster on the spike host. The plan's
  root:root 0640 stays [NV] until LL-11's integration run; kind or k3s in CI
  can check it.
- `bind-nonrecursive=true` on Engine and CLI 19.03-24, and with CLI 25-28.
- Swarm secrets propagation.
- Rootless Docker (unsupported in v1, named by `doctor`).
- Mode and owner of a Podman `k8s-file` log written to `--log-opt path=`.
