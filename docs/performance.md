# Performance: spike numbers and the defaults derived from them

The S3 (backends) and S4 (masking throughput) spikes measured these numbers
on 2026-10-31. Budgets, chunk sizes and perf thresholds start from them.
The nightly `perf` job replaces them with CI numbers once the engine exists.

Spike host: 22 logical CPUs, 30 GiB RAM, NVMe, Docker 29.7.2. The backends
ran in containers limited to `--cpus 4 --memory 4-6g`. Every client used one
connection pool, on loopback.

## S3 — backends

### Loki 3.5.7 (single binary, filesystem, TSDB schema v13)

Data: 2 GiB of lines in one dense hour (15.6 M lines, 12 streams sharded to
24-48 by Loki), plus 512 MiB of background over the 7 days before it
(4.2 M lines). Each line carried structured metadata `trace_id` (always) and
`user_email` (one line in three).

Ingest overrides needed for a test corpus with past timestamps (to document
in `TestLokiIncident`): `reject_old_samples: false`, `unordered_writes: true`,
and high `ingestion_rate_mb` / `per_stream_rate_limit`. The out-of-order
window is not a separate setting: Loki accepts an entry only up to `max_chunk_age / 2` behind the
newest entry of its stream, so either push in time order or raise
`max_chunk_age` (24 h used here). The push itself ran at about 22 MiB/s
(JSON + gzip, 4 writers).

| Measure | Result |
|---|---|
| `index/stats` latency | 0-20 ms |
| **`index/stats` accuracy** vs exact `bytes_over_time` | **not usable as a size**: same 1 h query, two runs a few minutes apart: 1.93× over, then 0.15× (6.7× under); 7 d: 4.3× and 11.5× over. It counts whole chunks and depends on what the ingesters have flushed |
| `index/volume` by `level`, 1 h | 3 ms |
| instant `sum(count_over_time({sel}[1h]))` over the dense hour | 7-14 s; 3.2 GiB "processed" by Loki's own count (1.6× the line bytes) |
| range `sum by (level)(count_over_time({sel}[1m]))`, 1 h / step 60 s | 14-15 s, 3.2 GiB processed |
| same, 24 h / step 300 s | 15-17 s, 3.4 GiB processed |
| same, 7 d / step 3600 s | 16-21 s, 4.6 GiB processed |
| raw `query_range` page, `limit` 5000 (1.75 MiB) | 180-530 ms |
| raw fetch (response bytes), 1 request in flight | 9.8 MiB/s (5.7 req/s) |
| 2 in flight | 17.3 MiB/s |
| **4 in flight** | **20.0 MiB/s (11.5 req/s), the knee** |
| 8 in flight | 17.4 MiB/s (no gain) |

Structured metadata: **without** the request header
`X-Loki-Response-Encoding-Flags: categorize-labels`, Loki 3 merges
structured metadata (`trace_id`, `detected_level`) into each stream's label
set. An untrusted metadata field then looks like a label. With the header,
the response puts labels in `stream` and moves structured metadata into a
third array element per value: `{"structuredMetadata": {...}}`. The
response says so in `encodingFlags`. `detected_level` is added by Loki
(`discover_log_levels`) as structured metadata. `/labels` lists only real
stream labels, plus Loki's `__stream_shard__`, which LL-18 must hide.

### Elasticsearch 8.14.3 and OpenSearch 2.19.3 (single node, 1 shard)

Data: 3 M documents, 806 MiB source, one hour, `@timestamp` as `date_nanos`.

| Measure | Elasticsearch | OpenSearch |
|---|---|---|
| `_count`, range + `term` | 52 ms (exact) | 13 ms (exact) |
| `date_histogram` 1 m × `terms(level)`, 1 h | 243 ms | 107 ms |
| `search_after` page, `size` 1000, sequential | 32 ms/page, 11 MiB/s | 24 ms/page, 15 MiB/s |
| 2 in flight | 20.5 MiB/s | 34.2 MiB/s |
| 4 in flight | 27.8 MiB/s | **50.9 MiB/s** |
| 8 in flight | 38.6 MiB/s | 33.8 MiB/s |

`_count` is exact and cheap, so it is a usable plan size for ES/OpenSearch.
Loki's `index/stats` is not.

Grafana Cloud was not measured (no account). Its documented defaults apply:
5,000 entries per query and a capped query length. They are [NV] until
someone runs against a real tenant.

## S4 — masking throughput

Measured: `pii.FindInViews` (detection views + every detector, `secret`
and `ip` included) plus `Pseudonymizer.ID` per match. The code was lockkit
`feat/pii-pseudonyms` (K-LL1 + K-LL2) merged with `feat/pii-ip-secret`
(K-LL3) at `26afaf4`. One core (`GOMAXPROCS=1`), 2,000 lines per corpus.

| Corpus (avg line) | Matches/line | MB/s/core, all detectors | without `secret` |
|---|---|---|---|
| nginx combined (211 B) | 1.0 | 0.9 | 5.3 |
| JSON app log (253 B) | 1.0 | 1.0 | 6.1 |
| plain syslog text, no PII (114 B) | 0 | 1.0 | 7.2 |
| dense PII (147 B) | 6.0 | 0.9 | 5.2 |
| percent / HTML / `\u` encoded (138 B) | 3.0 | 0.2 | 1.3 |
| worst: 4 KiB digit runs | 20.6 | 1.1 | 7.9 |
| worst: 4 KiB of `a@b.c` | 0 | 1.2 | 8.3 |
| worst: 4 KiB of `%41%2540&#x41;A` | 0 | 0.3 | 1.4 |
| worst: 4 KiB hex runs | 0 | 0.8 | 3.6 |
| worst: 4 KiB `api_key=` / `Bearer` pairs | 2.0 | 1.4 | 5.1 |

About 85 % of the time goes to the `secret` detector. Within it, 70 % is the
token-shape alternation, which has no literal prefix Go's regexp can use.
A literal-prefix gate costs about 1/75 of it. This is reported on lockkit#97
with a request for a floor benchmark.

Parsing only (what the local index costs per byte; values of trusted
fields pass the detectors once per distinct value): nginx combined
**160 MB/s/core**, JSON **80 MB/s/core**.

Calibration stability: a fixed mixed corpus, 2 workers, 5 runs, the binary
run in `alpine` under a cgroup limit: `--cpus 2`, CV 6.2 %; `--cpus 1`, CV
3.5 % (throughput halves, as expected).

One 256 KiB event (the cap; Find scans the first 64 KiB and masks the rest
whole) takes 268 ms with every detector, 46 ms without `secret`.

## Defaults derived (for LL-05, LL-06, LL-18, LL-19, LL-16/16b)

The pipeline is bound by masking, not I/O. 2 cores × about 1 MB/s/core
gives about **60 MB per 30 s call**. A remote call is bound by masking too,
because Loki's 20 MiB/s of responses carry about 7.5 MiB/s of log lines, about 4× faster. The plan's "4 GiB local / 2 GiB
remote per call" targets cannot be met at today's detector speed. The
admission default below is 512 MiB for both. The code ceiling stays at the
plan's 64 GiB for both: it is the most a profile may configure. Within the
admitted bytes, the deadline does the stopping (`complete:false` + cursor,
continued free).

| Setting | Default | From |
|---|---|---|
| per-call bytes, local (admission) | **512 MiB** (ceiling 64 GiB) | at 60 MB per call, about 9 calls (8 free continuations). Narrowed hour at 1 GiB/day (42 MiB): 1 call. At 7 GiB/day (300 MiB): about 5 calls, about 2.5 min, inside the 5-minute gate |
| per-call bytes, remote (admission, fetched) | **512 MiB** of response bytes (ceiling 64 GiB) | masking-bound, as local; 512 MiB of responses is ≈ 192 MiB of lines, ≈ 3-4 calls on this corpus |
| plan chunk (local) | **1 MiB** (one granule, `source.GranuleBytes`) | worst-case cost ≈ 5 µs/B (the encoded corpus, 0.2 MB/s/core): 1 MiB then takes ≈ 5.2 s per core, within the rule "a chunk's worst case ≤ 1/4 of the 30 s deadline" (7.5 s) |
| calibration corpus | **1 MiB fixed mixed corpus**, 3 passes (3.15 MB, ≈ 1.6-3.1 s at ≈ 1-2 MB/s aggregate on 2 workers) at start, hourly | measured CV 3.5-6.2 %, so a deviation under 10 % is noise. Recalibrate when a chunk takes > 1.5× its prediction |
| worst-case cost per byte (engine constant, before calibration) | **5 µs/B per core** (all detectors) | the slowest corpus (encoded, 0.2 MB/s/core). The 256 KiB event (268 ms) is 4.1 µs per *scanned* byte, since Find scans its first 64 KiB |
| Loki in-flight per source | **4** | knee of the curve |
| Loki `limit` | **5000** (Loki's default max) | 1.75 MiB pages: about 367 B per entry in the response (JSON, timestamp, `categorize-labels` metadata) for lines that average 137 B, so about 37.5 % of response bytes are line bytes |
| Loki rolling requests/min | **600 non-prod / 240 prod** (plan had 240 / 60) | at 4 in flight, Loki serves about 690/min; 600/min does not throttle it. Production must not throttle below masking speed (≈ 2 MB/s of lines on 2 cores): 240/min = 4 req/s × 5000 × 137 B ≈ 2.7 MB/s of lines. 150/min would give ≈ 1.7 MB/s, below it |
| Loki byte plans | **time slices + bytes actually fetched**, not `index/stats` | `index/stats` was off by −85 %…+1050 %. Use it only as an advisory estimate in `E_OVER_BUDGET` messages. Budgets charge **fetched bytes = response body bytes** (what crosses the network; ≈ 2.67× the line bytes on this corpus), which depend only on time + trusted selector, never on predicates |
| Loki structured metadata | always send `X-Loki-Response-Encoding-Flags: categorize-labels` | without it, untrusted metadata is merged into labels |
| Loki metric counts | per query 7-21 s for 1 h-7 d on 3.2-4.6 GiB processed. The 200 GiB/h prod / 1 TiB/h non-prod "server-processed" budget allows about 40 / 200 such queries per hour | — |
| ES/OpenSearch in-flight | **4**, `size` 1000 | OpenSearch's knee (51 MiB/s of responses). Elasticsearch still gains up to 8 (39 MiB/s), but the pipeline is masking-bound well below either |
| ES/OpenSearch plans | `_count` (exact) | — |
| approved-scan request rate | 4 in flight, no per-minute cap beyond the backend's own (R6-P2) | — |
| local index build budget | 20 GiB/h idle-only unchanged. Cold backfill newest-first at full speed: 7 GiB in about 45 s (JSON, 2 cores) | parse-only speed |
| nightly perf thresholds | fail on a 20 % drop per corpus vs the CI baseline recorded by the first nightly run (the spike table is only the initial reference: CI runners differ from the spike host) | — |

**Gate arithmetic** (R6-P2, `TestLokiIncident` without a `level` label):
the design's corpus for that test is a dense incident hour written at
5 GiB/day (213 MiB in the hour) on top of a sparse 7-day background of at
most 8 GiB (8,192 MiB; the background is sparse, not 5 GiB/day). One
approved scan over the 7-day range at today's ≈ 1.9 MiB/s of lines for 2 cores
(≈ 0.95 MiB/s/core) takes about 72 min, over the 30-minute TTL. Finishing in
1,800 s needs 4.6 MiB/s, so ≥ 2.3 MiB/s/core for the whole pipeline, which
means the `secret` detector must reach roughly ≥ 5 MiB/s/core. A scan of only
the dense incident hour (213 MiB) takes about 2 min today. Until lockkit#97 (or a
follow-up) reaches that speed, LL-16b's variant must scan the narrowed
range, not 7 days.
