# Loki

## `detected_level` (Loki 3)

Loki 3 discovers log levels by default (`discover_log_levels: true`): when a stream has no
`level` label, Loki adds a **`detected_level`** structured-metadata field to each line, derived
from the line itself (a `level` field, or a level word). Its values are enumerated (`debug`,
`info`, `warn`, `error`, `critical`, `trace`, `unknown`).

`locklog setup` proposes `level` and `detected_level` among the default trusted fields, and the
human reviews them. Once trusted, `detected_level` is selectable with `=`/`!=`/`in`. It is sent to
Loki as a structured-metadata filter (`| detected_level="error"`) after the stream selector.
Selector-only questions ("how many errors per minute in `checkout`") are then answered with
server-side metric counts under the rolling budget.

Limits:

- `detected_level` is a guess from content. A line Loki cannot classify is `unknown`, and a
  multi-line event is classified line by line.
- Loki adds it only at ingestion, while discovery is on. Data ingested before Loki 3, or with
  `discover_log_levels: false`, has no `detected_level`.
- When neither `level` nor `detected_level` is available, "find the errors" needs a scan of the
  text, which is matched locally after masking. That scan is an **approved scan**: it runs under
  its plan, with the request rate and in-flight cap from the S3 numbers. It is not limited by
  the rolling per-minute budget, so expect one approval and completion within the 30-minute
  ticket TTL, not an answer in seconds.
