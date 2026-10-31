# Loki

## `detected_level` (Loki 3)

Loki 3 discovers log levels at ingestion by default (`discover_log_levels: true`, with
`allow_structured_metadata: true`). The distributor adds a **`detected_level`**
structured-metadata field to each entry that does not already carry one, as follows (Loki 3.5,
`pkg/distributor/field_detection.go`, `extractLogLevel`):

- the value of a level stream label, if the stream has one (`level`, `LEVEL`, `Level`,
  `log.level`, `severity`, `lvl`, `severity_text` and their case variants, or the configured
  `log_level_fields`). The value is copied as is, not normalised. So `detected_level` is added
  **even when a `level` label exists**, with that label's value;
- otherwise the value of such a field in the structured metadata, copied as is;
- otherwise a level derived from the line: the OTLP severity number, a level field of a JSON
  or logfmt line, or a level word in the text. These are normalised to one of `trace`, `debug`,
  `info`, `warn`, `error`, `critical`, `fatal` or `unknown` (`pkg/util/constants/levels.go`).

`locklog setup` proposes `level` and `detected_level` among the default trusted fields, and the
human reviews them. Once trusted, `detected_level` is selectable with `=`/`!=`/`in`. It is matched
**locally**, on the metadata Loki returns apart from the stream labels, and is never sent to Loki
as a filter: a LogQL `| detected_level="error"` filter would also match a stream label of that
name, which anyone who writes to Loki can add. Selector-only questions on a trusted stream label
("how many errors per minute in `checkout`", with a `level` label) are answered with
server-side metric counts under the rolling budget. Counts on `detected_level` scan.

Limits:

- When it comes from the line, `detected_level` is a guess from content. A line Loki cannot
  classify is `unknown`, and a multi-line event is classified entry by entry. When it comes
  from a label or a metadata field, it holds that value as written (`WARNING`, `E`, ...).
- Loki adds it only at ingestion, while discovery is on. Data ingested before Loki 3, with
  `discover_log_levels: false`, or with `allow_structured_metadata: false`, has no
  `detected_level`.
- When neither `level` nor `detected_level` is available, "find the errors" needs a scan of the
  text, which is matched locally after masking. That scan is an **approved scan**: it runs under
  its plan, with the request rate and in-flight cap from the S3 numbers. It is not limited by
  the rolling per-minute budget, so expect one approval and completion within the 30-minute
  ticket TTL, not an answer in seconds.
