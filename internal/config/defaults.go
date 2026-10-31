package config

import (
	"time"

	"github.com/DavidGodefroid/lockkit/pii"
)

// Structured modes: how the leaves of structured records (JSON, logfmt,
// journald, syslog structured data) are masked.
const (
	// StructuredRedactUnknown redacts every leaf that is neither trusted
	// nor named by an allow rule (the production default).
	StructuredRedactUnknown = "redact-unknown"
	// StructuredDetect masks what rules, names and detectors find.
	StructuredDetect = "detect"
)

// Text modes: how free text is masked.
const (
	// TextDetect masks what the detectors find (the default).
	TextDetect = "detect"
	// TextTemplate also replaces every variable token of a clustered
	// template.
	TextTemplate = "template"
)

// Unmask modes: whether the agent may ask a human to unmask a value.
const (
	UnmaskNever    = "never"
	UnmaskApproved = "approved"
)

// Lookup modes: whether locklog_lookup is free (rate-limited) or a
// ticket the human approves.
const (
	LookupFree     = "free"
	LookupApproved = "approved"
)

// Pseudonym rotation keywords; any other value is a duration.
const (
	RotationSession = "session"
	RotationNever   = "never"
)

// Hard ceilings of the per-call budgets: no profile can go past them.
const (
	RangeCeiling    = 400 * Day
	BytesCeiling    = 64 * GiB
	RecordsCeiling  = 1000
	OutputCeiling   = 1 * MiB
	PIIRulesCeiling = 500
	// Rolling budgets: ceilings no profile can go past either.
	BytesPerHourCeiling = 1 * TiB
	RateCeiling         = 6000
	LookupsCeiling      = 1000
	PIIAddsCeiling      = 100
	DefaultRotation     = 7 * Day
	DefaultMaxAge       = 30 * Day
	MinRotation         = time.Hour
	MaxPseudonymAge     = 400 * Day
	DefaultMaxSession   = 12 * time.Hour
	DefaultIdle         = time.Hour
	MinIdleTimeout      = time.Minute
	MaxMaxSession       = 7 * Day
)

// Budgets are the per-call and rolling budgets of one kind of source
// (local: files, journald, containers; remote: Loki and the like).
type Budgets struct {
	// Range is the widest time range of a call with text, regex or
	// masked-field predicates.
	Range time.Duration `json:"range"`
	// CountRange is the widest range of a count on trusted fields only,
	// served from the local index or server-side metric queries.
	CountRange time.Duration `json:"count_range"`
	// MaxBytes is the most bytes one call processes (remote: fetches).
	MaxBytes int64 `json:"max_bytes"`
	// BytesPerHour is the rolling budget of bytes processed per hour.
	BytesPerHour int64 `json:"bytes_per_hour"`
	// MetricQueriesPerHour and RequestsPerMinute bound the load put on a
	// remote backend (remote only; 0 for local).
	MetricQueriesPerHour int `json:"metric_queries_per_hour,omitempty"`
	RequestsPerMinute    int `json:"requests_per_minute,omitempty"`
}

// Limits bound what the agent's free calls can cost and return.
type Limits struct {
	Local  Budgets `json:"local"`
	Remote Budgets `json:"remote"`
	// MaxRecords and MaxOutputBytes cap one call's output.
	MaxRecords     int   `json:"max_records"`
	MaxOutputBytes int64 `json:"max_output_bytes"`
	// LookupsPerHour caps the distinct values locklog_lookup resolves per
	// hour for the whole console, LookupsPerHourPerUID per peer uid.
	LookupsPerHour       int `json:"lookups_per_hour"`
	LookupsPerHourPerUID int `json:"lookups_per_hour_per_uid"`
	// PIIAddsPerHour and PIIRulesMax cap the agent's own masking rules.
	PIIAddsPerHour int `json:"pii_adds_per_hour"`
	PIIRulesMax    int `json:"pii_rules_max"`
}

// DefaultLimits returns the limits of a profile that sets none.
func DefaultLimits(production bool) Limits {
	l := Limits{
		// Per-call admission: 512 MiB (docs/performance.md, spikes S3/S4).
		// Masking runs at about 1 MB/s/core, so the 30 s deadline stops a
		// call long before and it continues free with its cursor. Remote
		// bytes are decompressed response bytes.
		Local: Budgets{Range: 7 * Day, CountRange: 30 * Day, MaxBytes: 512 * MiB, BytesPerHour: 40 * GiB},
		Remote: Budgets{Range: 24 * time.Hour, CountRange: 30 * Day, MaxBytes: 512 * MiB, BytesPerHour: 20 * GiB,
			MetricQueriesPerHour: 120, RequestsPerMinute: 600},
		MaxRecords:           200,
		MaxOutputBytes:       64 * KiB,
		LookupsPerHour:       50,
		LookupsPerHourPerUID: 20,
		PIIAddsPerHour:       10,
		PIIRulesMax:          50,
	}
	if production {
		l.Remote.BytesPerHour = 10 * GiB
		l.Remote.MetricQueriesPerHour = 60
		// 240/min still fetches about 2.7 MB/s of log lines, above masking
		// speed; 60/min would throttle below it.
		l.Remote.RequestsPerMinute = 240
		l.LookupsPerHour = 10
	}
	return l
}

// DefaultDetectors is the detector set of a profile that sets none: every
// lockkit value detector but the opt-in ones. Secret detection is not a
// detector setting: it is always on.
func DefaultDetectors() []string {
	ds := pii.AllDetectors()
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Name()
	}
	return out
}

// DefaultStructured is redact-unknown on production, detect elsewhere.
func DefaultStructured(production bool) string {
	if production {
		return StructuredRedactUnknown
	}
	return StructuredDetect
}

// DefaultUnmask is never on production, approved elsewhere.
func DefaultUnmask(production bool) string {
	if production {
		return UnmaskNever
	}
	return UnmaskApproved
}
