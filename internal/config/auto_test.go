package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func autoOf(t *testing.T, keys string) AutoRules {
	t.Helper()
	return mustParse(t, fileSrc+keys)["staging"].AutoRules()
}

func TestAutoRulesDefaults(t *testing.T) {
	p := mustParse(t, fileSrc)["staging"]
	if p.Auto != nil {
		t.Fatalf("a profile without auto stores %+v", p.Auto)
	}
	if r := p.AutoRules(); r != DefaultAutoRules || r.Preset() != PresetDefault {
		t.Fatalf("defaults %+v", r)
	}
	if got := DefaultAutoRules.String(); got != "read ask · unmask ask · lookup ask (default)" {
		t.Errorf("String() = %q", got)
	}
}

func TestAutoRulesPresetsAndOverrides(t *testing.T) {
	for _, tt := range []struct {
		name, keys string
		want       AutoRules
		preset     string
	}{
		{"full-auto", "[profiles.staging]\nauto = \"full-auto\"\n", FullAutoRules, PresetFullAuto},
		{"default", "[profiles.staging]\nauto = \"default\"\n", DefaultAutoRules, PresetDefault},
		{"table", "[profiles.staging.auto]\nread = \"auto\"\nunmask = \"deny\"\n",
			AutoRules{Read: AutoAuto, Unmask: AutoDeny, Lookup: AutoAsk}, ""},
		{"preset overridden", "[profiles.staging.auto]\npreset = \"full-auto\"\nunmask = \"ask\"\n",
			AutoRules{Read: AutoAuto, Unmask: AutoAsk, Lookup: AutoAuto}, ""},
		{"defaults spelled out", "[profiles.staging.auto]\nread = \"ask\"\nunmask = \"ask\"\nlookup = \"ask\"\n", DefaultAutoRules, PresetDefault},
		{"empty table", "[profiles.staging.auto]\n", DefaultAutoRules, PresetDefault},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := autoOf(t, tt.keys)
			if r != tt.want || r.Preset() != tt.preset {
				t.Fatalf("rules %+v (preset %q), want %+v (%q)", r, r.Preset(), tt.want, tt.preset)
			}
		})
	}
	// A profile stores only what differs from the defaults.
	p := mustParse(t, fileSrc+"[profiles.staging.auto]\nread = \"ask\"\nlookup = \"deny\"\n")["staging"]
	if p.Auto == nil || *p.Auto != (AutoRules{Lookup: AutoDeny}) {
		t.Fatalf("stored %+v", p.Auto)
	}
	if p := mustParse(t, fileSrc+"[profiles.staging]\nauto = \"default\"\n")["staging"]; p.Auto != nil {
		t.Fatalf("the default preset stores %+v", p.Auto)
	}
}

// Every action × value: Get, RuleText and the map lox run reads.
func TestAutoRulesEveryActionAndValue(t *testing.T) {
	for _, a := range AutoActions {
		for _, v := range []AutoValue{AutoAuto, AutoAsk, AutoDeny} {
			r := autoOf(t, "[profiles.staging.auto]\n"+string(a)+" = \""+string(v)+"\"\n")
			if r.Get(a) != v {
				t.Errorf("%s = %s: Get %s", a, v, r.Get(a))
			}
			if got, want := r.RuleText(a), "auto."+string(a)+" = "+string(v); got != want {
				t.Errorf("RuleText %q, want %q", got, want)
			}
			if r.Map()[string(a)] != v || len(r.Map()) != len(AutoActions) {
				t.Errorf("Map %v", r.Map())
			}
			for _, o := range AutoActions {
				if o != a && r.Get(o) != DefaultAutoRules.Get(o) {
					t.Errorf("%s = %s changed %s to %s", a, v, o, r.Get(o))
				}
			}
		}
	}
	// Fail closed: an unknown action or a stored value that is none.
	if v := (AutoRules{}).Get("connect"); v != AutoDeny {
		t.Errorf("unknown action: %s", v)
	}
	if v := (AutoRules{Read: "maybe"}).Get(ActionRead); v != AutoDeny {
		t.Errorf("unknown value: %s", v)
	}
}

// Refusals name the profile and the key, never the value.
func TestAutoRulesRefused(t *testing.T) {
	const val = "s3cr3t-looking-value"
	for _, tt := range []struct{ name, keys, want string }{
		{"unknown preset", "[profiles.staging]\nauto = \"" + val + "\"\n", "auto: unknown preset"},
		{"empty preset", "[profiles.staging]\nauto = \"\"\n", "auto: unknown preset"},
		{"unknown value", "[profiles.staging.auto]\nread = \"" + val + "\"\n", "auto.read: want auto, ask or deny"},
		{"unknown key", "[profiles.staging.auto]\nconnect = \"ask\"\n", `auto: unknown key "connect" (want preset, read, unmask, lookup)`},
		{"escaped key", "[profiles.staging.auto]\n\"a\\u001bb\" = \"ask\"\n", `auto: unknown key "a?b"`},
		{"not a string", "[profiles.staging.auto]\nunmask = true\n", "auto.unmask: want auto, ask or deny"},
		{"number", "[profiles.staging]\nauto = 3\n", "auto: want a preset"},
		{"preset not a string", "[profiles.staging.auto]\npreset = 1\n", "auto.preset: want"},
		{"unknown table preset", "[profiles.staging.auto]\npreset = \"" + val + "\"\n", "auto: unknown preset"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse(t, fileSrc+tt.keys)
			if err == nil {
				t.Fatal("accepted")
			}
			msg := err.Error()
			if !strings.Contains(msg, tt.want) || !strings.Contains(msg, `profile "staging"`) {
				t.Errorf("error %q, want %q and the profile", msg, tt.want)
			}
			if strings.Contains(msg, val) || strings.Contains(msg, "\x1b") {
				t.Errorf("the value is quoted: %q", msg)
			}
		})
	}
}

// Rules spelled as the defaults, or left out, are the same policy: a
// policy approved before auto rules existed keeps its fingerprint, and
// the policy's JSON has no auto key.
func TestAutoRulesFingerprintStable(t *testing.T) {
	none := policyOf(t, "", "")
	raw, err := json.Marshal(Canonical(none))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"auto":`) {
		t.Fatalf("a policy without rules has an auto key: %s", raw)
	}
	for _, keys := range []string{
		"[profiles.pp]\nauto = \"default\"\n",
		"[profiles.pp.auto]\nread = \"ask\"\nunmask = \"ask\"\nlookup = \"ask\"\n",
		"[profiles.pp.auto]\n",
	} {
		p := policyOf(t, keys, "")
		if p.Fingerprint() != none.Fingerprint() || len(p.Diff(none)) != 0 {
			t.Errorf("%q: another policy (%+v)", keys, p.Diff(none))
		}
	}
	// A stored value equal to its default is left out by Canonical too.
	spelled := none
	spelled.Profile.Auto = &AutoRules{Read: AutoAsk}
	if spelled.Fingerprint() != none.Fingerprint() {
		t.Error("a default spelled in the stored rules changes the fingerprint")
	}
	if p := policyOf(t, "[profiles.pp.auto]\nread = \"auto\"\n", ""); p.Fingerprint() == none.Fingerprint() {
		t.Error("read = auto keeps the fingerprint")
	}
}

// Moving a rule toward auto loosens; toward deny tightens.
func TestAutoRulesDiff(t *testing.T) {
	for _, tt := range []struct {
		name, from, to, field string
		loosens               bool
	}{
		{"ask to auto", "", "read = \"auto\"", "auto.read", true},
		{"deny to ask", "unmask = \"deny\"", "", "auto.unmask", true},
		{"deny to auto", "lookup = \"deny\"", "lookup = \"auto\"", "auto.lookup", true},
		{"ask to deny", "", "lookup = \"deny\"", "auto.lookup", false},
		{"auto to ask", "unmask = \"auto\"", "", "auto.unmask", false},
		{"auto to deny", "read = \"auto\"", "read = \"deny\"", "auto.read", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := policyOf(t, "[profiles.pp.auto]\n"+tt.from+"\n", "")
			c := policyOf(t, "[profiles.pp.auto]\n"+tt.to+"\n", "")
			d := c.Diff(a)
			if len(d) != 1 {
				t.Fatalf("changes %+v", d)
			}
			assertChange(t, d, tt.field, tt.loosens)
		})
	}
	// full-auto from the defaults: three loosenings.
	full := policyOf(t, "[profiles.pp]\nauto = \"full-auto\"\n", "")
	d := full.Diff(policyOf(t, "", ""))
	if len(d) != 3 {
		t.Fatalf("full-auto: %+v", d)
	}
	for _, ch := range d {
		if !ch.Loosens || ch.Old != "ask" || ch.New != "auto" {
			t.Errorf("full-auto change %+v", ch)
		}
	}
}

func TestAutoRulesDescribed(t *testing.T) {
	p := policyOf(t, "[profiles.pp.auto]\nread = \"auto\"\nlookup = \"deny\"\n", "")
	if !strings.Contains(strings.Join(p.Describe(), "\n"), "auto mode (lox run): read auto · unmask ask · lookup deny") {
		t.Errorf("Describe:\n%s", strings.Join(p.Describe(), "\n"))
	}
}
