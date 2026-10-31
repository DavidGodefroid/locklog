package parse

import (
	"strings"
	"testing"
	"time"
)

func fieldStr(t *testing.T, ev Event, key string) string {
	t.Helper()
	v, ok := Get(ev.Fields, key)
	if !ok {
		return "<none>"
	}
	return v.Str
}

func fieldsOf(t *testing.T, ev Event, keys ...string) string {
	t.Helper()
	var b []string
	for _, k := range keys {
		b = append(b, k+"="+fieldStr(t, ev, k))
	}
	return strings.Join(b, " ")
}

func TestSyslog5424(t *testing.T) {
	p := mustParser(t, Options{Format: "syslog"})
	in := `<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog 1234 ID47 [exampleSDID@32473 iut="3" eventSource="App\"x\]"][meta seq="1"] An application event` + "\n" +
		"<34>1 2003-10-11T22:14:15.003Z host su - - - \ufeff'su root' failed\n" +
		"<13>1 - - - - - -\n"
	evs := readAll(t, p, in)
	if len(evs) != 3 {
		t.Fatalf("%d events: %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Format != "syslog" || e.Fallback || e.Message != "An application event" || !e.HasTime || e.Time.Nanosecond() != 3e6 {
		t.Fatalf("%+v", e)
	}
	if got := fieldsOf(t, e, "facility", "level", "host", "app", "pid", "msgid"); got != "facility=local4 level=notice host=mymachine.example.com app=evntslog pid=1234 msgid=ID47" {
		t.Fatal(got)
	}
	sdv, _ := Get(e.Fields, "sd")
	sd, ok := Get(sdv.Members, "exampleSDID@32473")
	if !ok || sd.Kind != KindObject || len(sd.Members) != 2 || sd.Members[1].Value.Str != `App"x]` {
		t.Fatalf("structured data %+v", e.Fields)
	}
	if _, ok := Get(sdv.Members, "meta"); !ok {
		t.Fatalf("second SD element lost: %+v", e.Fields)
	}
	if e := evs[1]; e.Message != "'su root' failed" || fieldStr(t, e, "level") != "critical" || fieldStr(t, e, "facility") != "auth" || fieldStr(t, e, "pid") != "<none>" {
		t.Fatalf("%+v", e)
	}
	if e := evs[2]; e.Format != "syslog" || e.HasTime || e.Message != "" || fieldStr(t, e, "host") != "<none>" {
		t.Fatalf("%+v", e)
	}
	checkCoverage(t, in, evs)
}

func TestSyslog3164(t *testing.T) {
	defer func(f func() time.Time) { syslogNow = f }(syslogNow)
	syslogNow = func() time.Time { return time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC) }
	p := mustParser(t, Options{Format: "syslog"})
	cases := []struct {
		in, msg, fields string
		at              time.Time
	}{
		{"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8", "'su root' failed for lonvick on /dev/pts/8",
			"facility=auth level=critical host=mymachine app=su pid=<none>", time.Date(2025, 10, 11, 22, 14, 15, 0, time.UTC)},
		{"Jan  2 09:59:00 web nginx[811]: started", "started", "facility=<none> level=<none> host=web app=nginx pid=811", time.Date(2026, 1, 2, 9, 59, 0, 0, time.UTC)},
		// Tomorrow is still this year; two days ahead is last year.
		{"Jan  3 08:00:00 web cron[1]: x", "x", "facility=<none> level=<none> host=web app=cron pid=1", time.Date(2026, 1, 3, 8, 0, 0, 0, time.UTC)},
		{"Jan  4 08:00:00 web cron[1]: x", "x", "facility=<none> level=<none> host=web app=cron pid=1", time.Date(2025, 1, 4, 8, 0, 0, 0, time.UTC)},
		{"<34>Oct 11 22:14:15 host message without a tag", "message without a tag", "facility=auth level=critical host=host app=<none> pid=<none>", time.Date(2025, 10, 11, 22, 14, 15, 0, time.UTC)},
		{"<189>Oct 11 22:14:15 router %SYS-5-CONFIG_I: Configured", "%SYS-5-CONFIG_I: Configured", "facility=local7 level=notice host=router app=<none> pid=<none>", time.Date(2025, 10, 11, 22, 14, 15, 0, time.UTC)},
		{"<14>2026-01-02T09:00:00Z web app: pri makes it syslog", "pri makes it syslog", "facility=user level=info host=web app=app pid=<none>", time.Date(2026, 1, 2, 9, 0, 0, 0, time.UTC)},
		{"2026-01-02T09:00:00.123456+01:00 web systemd[1]: Started x.service.", "Started x.service.", "facility=<none> level=<none> host=web app=systemd pid=1", time.Date(2026, 1, 2, 8, 0, 0, 123456000, time.UTC)},
		{"<14>Dec 31 23:59:59 host kernel: [ 1.0] usb 1-1: new device", "[ 1.0] usb 1-1: new device", "facility=user level=info host=host app=kernel pid=<none>", time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)},
		// A Feb 29 lands in the last leap year that is not in the future.
		{"Feb 29 12:00:00 h app: leap", "leap", "facility=<none> level=<none> host=h app=app pid=<none>", time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		evs := readAll(t, p, c.in+"\n")
		if len(evs) != 1 {
			t.Fatalf("%q: %d events", c.in, len(evs))
		}
		e := evs[0]
		if e.Format != "syslog" || e.Fallback || e.Message != c.msg || !e.Time.Equal(c.at) {
			t.Errorf("%q: %+v", c.in, e)
		}
		if got := fieldsOf(t, e, "facility", "level", "host", "app", "pid"); got != c.fields {
			t.Errorf("%q: %s", c.in, got)
		}
	}
}

func TestSyslog3164Location(t *testing.T) {
	defer func(f func() time.Time) { syslogNow = f }(syslogNow)
	syslogNow = func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }
	loc := time.FixedZone("CEST", 2*3600)
	p := mustParser(t, Options{Format: "syslog", Location: loc})
	e := readAll(t, p, "May 31 12:00:00 h app: x\n")[0]
	if !e.Time.Equal(time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)) {
		t.Fatal(e.Time)
	}
}

func TestSyslogRejects(t *testing.T) {
	for _, in := range []string{
		"Oct 11 22:14:15 just a date and words",
		"<192>Oct 11 22:14:15 host app: pri too large",
		"<034>Oct 11 22:14:15 host app: leading zero",
		"<165>1 2003-13-11T22:14:15Z host app - - - bad month",
		"<165>1 2003-10-11T22:14:15Z host app - - [unterminated x=\"1\"",
		"<165>1 2003-10-11T22:14:15Z host app - - [id x=1] unquoted",
		"2026-01-02 09:00:00 host app: space-separated date",
	} {
		if (syslogFormat{}).Detect(in) {
			if _, ok := (syslogFormat{}).Decode(in, nil); ok && !strings.HasPrefix(in, "Oct 11 22:14:15 just") {
				t.Errorf("syslog accepts %q", in)
			}
		}
		if !strings.HasPrefix(in, "<1") {
			continue
		}
		p := mustParser(t, Options{Format: "syslog"})
		if e := readAll(t, p, in+"\n")[0]; e.Format != "plain" || !e.Fallback {
			t.Errorf("%q: %+v", in, e)
		}
	}
	if (syslogFormat{}).Detect("Oct 11 22:14:15 just a date and words") {
		t.Error("a date followed by prose is syslog")
	}
}

func TestCombined(t *testing.T) {
	p := mustParser(t, Options{Format: "combined"})
	in := `203.0.113.7 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif?q=\"x\" HTTP/1.0" 200 2326 "http://ref.example/" "Mozilla/5.0 (X11)"` + "\n" +
		`10.0.0.1 - - [31/Oct/2026:02:41:55 +0100] "POST /login HTTP/2.0" 502 - "-" "curl/8.0" 0.013 "upstream"` + "\n" +
		`::1 - - [31/Oct/2026:02:41:55 +0000] "\x16\x03\x01" 400 157` + "\n"
	evs := readAll(t, p, in)
	if len(evs) != 3 {
		t.Fatalf("%d %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Format != "combined" || e.Message != `GET /a.gif?q="x" HTTP/1.0` || !e.Time.Equal(time.Date(2000, 10, 10, 20, 55, 36, 0, time.UTC)) {
		t.Fatalf("%+v", e)
	}
	if got := fieldsOf(t, e, "remote_addr", "ident", "remote_user", "method", "protocol", "status", "status_class", "bytes", "referer", "user_agent"); got !=
		"remote_addr=203.0.113.7 ident=<none> remote_user=frank method=GET protocol=HTTP/1.0 status=200 status_class=2xx bytes=2326 referer=http://ref.example/ user_agent=Mozilla/5.0 (X11)" {
		t.Fatal(got)
	}
	if v, _ := Get(e.Fields, "status"); v.Kind != KindNumber {
		t.Fatalf("status kind %v", v.Kind)
	}
	e = evs[1]
	if e.Message != `POST /login HTTP/2.0 0.013 "upstream"` || fieldStr(t, e, "status_class") != "5xx" || fieldStr(t, e, "bytes") != "<none>" || fieldStr(t, e, "referer") != "<none>" {
		t.Fatalf("%+v", e)
	}
	e = evs[2]
	if e.Message != `\x16\x03\x01` || fieldStr(t, e, "method") != "<none>" || fieldStr(t, e, "user_agent") != "<none>" {
		t.Fatalf("%+v", e)
	}
	checkCoverage(t, in, evs)
}

func TestCRIFrames(t *testing.T) {
	p := mustParser(t, Options{Format: "cri"})
	in := "2026-10-31T02:41:55.123456789Z stderr P {\"level\":\"error\",\n" +
		"2026-10-31T02:41:55.2Z stderr F \"msg\":\"boom\"}\n" +
		"2026-10-31T02:41:56Z stdout F:x plain text\n" +
		"2026-10-31T02:41:57Z stdout F\n" +
		"not a frame\n"
	evs := readAll(t, p, in)
	// The empty payload is a blank line, which makes no event.
	if len(evs) != 3 {
		t.Fatalf("%d %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Format != "json" || e.Message != "boom" || e.Time.Nanosecond() != 123456789 || fieldStr(t, e, "level") != "error" {
		t.Fatalf("%+v", e)
	}
	if v, ok := Get(e.Attrs, "stream"); !ok || v.Str != "stderr" {
		t.Fatalf("attrs %+v", e.Attrs)
	}
	if e := evs[1]; e.Format != "plain" || e.Message != "plain text" || e.Time.Second() != 56 {
		t.Fatalf("%+v", e)
	}
	if e := evs[2]; e.Attrs != nil || e.Message != "not a frame" {
		t.Fatalf("%+v", e)
	}
	checkCoverageGaps(t, in, evs, false) // the empty frame makes no event
	for _, bad := range []string{"2026-10-31T02:41:55Z stdin F x", "2026-10-31T02:41:55Z stdout X x", "yesterday stdout F x", "2026-10-31T02:41:55Z stdout"} {
		if _, ok := (criFormat{}).Unwrap(bad, nil); ok {
			t.Errorf("cri unwraps %q", bad)
		}
	}
}

func TestDockerJSONFrames(t *testing.T) {
	p := mustParser(t, Options{Format: "docker-json"})
	in := `{"log":"level=warn msg=\"disk ","stream":"stdout","time":"2026-10-31T02:41:55.1Z"}` + "\n" +
		`{"log":"low\" free=3%\r\n","stream":"stdout","attrs":{"tag":"api"},"time":"2026-10-31T02:41:55.2Z"}` + "\n" +
		`{"log":"second\n","stream":"stderr","time":"2026-10-31T02:41:56Z"}` + "\n" +
		`{"stream":"stderr"}` + "\n"
	evs := readAll(t, p, in)
	if len(evs) != 3 {
		t.Fatalf("%d %+v", len(evs), evs)
	}
	e := evs[0]
	if e.Format != "logfmt" || e.Message != "disk low" || fieldStr(t, e, "free") != "3%" || e.Time.Nanosecond() != 1e8 {
		t.Fatalf("%+v", e)
	}
	if v, ok := Get(e.Attrs, "stream"); !ok || v.Str != "stdout" {
		t.Fatalf("attrs %+v", e.Attrs)
	}
	if e := evs[1]; e.Message != "second" || e.Format != "plain" {
		t.Fatalf("%+v", e)
	}
	if v, ok := Get(evs[1].Attrs, "stream"); !ok || v.Str != "stderr" {
		t.Fatalf("attrs %+v", evs[1].Attrs)
	}
	if e := evs[2]; e.Attrs != nil || e.Raw != `{"stream":"stderr"}` {
		t.Fatalf("%+v", e)
	}
	checkCoverage(t, in, evs)
	fr, ok := (dockerJSONFormat{}).Unwrap(`{"log":"x\n","attrs":{"tag":"api","env":"prod"}}`, nil)
	if a, _ := Get(fr.Attrs, "attrs"); !ok || a.Kind != KindObject || len(a.Members) != 2 {
		t.Fatalf("%+v", fr)
	}
}

// TestAutoDetectsNewFormats checks the priority of "auto": the new formats
// are tried after json and logfmt, and none takes another's lines.
func TestAutoDetectsNewFormats(t *testing.T) {
	p := mustParser(t, Options{})
	for in, want := range map[string]string{
		`{"msg":"x"}`:      "json",
		"level=info msg=x": "logfmt",
		`1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 1 "-" "-"`: "combined",
		"<34>Oct 11 22:14:15 host su: failed":                                     "syslog",
		"Oct 11 22:14:15 host sshd[1]: ok":                                        "syslog",
		"<165>1 2003-10-11T22:14:15Z h a - - - m":                                 "syslog",
		"Oct 11 22:14:15 started the server":                                      "plain",
		"2026-10-31T02:41:55Z stdout F x":                                         "plain",
		"GET / HTTP/1.1 200":                                                      "plain",
	} {
		if e := readAll(t, p, in+"\n")[0]; e.Format != want {
			t.Errorf("auto(%q) = %s, want %s", in, e.Format, want)
		}
	}
}

func TestFramesSplitByStream(t *testing.T) {
	for name, in := range map[string]string{
		"cri": "2026-10-31T02:41:55Z stdout P hello \n2026-10-31T02:41:55Z stderr F ERR boom\n2026-10-31T02:41:56Z stdout F world\n",
		"docker-json": `{"log":"hello ","stream":"stdout"}` + "\n" + `{"log":"ERR boom\n","stream":"stderr"}` + "\n" +
			`{"log":"world\n","stream":"stdout"}` + "\n",
	} {
		p := mustParser(t, Options{Format: name})
		evs := readAll(t, p, in)
		if len(evs) != 3 {
			t.Fatalf("%s: %d events %+v", name, len(evs), evs)
		}
		for i, want := range []string{"hello stdout", "ERR boom stderr", "world stdout"} {
			s, _ := Get(evs[i].Attrs, "stream")
			if got := strings.TrimSpace(evs[i].Message) + " " + s.Str; got != want {
				t.Errorf("%s event %d: %q, want %q", name, i, got, want)
			}
		}
		checkCoverage(t, in, evs)
	}
}

func TestDockerJSONStreamVocabulary(t *testing.T) {
	fr, ok := (dockerJSONFormat{}).Unwrap(`{"log":"x\n","stream":"secret-value"}`, nil)
	if _, has := Get(fr.Attrs, "stream"); !ok || has {
		t.Fatalf("%+v", fr)
	}
}

func TestCombinedBytesNumber(t *testing.T) {
	e, ok := (combinedFormat{}).Decode(`1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 0042`, nil)
	if v, _ := Get(e.Fields, "bytes"); !ok || v.Kind != KindNumber || v.Str != "42" {
		t.Fatalf("%+v", e.Fields)
	}
}

func TestAutoKeepsTimestampedStackTraces(t *testing.T) {
	in := "2026-10-31T02:41:55Z Unhandled exception: java.lang.NullPointerException\n\tat Foo.bar(Foo.java:1)\n\tat Main.main(Main.java:2)\n"
	evs := readAll(t, mustParser(t, Options{}), in)
	if len(evs) != 1 || evs[0].Format != "plain" || evs[0].Lines != 3 {
		t.Fatalf("%+v", evs)
	}
}
