#!/usr/bin/env python3
"""Generate site/assets/demo.svg: locklog's value in one looping image.

Claude Code (left) investigates PDF errors on a staging profile. locklog_count shows the step at
14:02, locklog_patterns the new pattern (the email and the IP already pseudonymised), and
locklog_trace the order behind it: all free, all masked. The agent then asks locklog_unmask for
the email. The locklog console (right, its own account and container) shows the read-pii approval
screen: the masked record with the exact span marked » «, the agent's reason and what revealing it
lets the agent do. The human answers "n". The agent gets "denied by the human" and carries on
without the address. The console's audit (bottom) keeps every call, with no clear value. Pure SVG + CSS keyframes, so it plays on
GitHub, on the site and in any browser; every animation shares one clock of LOOP seconds, and
prefers-reduced-motion shows the final frame.

The tool names, the pseudonym format and the refusal text follow the code (the approval screen is a simplified rendering of the console's); the demo test
(scripts/brand/check_demo.py) checks the committed SVG is this script's output and that its
strings stay in step. The demo profile is labelled staging: unmask is off by default on
production.

    python3 scripts/brand/demo.py > site/assets/demo.svg
"""

LOOP = 16.0
C = dict(bg="#0b1120", pane="#020617", bar="#0f172a", border="#253047", text="#e2e8f0",
         dim="#64748b", sub="#94a3b8", green="#4ade80", teal="#5eead4", violet="#a78bfa",
         red="#f87171", yellow="#facc15", accent="#38bdf8", amber="#fbbf24")
FONT = "'JetBrains Mono','SF Mono',Menlo,Consolas,'DejaVu Sans Mono',monospace"
SANS = "Inter,-apple-system,'Segoe UI',system-ui,Helvetica,Arial,'DejaVu Sans',sans-serif"

# The values the demo shows. A pseudonym is ⟦kind:ID⟧ with a 12-character Crockford base32 ID.
EMAIL = "⟦email:7F3KQ2M9ZD4X⟧"
IP = "⟦ip:K2M9ZDQ81RTA⟧"

css, body = [], []
n = 0


def p(t):
    return f"{t / LOOP * 100:.2f}%"


def anim(frames):
    """Register keyframes [(time_s, 'css decls'), ...] and return a class name."""
    global n
    n += 1
    name = f"k{n}"
    rules = " ".join(f"{p(t)}{{{d}}}" for t, d in frames)
    css.append(f"@keyframes {name}{{{rules}}}")
    css.append(f".{name}{{animation:{name} {LOOP}s linear infinite}}")
    return name


END = LOOP - 0.6


def show(t_in, t_out=END, fade=0.2):
    """Opacity window: hidden, visible from t_in to t_out."""
    return anim([(0, "opacity:0"), (t_in, "opacity:0"), (t_in + fade, "opacity:1"),
                 (t_out, "opacity:1"), (t_out + fade, "opacity:0"), (LOOP, "opacity:0")])


def move(t0, t1, x0, y0, x1, y1):
    return anim([(0, f"transform:translate({x0}px,{y0}px);opacity:0"),
                 (t0, f"transform:translate({x0}px,{y0}px);opacity:0"),
                 (t0 + 0.05, f"transform:translate({x0}px,{y0}px);opacity:1"),
                 (t1, f"transform:translate({x1}px,{y1}px);opacity:1"),
                 (t1 + 0.15, f"transform:translate({x1}px,{y1}px);opacity:0"),
                 (LOOP, f"transform:translate({x1}px,{y1}px);opacity:0")])


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def text(x, y, s, cls="", size=11.5, col=C["text"], weight=400, family=FONT, anchor="start"):
    c = f' class="{cls}"' if cls else ""
    return (f'<text x="{x:.1f}" y="{y}"{c} font-family="{family}" font-size="{size}" '
            f'fill="{col}" font-weight="{weight}" text-anchor="{anchor}" xml:space="preserve">{esc(s)}</text>')


def spans(x, y, parts, cls="", size=11.5):
    """One line of coloured runs [(text, colour), ...]."""
    c = f' class="{cls}"' if cls else ""
    runs = "".join(f'<tspan fill="{col}">{esc(s)}</tspan>' for s, col in parts)
    return (f'<text x="{x}" y="{y}"{c} font-family="{FONT}" font-size="{size}" '
            f'xml:space="preserve">{runs}</text>')


def pane(x, y, w, h, title, account):
    body.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="12" fill="{C["pane"]}" '
                f'stroke="{C["border"]}" stroke-width="1.5"/>')
    body.append(f'<path d="M{x} {y + 12} a12 12 0 0 1 12 -12 h{w - 24} a12 12 0 0 1 12 12 v18 h-{w} z" '
                f'fill="{C["bar"]}"/>')
    for i, col in enumerate(("#f87171", "#facc15", "#4ade80")):
        body.append(f'<circle cx="{x + 18 + i * 16}" cy="{y + 15}" r="5" fill="{col}" fill-opacity=".7"/>')
    body.append(text(x + 70, y + 20, title, size=12, col=C["sub"], family=SANS, weight=600))
    body.append(text(x + w - 14, y + 20, account, size=12, col=C["dim"], family=SANS, anchor="end"))


def badge(xc, y, label, col, cls):
    w = len(label) * 7.6 + 16
    body.append(f'<g class="{cls}"><rect x="{xc - w / 2:.1f}" y="{y - 14}" width="{w:.1f}" height="20" '
                f'rx="5" fill="{col}"/>' + text(xc, y, label, size=11.5, col=C["pane"], weight=700,
                                                 family=FONT, anchor="middle") + "</g>")


W, H = 1200, 620
body.append(f'<rect width="{W}" height="{H}" rx="24" fill="{C["bg"]}"/>')
LH = 18
D, S, T, G, R, Y, V, TL = C["dim"], C["sub"], C["text"], C["green"], C["red"], C["yellow"], C["violet"], C["teal"]

# --- Agent pane (left) --------------------------------------------------------------------
AX, AY, AW, AH = 24, 24, 500, 408
pane(AX, AY, AW, AH, "✻ Claude Code", "its own container · profile staging")
ax, ay = AX + 16, AY + 52
agent = [
    (0.3, [("> ", D), ("when did the PDF errors start on staging?", T)]),
    (1.0, [("● ", G), ("locklog_count", T), ("(api, last 24h, by 1m, level=error)", S)]),
    (1.8, [("  └ ", D), ("0/min until 14:01 · ", S), ("67/min from 14:02", Y)]),
    (2.6, [("● ", G), ("locklog_patterns", T), ("(api, 13:50-14:20, baseline 1h)", S)]),
    (3.4, [("  └ ", D), ("new ×1,204: ", Y), ("render pdf for ", T), (EMAIL, TL)]),
    (3.4, [("    ", D), ("from ", T), (IP, TL), (" failed: upstream timed out", T)]),
    (4.2, [("● ", G), ("locklog_trace", T), ("(order_id 4812, 14:00-14:05)", S)]),
    (5.0, [("  └ ", D), ("14:02:11.180 nginx  GET /api/orders/4812/pdf 502", S)]),
    (5.0, [("    ", D), ("14:02:11.204 api    render pdf … upstream timed out", S)]),
    (5.8, [("● ", G), ("locklog_unmask", T), ("(ref Lr1.QW3H…, ", S), (EMAIL, TL), (")", S)]),
]
for i, (t, parts) in enumerate(agent):
    body.append(spans(ax, ay + i * LH, parts, cls=show(t)))
row = len(agent)
body.append(spans(ax, ay + row * LH, [("  └ ", D), ("Waiting for approval in the locklog console…", Y)],
                  cls=show(6.1, 11.4)))
reply = [
    (11.6, [("  └ ", D), ("Error: denied by the human; do not retry", T)]),
    (11.6, [("    ", D), ("unless asked", T)]),
    (12.4, [("● ", T), ("The PDF renderer's upstream has timed out since", T)]),
    (12.4, [("  ", T), ("14:02:11 (1,204 requests, order 4812 among them).", T)]),
    (12.4, [("  ", T), ("I can't see the customer's address: support can", T)]),
    (12.4, [("  ", T), ("reach them through order 4812.", T)]),
]
for i, (t, parts) in enumerate(reply):
    body.append(spans(ax, ay + (row + i) * LH, parts, cls=show(t)))

# --- Console pane (right) -----------------------------------------------------------------
CX, CY, CW, CH = 604, 24, 572, 408
pane(CX, CY, CW, CH, "locklog console", "account locklog · its own container")
cx, cy = CX + 16, CY + 52
CS = 11
CHW = CS * 0.602  # one character is 0.602 em wide
con = [
    [("$ ", D), ("locklog console", T)],
    [("✓ ", G), ("profile ", T), ("staging", Y), (" · sources api, nginx, system", T)],
    [("› ", C["accent"]), ("socket /run/locklog/<project>-staging.sock", T)],
]
for i, parts in enumerate(con):
    body.append(spans(cx, cy + i * LH, parts, size=CS))
# Free calls print nothing on the console: they go to the audit only.
screen = [
    [("╭─ ", V), ("STAGING", Y), (" · unmask · read-pii ", T), ("──────────────────────────────", V)],
    [("│ ", V), ("uid 10052 (agent) · reason ", D), ('"contact the customer"', T)],
    [("│ ", V), ("source: api · record: 2026-10-30T14:02:11.204Z", T)],
    [("│ ", V), ("reveal: ", T), (EMAIL, Y)],
    [("│ ", V), ("spans: 1 in this record (marked » «)", T)],
]
srow = 3
g = [f'<g class="{show(6.4)}">']
for i, parts in enumerate(screen):
    g.append(spans(cx, cy + (srow + i) * LH, parts, size=CS))
g.append("</g>")
body.append("".join(g))
# The record stays masked on the approval screen, with the asked span marked.
ry = cy + (srow + len(screen)) * LH
pre = "│   render pdf for »"
marked_rec = [("│   ", V), ("render pdf for ", T), ("»", C["amber"]), (EMAIL, Y), ("«", C["amber"]),
              (" from ", T), (IP, TL)]
body.append(f'<rect x="{cx + CHW * len(pre) - 2:.1f}" y="{ry - 12}" width="{CHW * len(EMAIL) + 4:.1f}" '
            f'height="16" rx="3" fill="{C["amber"]}" fill-opacity=".18" class="{show(6.4)}"/>')
body.append(spans(cx, ry, marked_rec, cls=show(6.4), size=CS))
body.append(spans(cx, ry + LH, [("│   ", V), ("failed: upstream timed out", T)], cls=show(6.4), size=CS))
tail = [
    [("│", V)],
    [("│ ", V), ("! the agent receives these clear values, once", Y)],
    [("│ ", V), ("! the agent can link this value to every record", Y)],
    [("│ ", V), ("  with this pseudonym (in this epoch)", Y)],
]
g = [f'<g class="{show(6.6)}">']
for i, parts in enumerate(tail):
    g.append(spans(cx, ry + (2 + i) * LH, parts, size=CS))
g.append("</g>")
body.append("".join(g))
py = ry + (2 + len(tail)) * LH
ask = "╰─ Approve? [y/N] "
body.append(spans(cx, py, [("╰─ ", V), ("Approve? [y/N] ", T)], cls=show(6.8), size=CS))
body.append(text(cx + CHW * len(ask), py, "n", cls=show(10.6, fade=0.03), size=CS, col=R, weight=700))
blink = anim([(0, "opacity:0"), (6.9, "opacity:0"), (6.91, "opacity:1"), (7.4, "opacity:1"),
              (7.41, "opacity:0"), (7.8, "opacity:0"), (7.81, "opacity:1"), (8.29, "opacity:1"),
              (8.3, "opacity:0"), (8.7, "opacity:0"), (8.71, "opacity:1"), (9.5, "opacity:1"),
              (9.51, "opacity:0"), (9.9, "opacity:0"), (9.91, "opacity:1"), (10.59, "opacity:1"),
              (10.6, "opacity:0"), (LOOP, "opacity:0")])
body.append(f'<rect x="{cx + CHW * len(ask):.1f}" y="{py - 11}" width="{CHW:.1f}" height="14" '
            f'fill="{T}" class="{blink}"/>')
body.append(spans(cx, py + LH, [("✗ ", R), ("denied · the agent gets no clear value", T)], cls=show(11.0), size=CS))
body.append(f'<g class="{show(7.0, 10.6, fade=0.1)}"><rect x="{CX + CW - 196}" y="{py + 4}" '
            f'width="180" height="22" rx="6" fill="{V}"/>'
            + text(CX + CW - 106, py + 19, "only you can answer", size=12, col=C["pane"],
                   weight=700, family=SANS, anchor="middle") + "</g>")

# --- The socket between the two ----------------------------------------------------------
GX, GW = AX + AW + 12, CX - AX - AW - 24
GC = GX + GW / 2
body.append(f'<rect x="{GX}" y="{AY + 40}" width="{GW}" height="{AH - 56}" rx="8" fill="{C["bar"]}" '
            f'stroke="{C["accent"]}" stroke-width="1.5" stroke-dasharray="6 5"/>')
body.append(text(GC, AY + 26, "MCP", size=12, col=C["accent"], weight=700, family=SANS, anchor="middle"))
body.append(text(GC, AY + AH - 2, "masked", size=11, col=S, family=FONT, anchor="middle"))
pkt = 'r="6" cx="0" cy="0"'
for t, line, back in ((1.0, 1, 2), (2.6, 3, 4), (4.2, 6, 7)):
    y0 = ay + line * LH - 4
    y1 = ay + back * LH - 4
    body.append(f'<circle {pkt} fill="{G}" class="{move(t + 0.05, t + 0.35, AX + AW - 20, y0, GC, y0)}"/>')
    body.append(f'<circle {pkt} fill="{TL}" class="{move(t + 0.45, t + 0.75, GC, y0, AX + AW - 20, y1)}"/>')
    badge(GC, y0 - 14, "FREE", G, show(t + 0.3, t + 1.4, fade=0.1))
uy = ay + 9 * LH - 4
body.append(f'<circle {pkt} fill="{V}" class="{move(5.85, 6.15, AX + AW - 20, uy, GC, uy)}"/>')
body.append(f'<circle {pkt} fill="{V}" class="{move(6.2, 6.5, GC, uy, CX + 20, cy + srow * LH - 4)}"/>')
badge(GC, uy - 14, "ASK", Y, show(6.05, 11.0, fade=0.1))
dy = ay + 11 * LH - 4
body.append(f'<circle {pkt} fill="{R}" class="{move(11.05, 11.3, CX + 20, py + LH - 4, GC, dy)}"/>')
body.append(f'<circle {pkt} fill="{R}" class="{move(11.35, 11.6, GC, dy, AX + AW - 20, dy)}"/>')
badge(GC, dy + 22, "NO", R, show(11.3, END, fade=0.1))

# --- The console's audit (bottom) ---------------------------------------------------------
BX, BY, BW, BH = 24, 446, W - 48, 84
body.append(f'<rect x="{BX}" y="{BY}" width="{BW}" height="{BH}" rx="10" fill="{C["pane"]}" '
            f'stroke="{C["border"]}" stroke-width="1.5"/>')
body.append(text(BX + 16, BY + 24, "audit", size=12, col=C["accent"], weight=700, family=SANS))
body.append(text(BX + 62, BY + 24, "chained, one line per call, pseudonyms only: the clear address is in no log",
                 size=12, col=D, family=SANS))


def jline(pairs):
    """A JSONL record as coloured runs: pairs of (key, value, colour) or "…" for an elided run."""
    out = [("{", D)]
    for i, kv in enumerate(pairs):
        if i:
            out.append((",", D))
        if kv == "…":
            out.append(("…", D))
            continue
        k, v, col = kv
        out += [(f'"{k}":', D), (v, col)]
    out.append(("}", D))
    return out


free = jline([("event", '"log.call"', T), ("profile", '"staging"', T), ("decision", '"ok"', G),
              "…", ("peer_uid", "10052", T), "…", ("method", '"log.patterns"', T), ("sources", '["api"]', S)])
denied = jline([("event", '"log.call"', T), ("profile", '"staging"', T), ("decision", '"denied"', R),
                "…", ("peer_uid", "10052", T), "…", ("method", '"log.unmask"', T)])
body.append(spans(BX + 16, BY + 48, free, cls=show(3.6), size=10))
body.append(spans(BX + 16, BY + 68, denied, cls=show(11.4), size=10))

# Captions.
caps = [(0.0, 5.7, "Counts, patterns and traces are free, and masked before the model sees them."),
        (5.7, 11.2, "Unmasking a value waits for you, in a console the agent can't reach."),
        (11.2, END, "You said no. The agent never saw the address, and the audit kept the call.")]
for t0, t1, s in caps:
    body.append(text(W / 2, 580, s, cls=show(t0 + 0.05, t1 - 0.2), size=23, weight=650,
                     family=SANS, anchor="middle"))

label = ("locklog: Claude Code asks when the PDF errors started on a staging profile. locklog_count "
         "shows the step at 14:02, locklog_patterns finds the new pattern with the email and the IP "
         "already pseudonymised, and locklog_trace follows order 4812: all free and masked. The agent "
         "then asks locklog_unmask for the email. The locklog console, in its own account and "
         "container, shows the read-pii approval screen with the masked record and the span marked; "
         "the human answers n. The agent gets denied and "
         "carries on without the address; the audit records every call with pseudonyms only.")
print(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" '
      f'role="img" aria-label="{esc(label)}">')
print("<title>locklog: your AI reads the logs, not the people in them</title>")
print("<style>" + "\n".join(css) +
      f"\n@media (prefers-reduced-motion: reduce){{*{{animation-delay:-{END - 0.4:.1f}s!important;"
      "animation-play-state:paused!important}}</style>")
print("\n".join(body))
print("</svg>")
