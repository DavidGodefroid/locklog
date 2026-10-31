#!/usr/bin/env python3
"""Generate a synthetic journal export-format stream (deterministic, seeded).

Covers: short and long (compressible) MESSAGE, multi-line, UTF-8, binary
fields, COREDUMP* fields, _CMDLINE/_EXE/_AUDIT_*, trusted fields, repeated
values (data object dedup), past timestamps, several boots, and canaries.
"""
import random
import struct
import sys

rnd = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 42)
n = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
out = sys.stdout.buffer

boots = ["%032x" % rnd.getrandbits(128) for _ in range(3)]
units = ["nginx.service", "shop-api.service", "cron.service", "sshd.service", "docker.service"]
idents = ["nginx", "shop-api", "CRON", "sshd", "dockerd"]
base = 1761800000_000000  # 2025-10-30 µs

def field(k, v):
    if isinstance(v, str):
        v = v.encode()
    if b"\n" in v or any(c < 32 and c not in (9,) for c in v):
        out.write(k.encode() + b"\n" + struct.pack("<Q", len(v)) + v + b"\n")
    else:
        out.write(k.encode() + b"=" + v + b"\n")

for i in range(n):
    b = boots[min(i * 3 // n, 2)]
    ts = base + i * 1_000_003 + rnd.randint(0, 999)
    u = rnd.randrange(len(units))
    field("__REALTIME_TIMESTAMP", str(ts))
    field("__MONOTONIC_TIMESTAMP", str(1_000_000 + i * 1000))
    field("_BOOT_ID", b)
    field("_MACHINE_ID", "0123456789abcdef0123456789abcdef")
    field("_HOSTNAME", "web-%d" % (u % 2))
    field("_SYSTEMD_UNIT", units[u])
    field("SYSLOG_IDENTIFIER", idents[u])
    field("PRIORITY", str(rnd.choice([3, 4, 6, 6, 6, 7])))
    field("_PID", str(1000 + u))
    field("_UID", "0")
    field("_TRANSPORT", rnd.choice(["journal", "stdout", "syslog"]))
    k = i % 10
    if k == 0:
        msg = "render pdf for alice%d@example.com from 203.0.113.%d failed: upstream timed out" % (i, i % 250)
    elif k == 1:
        msg = ("GET /api/orders/%d 502 " % i) + "x" * rnd.randint(600, 4000)  # compressible
    elif k == 2:
        msg = "trace line 1\n\tat com.shop.Api.render(Api.java:42)\n\tat main"
    elif k == 3:
        msg = "utf8 ✓ éàü 日本語 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"
    elif k == 4:
        msg = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(rnd.randint(1, 3000)))
    else:
        msg = "order %d processed in %dms" % (rnd.randint(1, 9999), rnd.randint(1, 900))
    field("MESSAGE", msg)
    if k == 3:
        field("CODE_FILE", "api.go")
        field("CODE_LINE", str(i))
        field("CODE_FUNC", "render")
    if k == 5:
        field("_CMDLINE", "/usr/bin/shop-api --password=hunter2-canary")
        field("_EXE", "/usr/bin/shop-api")
        field("_AUDIT_SESSION", "4")
        field("_AUDIT_LOGINUID", "1000")
    if k == 6:
        field("COREDUMP_ENVIRON", "SECRET_TOKEN=canary-coredump-%d\nHOME=/root" % i)
        field("COREDUMP_EXE", "/usr/bin/shop-api")
        field("COREDUMP", bytes(rnd.getrandbits(8) for _ in range(2048)))
    if k == 7:
        field("BINARY_BLOB", bytes([0, 1, 2, 255, 10, 13]) + b"canary")
        field("CONTAINER_NAME", "shop-api-1")
    if k == 8:
        field("USER_EMAIL", "bob%d@example.org" % i)
    out.write(b"\n")
