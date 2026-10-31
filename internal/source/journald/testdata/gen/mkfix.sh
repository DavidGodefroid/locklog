#!/bin/sh
# Runs inside a distro container: installs journal tools, writes two fixture
# kinds into /out: remote.journal (systemd-journal-remote from export format)
# and native/ (a standalone systemd-journald fed through the native socket),
# then the journalctl -o json reference for each.
set -eu
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq systemd systemd-journal-remote python3 >/dev/null 2>&1
else
  dnf -y -q install systemd systemd-journal-remote python3 >/dev/null 2>&1
fi
systemctl --version | head -1 > /out/systemd-version.txt
JR=$(ls /lib/systemd/systemd-journal-remote /usr/lib/systemd/systemd-journal-remote 2>/dev/null | head -1)
python3 /s1/genexport.py ${N:-300} 42 > /tmp/export.txt
rm -f /out/remote.journal
"$JR" --split-mode=none -o /out/remote.journal /tmp/export.txt
journalctl --file /out/remote.journal -o json --no-pager --all > /out/remote.json
journalctl --file /out/remote.journal -o export --no-pager --all > /out/remote.export
journalctl --file /out/remote.journal --header > /out/remote.header || true

# native journald, standalone, persistent storage
systemd-machine-id-setup >/dev/null 2>&1 || true
mkdir -p /var/log/journal /run/systemd/journal /etc/systemd
JD=$(ls /lib/systemd/systemd-journald /usr/lib/systemd/systemd-journald 2>/dev/null | head -1)
"$JD" >/dev/null 2>&1 &

JPID=$!
sleep 2
i=0
while [ $i -lt 120 ]; do
  echo "native line $i user carol$i@example.net ip 198.51.100.$((i % 250))" | systemd-cat -t shop-api -p info
  i=$((i+1))
done
python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
for i in range(60):
    msg = ("MESSAGE=long native %d " % i + "y" * (700 + i * 13) + "\nPRIORITY=3\nSYSLOG_IDENTIFIER=nativepy\nCODE_FILE=x.py\nCODE_LINE=%d\n" % i).encode()
    s.sendto(msg, "/run/systemd/journal/socket")
EOF
logger -t shop-worker "syslog transport line for dave@example.com"
sleep 2
kill $JPID; wait $JPID 2>/dev/null || true
rm -rf /out/native; mkdir -p /out/native
cp -r /var/log/journal/* /run/log/journal/* /out/native/ 2>/dev/null || true
for f in $(find /out/native -name '*.journal*'); do
  journalctl --file "$f" -o json --no-pager --all > "$f.json"
  journalctl --file "$f" --header > "$f.header" || true
done
chmod -R a+rX /out
