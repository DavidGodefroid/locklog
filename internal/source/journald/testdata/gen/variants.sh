set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null; apt-get install -y -qq systemd systemd-journal-remote python3 >/dev/null 2>&1
python3 /s1/genexport.py 200 7 > /tmp/e.txt
for c in LZ4 XZ ZSTD 0; do for k in 0 1; do for h in 0 1; do
  n=c$c-compact$k-keyed$h; rm -f /out/$n.journal
  SYSTEMD_JOURNAL_COMPRESS=$c SYSTEMD_JOURNAL_COMPACT=$k SYSTEMD_JOURNAL_KEYED_HASH=$h /lib/systemd/systemd-journal-remote --split-mode=none -o /out/$n.journal /tmp/e.txt 2>/dev/null
  journalctl --file /out/$n.journal -o json --all --no-pager > /out/$n.json
  journalctl --file /out/$n.journal --header | grep Incompat > /out/$n.flags
done; done; done
chmod -R a+rX /out
