#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <rbtc_log_file> [window_minutes]"
  exit 1
fi

LOG_FILE="$1"
WINDOW_MINUTES="${2:-30}"

if [[ ! -f "$LOG_FILE" ]]; then
  echo "log file not found: $LOG_FILE"
  exit 1
fi

python - "$LOG_FILE" "$WINDOW_MINUTES" <<'PY'
import re
import sys
from datetime import datetime, timedelta

path = sys.argv[1]
window_minutes = int(sys.argv[2])

ts_re = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)")
height_re = re.compile(r"height=(\d+)")
timing_re = re.compile(r"connect timing: height=(\d+)\s+verify_ms=(\d+)\s+write_ms=(\d+)\s+total_ms=(\d+)")
verify_re = re.compile(r"verify timing: height=(\d+)\s+txs=(\d+)\s+script_precheck_ms=(\d+)\s+script_serial_ms=(\d+)\s+verify_total_ms=(\d+)")

rows = []
verify_rows = []
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m_ts = ts_re.search(line)
        m_t = timing_re.search(line)
        if m_ts and m_t:
            ts = datetime.strptime(m_ts.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")
            rows.append(
                (
                    ts,
                    int(m_t.group(1)),
                    int(m_t.group(2)),
                    int(m_t.group(3)),
                    int(m_t.group(4)),
                )
            )
        m_v = verify_re.search(line)
        if m_ts and m_v:
            ts = datetime.strptime(m_ts.group(1), "%Y-%m-%dT%H:%M:%S.%fZ")
            verify_rows.append(
                (
                    ts,
                    int(m_v.group(1)),
                    int(m_v.group(2)),
                    int(m_v.group(3)),
                    int(m_v.group(4)),
                    int(m_v.group(5)),
                )
            )

if not rows:
    print("No 'connect timing' rows found. Start node with RUST_LOG=debug first.")
    sys.exit(2)

rows.sort(key=lambda x: x[0])
end_ts = rows[-1][0]
start_ts = end_ts - timedelta(minutes=window_minutes)
window = [r for r in rows if r[0] >= start_ts]

if len(window) < 2:
    print(f"Not enough samples in last {window_minutes} minutes.")
    sys.exit(3)

heights = [r[1] for r in window]
verify = [r[2] for r in window]
write = [r[3] for r in window]
total = [r[4] for r in window]
elapsed = (window[-1][0] - window[0][0]).total_seconds()
height_delta = max(0, heights[-1] - heights[0])
blocks_per_sec = (height_delta / elapsed) if elapsed > 0 else 0.0

def p95(values):
    if not values:
        return 0
    vals = sorted(values)
    idx = min(len(vals) - 1, int(len(vals) * 0.95))
    return vals[idx]

print("==== rbtc connect performance window ====")
print(f"log_file: {path}")
print(f"window_minutes: {window_minutes}")
print(f"samples: {len(window)}")
print(f"time_range: {window[0][0].isoformat()}Z -> {window[-1][0].isoformat()}Z")
print(f"height_range: {heights[0]} -> {heights[-1]} (delta={height_delta})")
print(f"blocks_per_sec: {blocks_per_sec:.3f}")
print("--- timing (ms) ---")
print(f"verify_avg: {sum(verify)/len(verify):.2f}, verify_p95: {p95(verify)}")
print(f"write_avg:  {sum(write)/len(write):.2f}, write_p95:  {p95(write)}")
print(f"total_avg:  {sum(total)/len(total):.2f}, total_p95:  {p95(total)}")

if verify_rows:
    verify_rows.sort(key=lambda x: x[0])
    v_end = verify_rows[-1][0]
    v_start = v_end - timedelta(minutes=window_minutes)
    v_window = [r for r in verify_rows if r[0] >= v_start]
    if v_window:
        txs = [r[2] for r in v_window]
        pre = [r[3] for r in v_window]
        serial = [r[4] for r in v_window]
        vtotal = [r[5] for r in v_window]
        print("--- verify timing (ms) ---")
        print(f"samples: {len(v_window)}, avg_txs_per_block: {sum(txs)/len(txs):.2f}")
        print(f"script_precheck_avg: {sum(pre)/len(pre):.2f}, script_precheck_p95: {p95(pre)}")
        print(f"script_serial_avg:   {sum(serial)/len(serial):.2f}, script_serial_p95:   {p95(serial)}")
        print(f"verify_total_avg:    {sum(vtotal)/len(vtotal):.2f}, verify_total_p95:    {p95(vtotal)}")
PY
