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

rows = []
with open(path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        m_ts = ts_re.search(line)
        m_t = timing_re.search(line)
        if not (m_ts and m_t):
            continue
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
PY
