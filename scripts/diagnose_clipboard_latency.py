"""Privacy-safe timing review of already-existing installed Shelf log events.

Records no queries, clips, titles, matched text, file names or sensitive
log lines. Source is the installed provider's content-free timing events.
Does not open/lock its databases or change live processes or settings.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import statistics

PHASE = re.compile(r"Clipboard interaction stage timing;.*\bphase=(\w+)\s+elapsed_ms=(\d+)")
IPC = re.compile(r'Clipboard IPC phase timing;.*operation="([^"]+)"\s+discovery_ms=\d+\s+ipc_ms=(\d+)\s+total_ms=(\d+)')
WORKER = re.compile(r'Clipboard search completed without retaining the copy authorization lock operation="([^"]+)"\s+worker_queue_ms=(\d+)\s+lock_wait_ms=(\d+)\s+total_ms=(\d+)')
MAX_FILE = 8 * 1024 * 1024


def percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    values = sorted(values)
    index = min(len(values) - 1, int((len(values) - 1) * fraction + 0.5))
    return values[index]


def extract(line: str):
    if "Clipboard " not in line:
        return None
    match = PHASE.search(line)
    if match:
        return "phase." + match[1], int(match[2])
    match = IPC.search(line)
    if match:
        return "ipc." + match[1], int(match[3])
    match = WORKER.search(line)
    if match:
        return "worker." + match[1], int(match[4])
    return None


def extract_diagnostics(line: str):
    """Additional duration-only detail to separate queue, lock, and IPC work."""
    match = IPC.search(line)
    if match:
        return [("ipc_transport." + match[1], int(match[2]))]
    match = WORKER.search(line)
    if match:
        return [
            ("worker_queue." + match[1], int(match[2])),
            ("worker_lock_wait." + match[1], int(match[3])),
        ]
    return []


def review(log_dir: Path) -> dict:
    measurements = defaultdict(list)
    records = {}
    for path in sorted(log_dir.glob("spiffy-shelf.log.20*")):
        if path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE:
            continue
        day = path.name.removeprefix("spiffy-shelf.log.")
        daystats = defaultdict(list)
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                item = extract(line)
                if item:
                    name, duration = item
                    if 0 <= duration <= 600_000:
                        daystats[name].append(duration)
                        measurements[name].append(duration)
                for name, duration in extract_diagnostics(line):
                    if 0 <= duration <= 600_000:
                        daystats[name].append(duration)
                        measurements[name].append(duration)
        if daystats:
            records[day] = {
                metric: {"samples": len(values), "p50_ms": percentile(values, 0.50),
                         "p95_ms": percentile(values, 0.95), "max_ms": max(values)}
                for metric, values in sorted(daystats.items())
            }
    return {
        "schema": "spiffy_clipboard_content_free_latency_audit_v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "content_recorded": False,
        "days_covered": sorted(records),
        "aggregate": {
            metric: {
                "samples": len(values), "p50_ms": percentile(values, 0.5),
                "p95_ms": percentile(values, 0.95), "max_ms": max(values)}
            for metric, values in sorted(measurements.items())
        },
        "daily": records,
        "limits": "Historical provider-owned timing logs, not a fresh user-visible hotkey-to-first-paint measurement",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", type=Path, default=Path.home() / "AppData" / "Local" / "SpiffyShelf" / "logs")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.logs.is_symlink() or not args.logs.is_dir():
        parser.error("Expected historical Shelf log directory does not exist")
    result = review(args.logs)
    if args.report:
        if not args.report.parent.is_dir() or args.report.is_symlink():
            parser.error("Report parent unavailable or report is a symlink")
        args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "days": result["days_covered"],
        "aggregate": result["aggregate"],
        "last_two_days": {day: result["daily"][day] for day in result["days_covered"][-2:]},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
