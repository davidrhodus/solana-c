#!/usr/bin/env python3
"""Compute replay latency percentiles from validator logs and optionally gate."""

from __future__ import annotations

import argparse
import math
import re
import sys
from pathlib import Path

RE_SLOT_TIME = re.compile(
    r"Slot\s+\d+\s+replayed successfully\s+\(tx=\d+\s+entries=\d+\s+time=([0-9]+(?:\.[0-9]+)?)ms\)"
)
RE_REPLAY_LAST = re.compile(
    r"Replay:\s+last_slot=\d+\s+slots=\d+\s+avg=[0-9]+(?:\.[0-9]+)?ms\s+last=([0-9]+(?:\.[0-9]+)?)ms"
)


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    idx = (p / 100.0) * (len(values) - 1)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return values[lo]
    frac = idx - lo
    return values[lo] + (values[hi] - values[lo]) * frac


def parse_samples(log_path: Path) -> list[float]:
    samples: list[float] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = RE_REPLAY_LAST.search(line)
            if m:
                samples.append(float(m.group(1)))
                continue
            m = RE_SLOT_TIME.search(line)
            if not m:
                continue
            samples.append(float(m.group(1)))
    return samples


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log", help="validator log path")
    ap.add_argument("--min-samples", type=int, default=1, help="minimum required samples")
    ap.add_argument("--max-p50", type=float, default=None)
    ap.add_argument("--max-p90", type=float, default=None)
    ap.add_argument("--max-p95", type=float, default=None)
    ap.add_argument("--max-p99", type=float, default=None)
    ap.add_argument("--max-max", type=float, default=None)
    args = ap.parse_args()

    log_path = Path(args.log)
    if not log_path.is_file():
        print(f"error: log not found: {log_path}", file=sys.stderr)
        return 2

    samples = parse_samples(log_path)
    n = len(samples)
    if n < args.min_samples:
        print(
            f"error: insufficient replay samples: have={n} need={args.min_samples}",
            file=sys.stderr,
        )
        return 2

    samples.sort()
    p50 = percentile(samples, 50.0)
    p90 = percentile(samples, 90.0)
    p95 = percentile(samples, 95.0)
    p99 = percentile(samples, 99.0)
    pmax = samples[-1]

    print(
        "replay_n={} p50={:.2f}ms p90={:.2f}ms p95={:.2f}ms p99={:.2f}ms max={:.2f}ms".format(
            n, p50, p90, p95, p99, pmax
        )
    )

    failures: list[str] = []
    if args.max_p50 is not None and p50 > args.max_p50:
        failures.append(f"p50 {p50:.2f}ms > {args.max_p50:.2f}ms")
    if args.max_p90 is not None and p90 > args.max_p90:
        failures.append(f"p90 {p90:.2f}ms > {args.max_p90:.2f}ms")
    if args.max_p95 is not None and p95 > args.max_p95:
        failures.append(f"p95 {p95:.2f}ms > {args.max_p95:.2f}ms")
    if args.max_p99 is not None and p99 > args.max_p99:
        failures.append(f"p99 {p99:.2f}ms > {args.max_p99:.2f}ms")
    if args.max_max is not None and pmax > args.max_max:
        failures.append(f"max {pmax:.2f}ms > {args.max_max:.2f}ms")

    if failures:
        print("replay_latency_gate=FAIL", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print("replay_latency_gate=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
