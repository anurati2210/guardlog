"""Disorder simulator: delays a fraction of log lines (log-sync lag) and reorders by arrival time."""
import random
from datetime import datetime


def line_ts(line):
    return datetime.fromisoformat(line.split(" ", 1)[0]).timestamp()


def disorder(lines, frac=0.2, max_delay=600, min_delay=5, seed=1):
    """Return (lines_in_arrival_order, stats). `frac` of the lines are delayed by min_delay..max_delay seconds."""
    rng = random.Random(seed)
    keyed = []
    for i, line in enumerate(lines):
        ts = line_ts(line)
        delay = rng.uniform(min_delay, max_delay) if rng.random() < frac else 0.0
        keyed.append((ts + delay, i, ts, delay, line))
    keyed.sort(key=lambda k: (k[0], k[1]))      # arrival order

    out, newest, late, worst = [], 0.0, 0, 0.0
    for arrival, i, ts, delay, line in keyed:
        if ts < newest:                          # older than something we already saw
            late += 1
            worst = max(worst, newest - ts)
        newest = max(newest, ts)
        out.append(line)
    stats = {"lines": len(lines), "delayed": sum(1 for k in keyed if k[3] > 0),
             "out_of_order": late, "max_lateness_s": round(worst)}
    return out, stats


if __name__ == "__main__":
    from .detectors.window import SlidingWindowDetector, run
    from .generator import generate_logs, get_attacker_ips
    from .parser import parse_lines

    seed = 42
    lines = generate_logs(50000, seed)
    attackers = set(get_attacker_ips(seed))
    shuffled, stats = disorder(lines, frac=0.2, max_delay=600, seed=1)
    print("Disorder stats:", stats)

    for label, data in (("in order", lines), ("20% delayed", shuffled)):
        events, _ = parse_lines(data)
        alerts = run(SlidingWindowDetector(), events)
        ips = {a["ip"] for a in alerts}
        print(f"{label:<12} alerts={len(alerts):>4}  IPs flagged={len(ips):>3}  "
              f"attackers caught={len(ips & attackers):>2}  legit IPs flagged={len(ips - attackers)}")