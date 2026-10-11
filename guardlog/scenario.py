"""Challenge Card 1 scenario: benign busy IPs, log-sync delay model, ground truth and scoring."""
import math
import random
from datetime import datetime, timedelta

from .disorder import disorder, line_ts
from .generator import fmt, generate_logs, get_attacker_ips

START = datetime(2026, 10, 11, 0, 0, 0)
BENIGN_USERS = ["alice", "bob", "carol", "dave", "eve"]


def busy_benign_lines(n_ips=10, seed=5, minutes=40):
    """Shared office/campus IPs whose users mistype passwords often, but never fast enough to be an attack.
    Gaps of 7-11 s mean at most 9 failures in any 60 s window, below the threshold of 10."""
    rng = random.Random(seed)
    lines, ips = [], []
    for i in range(n_ips):
        ip = f"198.51.100.{10 + i}"          # documentation range, will not clash with generated IPs
        ips.append(ip)
        t = START + timedelta(seconds=rng.randint(0, 20 * 3600))
        end = t + timedelta(minutes=minutes)
        while t < end:
            t += timedelta(seconds=rng.uniform(7, 11))
            lines.append(fmt(t, ip, rng.choice(BENIGN_USERS), "LOGIN_FAIL",
                             "pw" + str(rng.randint(100, 999)), "/login"))
    return lines, ips


def batch_sync(lines, frac=0.2, interval=600, seed=1):
    """Log sync model: a random `frac` of lines is held on the remote server and delivered in bulk at
    the next sync (every `interval` s). Each delayed line is late by up to `interval` s, and delayed
    lines arrive together as one batch, in timestamp order inside the batch."""
    rng = random.Random(seed)
    t0 = START.timestamp()
    keyed = []
    for i, line in enumerate(lines):
        ts = line_ts(line)
        if rng.random() < frac:
            arrival = t0 + math.ceil((ts - t0) / interval) * interval + 0.5   # next sync boundary
        else:
            arrival = ts
        keyed.append((arrival, ts, i, line))
    keyed.sort()

    out, newest, late, worst = [], 0.0, 0, 0.0
    for arrival, ts, i, line in keyed:
        if ts < newest:
            late += 1
            worst = max(worst, newest - ts)
        newest = max(newest, ts)
        out.append(line)
    stats = {"lines": len(lines), "delayed": sum(1 for k in keyed if k[0] > k[1]),
             "out_of_order": late, "max_lateness_s": round(worst)}
    return out, stats


def make_scenario(n_lines=50000, seed=42, n_busy=10):
    """Attack logs + benign busy IPs, in true time order. Returns (lines, attacker_ips, busy_ips)."""
    lines = generate_logs(n_lines, seed)
    busy, busy_ips = busy_benign_lines(n_busy, seed + 5)
    merged = sorted(lines + busy, key=line_ts)
    return merged, set(get_attacker_ips(seed)), set(busy_ips)


def score(alerts, attackers, busy_ips):
    """Ground-truth metrics. An alert on any IP that is not an attacker is a false positive."""
    ips = {a["ip"] for a in alerts}
    fp_alerts = [a for a in alerts if a["ip"] not in attackers]
    return {
        "alerts": len(alerts),
        "attackers_caught": len(ips & attackers),
        "busy_ips_flagged": len(ips & busy_ips),
        "legit_ips_flagged": len(ips - attackers),
        "fp_alert_rate": len(fp_alerts) / len(alerts) if alerts else 0.0,
    }


if __name__ == "__main__":
    from .detectors.window import SlidingWindowDetector, run
    from .parser import parse_lines

    lines, attackers, busy = make_scenario()
    print(f"{len(lines)} lines | {len(attackers)} attacker IPs | {len(busy)} busy benign IPs "
          f"(at most 9 failures per 60 s; the alert threshold is 10)")

    jitter, jstats = disorder(lines, frac=0.2, max_delay=600, seed=1)
    batch, bstats = batch_sync(lines, frac=0.2, interval=600, seed=1)
    print("Jitter stats:", jstats)
    print("Batch stats: ", bstats)

    print(f"\nOLD detector (sliding window with deque)")
    print(f"{'scenario':<16}{'alerts':>7}{'attackers':>11}{'busy IPs flagged':>18}{'FP alert rate':>15}")
    for label, data in (("in order", lines), ("jitter 20%", jitter), ("sync batch 20%", batch)):
        events, _ = parse_lines(data)
        s = score(run(SlidingWindowDetector(), events), attackers, busy)
        caught = f"{s['attackers_caught']}/{len(attackers)}"
        rate = f"{s['fp_alert_rate'] * 100:.1f}%"
        print(f"{label:<16}{s['alerts']:>7}{caught:>11}{s['busy_ips_flagged']:>18}{rate:>15}")