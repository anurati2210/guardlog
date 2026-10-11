"""Order-tolerant brute-force detector (Challenge Card 1).

Keeps each IP's failure times SORTED BY EVENT TIME. A late line is inserted where it belongs and
only the windows that contain it are re-checked, so a burst is flagged the moment its last line
arrives (no buffering), and a delayed batch of slow failures can never look like a burst.
"""
import sys
import time
from bisect import bisect_left, bisect_right, insort
from collections import defaultdict

from .base import Detector


class OrderTolerantWindowDetector(Detector):
    name = "brute_force"

    def __init__(self, window=60, threshold=10, cooldown=60, max_lateness=900):
        self.window = window
        self.threshold = threshold
        self.cooldown = cooldown
        self.max_lateness = max_lateness    # how late (seconds) a line may arrive and still be handled exactly
        self.fails = defaultdict(list)      # ip -> failure times, sorted by EVENT time
        self.alerted = defaultdict(list)    # ip -> event times of alerts already raised
        self.newest = float("-inf")         # newest event time seen so far
        self.seen = 0
        self.late_events = 0                # lines that arrived after a newer line
        self.too_late = 0                   # lines later than max_lateness (may be undercounted)
        self.worst_lateness = 0.0

    def _prune(self):
        """Drop state no future line can need, so memory stays bounded."""
        cutoff = self.newest - self.max_lateness - self.window
        for ip in list(self.fails):
            lst = self.fails[ip]
            if lst and lst[0] < cutoff:
                del lst[:bisect_left(lst, cutoff)]
            if not lst:
                del self.fails[ip]
        keep_from = self.newest - self.max_lateness - self.cooldown
        for ip in list(self.alerted):
            self.alerted[ip] = [t for t in self.alerted[ip] if t >= keep_from]
            if not self.alerted[ip]:
                del self.alerted[ip]

    def _best_window_count(self, lst, ts):
        """Most failures inside any `window`-second span that contains time ts (two pointers)."""
        lo = bisect_left(lst, ts - self.window)
        hi = bisect_right(lst, ts + self.window)
        seg = lst[lo:hi]
        best, left = 0, 0
        for right in range(len(seg)):
            while seg[right] - seg[left] > self.window:
                left += 1
            if seg[left] <= ts <= seg[right]:
                best = max(best, right - left + 1)
        return best

    def _alert(self, event, count):
        ts = event.ts
        times = self.alerted[event.ip]
        if any(abs(ts - t) < self.cooldown for t in times):   # cooldown in EVENT time
            return []
        times.append(ts)
        return [{
            "type": "BRUTE_FORCE",
            "ip": event.ip,
            "time": event.time_str,
            "count": count,
            "detail": f"{count} failed logins from {event.ip} within {self.window}s",
        }]

    def process(self, event):
        ts = event.ts
        if ts > self.newest:
            self.newest = ts
        else:
            lateness = self.newest - ts
            if lateness > 0:
                self.late_events += 1
                self.worst_lateness = max(self.worst_lateness, lateness)
                if lateness > self.max_lateness:
                    self.too_late += 1
        self.seen += 1
        if self.seen % 20000 == 0:
            self._prune()

        if event.action != "LOGIN_FAIL":
            return []

        lst = self.fails[event.ip]
        cutoff = self.newest - self.max_lateness - self.window
        if lst and lst[0] < cutoff:
            del lst[:bisect_left(lst, cutoff)]

        if not lst or ts >= lst[-1]:                  # fast path: on time, plain append
            lst.append(ts)
            count = len(lst) - bisect_left(lst, ts - self.window)
        else:                                         # late line: insert at its true position
            insort(lst, ts)
            count = self._best_window_count(lst, ts)

        if count >= self.threshold:
            return self._alert(event, count)
        return []


if __name__ == "__main__":
    from ..disorder import disorder
    from ..generator import generate_logs
    from ..parser import Event, parse_lines
    from ..scenario import batch_sync, make_scenario, score
    from .window import SlidingWindowDetector, run

    def fail(ts, ip="9.9.9.9"):
        return Event(ts, "t", ip, "admin", "LOGIN_FAIL", "x", "/login", "raw")

    def alerts_for(det, stamps):
        return run(det, [fail(t) for t in stamps])

    def new(**kw):
        return OrderTolerantWindowDetector(10, 5, 60, **kw)     # window 10 s, threshold 5

    def old():
        return SlidingWindowDetector(10, 5, 60)

    # 1) in-order input: same alerts as the old detector
    for stamps in ([0, 1, 2, 3, 4], [0, 1, 2, 3], [i * 20 for i in range(10)], list(range(20))):
        assert alerts_for(new(), stamps) == alerts_for(old(), stamps)
    # 2) a real burst is caught whatever the arrival order
    for order in ([4, 3, 2, 1, 0], [2, 0, 4, 1, 3], [0, 1, 2, 3, 4]):
        assert len(alerts_for(new(), order)) == 1
    # 3) a late line that completes a burst raises the alert ON ARRIVAL (no buffering)
    det = new()
    assert run(det, [fail(t) for t in [0, 1, 2, 3, 20]]) == []
    assert len(det.process(fail(4))) == 1
    # 4) the card's false positive: slow failures (30 s apart) delivered late, in one batch
    slow_batch = [i * 30 for i in range(20)][::-1]
    assert len(alerts_for(new(), slow_batch)) == 0
    assert len(alerts_for(old(), slow_batch)) > 0            # old detector raises a false alarm
    # 5) memory stays bounded
    det = OrderTolerantWindowDetector(10, 5, 60, max_lateness=100)
    run(det, [fail(i) for i in range(0, 5000, 3)])
    assert len(det.fails["9.9.9.9"]) < 120
    print("Unit tests passed")

    # ---- regression: in-order logs give exactly the old detector's alerts ----
    events, _ = parse_lines(generate_logs(10000, 42))
    assert run(OrderTolerantWindowDetector(), events) == run(SlidingWindowDetector(), events)
    print("Regression passed: identical alerts on in-order logs")

    # ---- Challenge Card 1 evaluation ----
    lines, attackers, busy = make_scenario()
    jitter, _ = disorder(lines, frac=0.2, max_delay=600, seed=1)
    batch, bstats = batch_sync(lines, frac=0.2, interval=600, seed=1)
    print(f"\nScenario: {len(lines)} lines, 20% delayed up to 10 minutes. Batch stats: {bstats}")

    def evaluate(make_det, events):
        det = make_det()
        t0 = time.perf_counter()
        alerts = run(det, events)
        dt = time.perf_counter() - t0
        s = score(alerts, attackers, busy)
        legit_total = len({e.ip for e in events} - attackers)
        s["ip_fp"] = s["legit_ips_flagged"] / legit_total
        s["eps"] = len(events) / dt
        return s, det

    print(f"\n{'scenario':<12}{'det':<5}{'alerts':>7}{'caught':>8}{'legitFP':>8}{'IP FP%':>8}{'alertFP%':>10}{'ev/s':>9}")
    new_rows = []
    for label, data in (("in order", lines), ("jitter 20%", jitter), ("batch 20%", batch)):
        events, _ = parse_lines(data)
        for tag, make in (("old", SlidingWindowDetector), ("new", OrderTolerantWindowDetector)):
            s, det = evaluate(make, events)
            if tag == "new":
                new_rows.append(s)
            print(f"{label:<12}{tag:<5}{s['alerts']:>7}{s['attackers_caught']:>5}/{len(attackers)}"
                  f"{s['legit_ips_flagged']:>8}{s['ip_fp'] * 100:>7.1f}%{s['fp_alert_rate'] * 100:>9.1f}%{s['eps']:>9,.0f}")
            if tag == "new" and label == "batch 20%":
                print(f"             (new detector handled {det.late_events} late lines, worst {det.worst_lateness:.0f} s late, "
                      f"{det.too_late} beyond max_lateness)")

    ok = all(r["ip_fp"] < 0.05 and r["fp_alert_rate"] < 0.05 and r["attackers_caught"] == len(attackers)
             for r in new_rows)
    print("\nCARD 1 CRITERIA (20% delayed up to 10 min, false positives < 5%, all attackers caught):",
          "PASS" if ok else "FAIL")