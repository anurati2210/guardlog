"""Sliding-window brute-force detector: fast (deque) and naive versions."""
import sys
import time
from collections import defaultdict, deque

from .base import Detector


class SlidingWindowDetector(Detector):
    """O(1) amortized per event: each timestamp is added once and removed once."""
    name = "brute_force"

    def __init__(self, window=60, threshold=10, cooldown=60):
        self.window = window          # seconds to look back
        self.threshold = threshold    # failures inside the window that trigger an alert
        self.cooldown = cooldown      # seconds before the same IP can alert again
        self.fails = defaultdict(deque)
        self.last_alert = {}

    def _alert(self, event, count):
        last = self.last_alert.get(event.ip)
        if last is not None and event.ts - last < self.cooldown:
            return []
        self.last_alert[event.ip] = event.ts
        return [{
            "type": "BRUTE_FORCE",
            "ip": event.ip,
            "time": event.time_str,
            "count": count,
            "detail": f"{count} failed logins from {event.ip} within {self.window}s",
        }]

    def process(self, event):
        if event.action != "LOGIN_FAIL":
            return []
        dq = self.fails[event.ip]
        dq.append(event.ts)
        while dq and event.ts - dq[0] > self.window:
            dq.popleft()
        if len(dq) >= self.threshold:
            return self._alert(event, len(dq))
        return []


class NaiveWindowDetector(SlidingWindowDetector):
    """Same behaviour, but rescans ALL earlier failures of the IP on every event."""

    def __init__(self, window=60, threshold=10, cooldown=60):
        super().__init__(window, threshold, cooldown)
        self.fails = defaultdict(list)

    def process(self, event):
        if event.action != "LOGIN_FAIL":
            return []
        history = self.fails[event.ip]
        history.append(event.ts)
        count = sum(1 for t in history if event.ts - t <= self.window)   # O(history)
        if count >= self.threshold:
            return self._alert(event, count)
        return []


def run(detector, events):
    alerts = []
    for ev in events:
        alerts.extend(detector.process(ev))
    return alerts


if __name__ == "__main__":
    from ..parser import Event, parse_file

    # ---- unit tests ----
    def fail(ts, ip="9.9.9.9"):
        return Event(ts, "t", ip, "admin", "LOGIN_FAIL", "x", "/login", "raw")

    for cls in (SlidingWindowDetector, NaiveWindowDetector):
        assert len(run(cls(10, 5, 60), [fail(i) for i in range(5)])) == 1        # 5 fast fails -> alert
        assert len(run(cls(10, 5, 60), [fail(i) for i in range(4)])) == 0        # only 4 -> no alert
        assert len(run(cls(10, 5, 60), [fail(i * 20) for i in range(10)])) == 0  # too spread out -> no alert
        assert len(run(cls(10, 5, 60), [fail(i) for i in range(20)])) == 1       # cooldown: one alert, not 16
    print("Unit tests passed")

    # ---- real data: both versions must agree ----
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample.log"
    events, bad = parse_file(path)

    t0 = time.perf_counter(); fast = run(SlidingWindowDetector(), events); t_fast = time.perf_counter() - t0
    t0 = time.perf_counter(); slow = run(NaiveWindowDetector(), events); t_slow = time.perf_counter() - t0

    print(f"Events: {len(events)}")
    print(f"Alerts (sliding window): {len(fast)} in {t_fast * 1000:.1f} ms")
    print(f"Alerts (naive):          {len(slow)} in {t_slow * 1000:.1f} ms")
    print("Same alerts from both versions:", fast == slow)
    for a in fast[:3]:
        print(a)