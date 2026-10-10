"""Top-k attacker ranking: min-heap O(n log k) vs full sort O(n log n)."""
import heapq
import random
import sys
import time
from collections import Counter

SUSPICIOUS_ACTIONS = {"LOGIN_FAIL", "REQUEST_404"}


def top_k_heap(counts, k=10):
    """Keep a min-heap of the k best items seen so far. O(n log k) time, O(k) space."""
    heap = []
    for ip, c in counts.items():
        item = (c, ip)
        if len(heap) < k:
            heapq.heappush(heap, item)
        elif item > heap[0]:               # beats the weakest of the current top k
            heapq.heapreplace(heap, item)  # pop weakest, push new, O(log k)
    return sorted(heap, reverse=True)      # only k items to sort


def top_k_naive(counts, k=10):
    """Sort everything, then take the first k. O(n log n)."""
    items = [(c, ip) for ip, c in counts.items()]
    items.sort(reverse=True)
    return items[:k]


class AttackerTracker:
    """Counts suspicious events per IP and reports the worst offenders."""

    def __init__(self):
        self.counts = Counter()

    def observe(self, event):
        if event.action in SUSPICIOUS_ACTIONS:
            self.counts[event.ip] += 1

    def add(self, ip, n=1):
        """Let other detectors (e.g. signature hits) add to an IP's score."""
        self.counts[ip] += n

    def top(self, k=10):
        return [{"ip": ip, "score": c} for c, ip in top_k_heap(self.counts, k)]


if __name__ == "__main__":
    from .parser import parse_file

    # ---- unit tests ----
    sample = Counter({"a": 5, "b": 9, "c": 9, "d": 1})
    assert top_k_heap(sample, 2) == top_k_naive(sample, 2) == [(9, "c"), (9, "b")]
    assert top_k_heap(sample, 10) == top_k_naive(sample, 10)
    assert top_k_heap(Counter(), 3) == []
    print("Unit tests passed")

    # ---- real data ----
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample.log"
    events, bad = parse_file(path)
    tracker = AttackerTracker()
    for ev in events:
        tracker.observe(ev)
    print(f"\nTop 5 suspicious IPs from {len(events)} events:")
    for row in tracker.top(5):
        print(f"  {row['ip']:<18} score={row['score']}")

    # ---- benchmark: many distinct IPs, small k ----
    rng = random.Random(1)
    big = Counter({f"ip{i}": rng.randint(1, 1_000_000) for i in range(300_000)})
    t0 = time.perf_counter(); a = top_k_heap(big, 10); t_heap = time.perf_counter() - t0
    t0 = time.perf_counter(); b = top_k_naive(big, 10); t_sort = time.perf_counter() - t0
    print(f"\nBenchmark: 300,000 IPs, k=10")
    print(f"  heap: {t_heap * 1000:.1f} ms")
    print(f"  sort: {t_sort * 1000:.1f} ms")
    print("  Same result:", a == b)