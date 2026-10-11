"""Bloom filter + reputation detector (known-bad IPs, common-password guessing)."""
import hashlib
import math
import random
import sys
import time
from collections import Counter

from .base import Detector


class BloomFilter:
    """Set membership in tiny memory. May give false positives, never false negatives."""

    def __init__(self, n_items, fp_rate=0.01):
        self.n = max(1, n_items)
        self.p = fp_rate
        # optimal size in bits and number of hash functions
        self.m = max(8, math.ceil(-self.n * math.log(fp_rate) / (math.log(2) ** 2)))
        self.k = max(1, round(self.m / self.n * math.log(2)))
        self.bits = bytearray((self.m + 7) // 8)
        self.count = 0

    def _positions(self, item):
        # double hashing: k positions from one 128-bit hash, g_i = h1 + i*h2
        d = hashlib.blake2b(item.encode("utf-8"), digest_size=16).digest()
        h1 = int.from_bytes(d[:8], "little")
        h2 = int.from_bytes(d[8:], "little") | 1
        return [(h1 + i * h2) % self.m for i in range(self.k)]

    def add(self, item):
        for pos in self._positions(item):
            self.bits[pos >> 3] |= 1 << (pos & 7)
        self.count += 1

    def __contains__(self, item):
        return all(self.bits[pos >> 3] & (1 << (pos & 7)) for pos in self._positions(item))

    def size_bytes(self):
        return len(self.bits)

    def expected_fp(self):
        return (1 - math.exp(-self.k * self.count / self.m)) ** self.k


class ReputationDetector(Detector):
    """Flags (1) IPs from a threat feed, (2) IPs guessing common passwords."""
    name = "reputation"

    def __init__(self, bad_ips, common_passwords, pw_threshold=3, pw_ratio=0.5):
        self.bad_ips = bad_ips                # anything supporting `in`
        self.common_pw = common_passwords     # anything supporting `in`
        self.pw_threshold = pw_threshold      # minimum common-password hits
        self.pw_ratio = pw_ratio              # and at least this share of the IP's failed attempts
        self.seen_bad = set()
        self.pw_hits = Counter()
        self.pw_total = Counter()
        self.pw_alerted = set()

    def process(self, event):
        alerts = []
        if event.ip in self.bad_ips and event.ip not in self.seen_bad:
            self.seen_bad.add(event.ip)
            alerts.append({"type": "KNOWN_BAD_IP", "ip": event.ip, "time": event.time_str,
                           "detail": f"{event.ip} appears in the threat feed"})
        if event.action == "LOGIN_FAIL" and event.pw != "-":
            self.pw_total[event.ip] += 1
            if event.pw in self.common_pw:
                self.pw_hits[event.ip] += 1
            hits, total = self.pw_hits[event.ip], self.pw_total[event.ip]
            if hits >= self.pw_threshold and hits / total >= self.pw_ratio and event.ip not in self.pw_alerted:
                self.pw_alerted.add(event.ip)
                alerts.append({"type": "COMMON_PASSWORD_GUESSING", "ip": event.ip,
                               "time": event.time_str,
                               "detail": f"{event.ip} used common passwords in {hits} of {total} failed logins"})
        return alerts

if __name__ == "__main__":
    from ..generator import COMMON_PASSWORDS
    from ..parser import Event, parse_file

    # ---- unit tests ----
    bf = BloomFilter(1000, 0.01)
    words = [f"word{i}" for i in range(1000)]
    for w in words:
        bf.add(w)
    assert all(w in bf for w in words)          # no false negatives, ever
    print("Unit tests passed (no false negatives)")

    # ---- false-positive rate and memory ----
    N = 100_000
    leaked = [f"leak{i}" for i in range(N)]
    unseen = [f"other{i}" for i in range(N)]
    bf = BloomFilter(N, 0.01)
    t0 = time.perf_counter()
    for w in leaked:
        bf.add(w)
    t_build = time.perf_counter() - t0
    plain = set(leaked)

    t0 = time.perf_counter(); fp = sum(1 for w in unseen if w in bf); t_bloom = time.perf_counter() - t0
    t0 = time.perf_counter(); _ = sum(1 for w in unseen if w in plain); t_set = time.perf_counter() - t0
    set_bytes = sys.getsizeof(plain) + sum(sys.getsizeof(w) for w in plain)

    print(f"\nBloom filter: n={N}, target FP=1%, m={bf.m} bits, k={bf.k} hashes")
    print(f"  Measured false-positive rate: {fp / N * 100:.2f}%  (theory: {bf.expected_fp() * 100:.2f}%)")
    print(f"  Memory: bloom {bf.size_bytes() / 1024:.0f} KB vs set {set_bytes / 1024:.0f} KB "
          f"({set_bytes / bf.size_bytes():.1f}x smaller)")
    print(f"  Build: {t_build * 1000:.0f} ms | 100k lookups: bloom {t_bloom * 1000:.0f} ms, set {t_set * 1000:.0f} ms")
    assert fp / N < 0.02

    # ---- space vs false-positive trade-off ----
    print("\nTrade-off (n=100,000):")
    for p in (0.1, 0.01, 0.001, 0.0001):
        b = BloomFilter(N, p)
        print(f"  FP target {p * 100:>6.2f}%  ->  {b.size_bytes() / 1024:>6.0f} KB, k={b.k}")

    # ---- run on the real log ----
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample.log"
    events, bad = parse_file(path)

    # Simulated threat feed: 50k random IPs plus the 6 noisiest real attackers
    rng = random.Random(7)
    feed = [f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            for _ in range(50_000)]
    fails = Counter(e.ip for e in events if e.action == "LOGIN_FAIL")
    feed += [ip for ip, _ in fails.most_common(6)]
    bad_ips = BloomFilter(len(feed), 0.001)
    for ip in feed:
        bad_ips.add(ip)

    # Simulated leaked-password list: the common ones + 100k filler entries
    pw_list = list(COMMON_PASSWORDS) + [f"leak{i}" for i in range(100_000)]
    common_pw = BloomFilter(len(pw_list), 0.01)
    for pw in pw_list:
        common_pw.add(pw)

    det = ReputationDetector(bad_ips, common_pw)
    alerts = []
    for ev in events:
        alerts.extend(det.process(ev))
    print(f"\nReputation alerts on {len(events)} events: {len(alerts)}")
    print(" ", dict(Counter(a["type"] for a in alerts)))
    for a in alerts[:3]:
        print(" ", a)