"""Benchmarks: naive vs optimized for each DAA piece. Saves plots to benchmarks/."""
import os
import random
import time
from collections import Counter

import matplotlib
matplotlib.use("Agg")   # draw to files, no pop-up windows
import matplotlib.pyplot as plt

from .detectors.bloom import BloomFilter
from .detectors.signature import AhoCorasick, kmp_contains, naive_contains
from .detectors.window import NaiveWindowDetector, SlidingWindowDetector, run
from .generator import generate_logs
from .parser import parse_lines
from .ranking import top_k_heap, top_k_naive

OUT = "benchmarks"


def timed(fn):
    t0 = time.perf_counter()
    result = fn()
    return result, time.perf_counter() - t0


def save(name):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"  saved {path}")


def bench_window():
    print("\n1) Sliding window (deque) vs naive rescan")
    sizes = [10_000, 20_000, 40_000, 80_000, 160_000]
    fast_t, slow_t = [], []
    for n in sizes:
        events, _ = parse_lines(generate_logs(n, seed=42))
        a, tf = timed(lambda: run(SlidingWindowDetector(), events))
        b, ts = timed(lambda: run(NaiveWindowDetector(), events))
        fast_t.append(tf * 1000)
        slow_t.append(ts * 1000)
        print(f"  n={n:>8,}  window {tf * 1000:>8.0f} ms   naive {ts * 1000:>8.0f} ms   same alerts: {a == b}")
    plt.figure(figsize=(6, 4))
    plt.plot(sizes, slow_t, "o-", label="Naive rescan")
    plt.plot(sizes, fast_t, "o-", label="Sliding window (deque)")
    plt.xlabel("Log lines")
    plt.ylabel("Time (ms)")
    plt.title("Brute-force detection: time vs input size")
    plt.legend()
    plt.grid(alpha=0.3)
    save("window.png")


def bench_topk():
    print("\n2) Top-k ranking: heap vs full sort (k = 10)")
    sizes = [10_000, 100_000, 300_000, 1_000_000]
    heap_t, sort_t = [], []
    rng = random.Random(1)
    for n in sizes:
        counts = Counter({f"ip{i}": rng.randint(1, 1_000_000) for i in range(n)})
        a, th = timed(lambda: top_k_heap(counts, 10))
        b, ts = timed(lambda: top_k_naive(counts, 10))
        heap_t.append(th * 1000)
        sort_t.append(ts * 1000)
        print(f"  IPs={n:>9,}  heap {th * 1000:>8.0f} ms   sort {ts * 1000:>8.0f} ms   same result: {a == b}")
    plt.figure(figsize=(6, 4))
    plt.plot(sizes, sort_t, "o-", label="Full sort  O(n log n)")
    plt.plot(sizes, heap_t, "o-", label="Min-heap  O(n log k)")
    plt.xlabel("Distinct IPs")
    plt.ylabel("Time (ms)")
    plt.title("Top-10 attackers: time vs number of IPs")
    plt.legend()
    plt.grid(alpha=0.3)
    save("topk.png")


def bench_signature():
    print("\n3) Signature matching: naive vs KMP vs Aho-Corasick (20,000-character text)")
    rng = random.Random(3)
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    base = "".join(rng.choices(alphabet, k=20000))
    counts = [5, 25, 100, 200]
    t_naive, t_kmp, t_aho = [], [], []
    for c in counts:
        pats = ["".join(rng.choices(alphabet, k=rng.randint(5, 8))) for _ in range(c)]
        text = base + "".join(pats[:3])      # plant 3 patterns so there is something to find
        r1, t1 = timed(lambda: {p for p in pats if naive_contains(text, p)})
        r2, t2 = timed(lambda: {p for p in pats if kmp_contains(text, p)})
        r3, t3 = timed(lambda: AhoCorasick(pats).search(text))
        assert r1 == r2 == r3
        t_naive.append(t1 * 1000)
        t_kmp.append(t2 * 1000)
        t_aho.append(t3 * 1000)
        print(f"  patterns={c:>4}  naive {t1 * 1000:>7.0f} ms   KMP {t2 * 1000:>7.0f} ms   Aho-Corasick {t3 * 1000:>7.0f} ms")
    plt.figure(figsize=(6, 4))
    plt.plot(counts, t_naive, "o-", label="Naive")
    plt.plot(counts, t_kmp, "o-", label="KMP (one scan per pattern)")
    plt.plot(counts, t_aho, "o-", label="Aho-Corasick (one scan total)")
    plt.xlabel("Number of signatures")
    plt.ylabel("Time (ms)")
    plt.title("Signature matching: time vs number of patterns")
    plt.legend()
    plt.grid(alpha=0.3)
    save("signature.png")


def bench_bloom():
    print("\n4) Bloom filter: memory vs false-positive rate (n = 100,000 items)")
    n = 100_000
    items = [f"leak{i}" for i in range(n)]
    unseen = [f"other{i}" for i in range(n)]
    plain = set(items)
    import sys
    set_kb = (sys.getsizeof(plain) + sum(sys.getsizeof(w) for w in plain)) / 1024
    targets = [0.1, 0.01, 0.001, 0.0001]
    mem, measured = [], []
    for p in targets:
        bf = BloomFilter(n, p)
        for w in items:
            bf.add(w)
        fp = sum(1 for w in unseen if w in bf) / n
        mem.append(bf.size_bytes() / 1024)
        measured.append(fp * 100)
        print(f"  target {p * 100:>7.3f}%  measured {fp * 100:>7.3f}%  memory {bf.size_bytes() / 1024:>6.0f} KB  (k={bf.k})")
    print(f"  Python set of the same items: {set_kb:,.0f} KB")
    plt.figure(figsize=(6, 4))
    labels = [f"{p * 100:g}%" for p in targets]
    plt.bar(labels, mem, label="Bloom filter")
    plt.axhline(set_kb, color="red", linestyle="--", label=f"Python set ({set_kb:,.0f} KB)")
    plt.xlabel("False-positive rate target")
    plt.ylabel("Memory (KB)")
    plt.title("Bloom filter: memory vs false-positive rate")
    plt.legend()
    save("bloom.png")


if __name__ == "__main__":
    print("Running benchmarks (takes about 1 to 2 minutes)...")
    bench_window()
    bench_topk()
    bench_signature()
    bench_bloom()
    print("\nDone. Plots are in the benchmarks/ folder.")