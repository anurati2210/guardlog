"""Attack-signature matching: naive vs KMP vs Aho-Corasick (all pure Python, so the comparison is fair)."""
import random
import sys
import time
from collections import Counter, deque

from .base import Detector

DEFAULT_SIGNATURES = [
    "../../etc/passwd", "/etc/shadow", "union select", "' or '1'='1", "; drop table",
    "<script>", "cmd.exe", "/bin/sh", "xp_cmdshell", "base64_decode(", "wget http", "${jndi:",
]


# ---------- 1) Naive: try every start position ----------
def naive_contains(text, pat):
    n, m = len(text), len(pat)
    if m == 0:
        return False
    for i in range(n - m + 1):
        j = 0
        while j < m and text[i + j] == pat[j]:
            j += 1
        if j == m:
            return True
    return False


# ---------- 2) KMP: never move backwards in the text ----------
def build_failure(pat):
    """f[i] = length of the longest proper prefix of pat[:i+1] that is also its suffix."""
    f = [0] * len(pat)
    k = 0
    for i in range(1, len(pat)):
        while k and pat[i] != pat[k]:
            k = f[k - 1]
        if pat[i] == pat[k]:
            k += 1
        f[i] = k
    return f


def kmp_contains(text, pat, f=None):
    if not pat:
        return False
    if f is None:
        f = build_failure(pat)
    k = 0
    for ch in text:
        while k and ch != pat[k]:
            k = f[k - 1]
        if ch == pat[k]:
            k += 1
        if k == len(pat):
            return True
    return False


# ---------- 3) Aho-Corasick: all patterns in ONE pass ----------
class AhoCorasick:
    def __init__(self, patterns):
        self.goto = [{}]    # trie edges
        self.fail = [0]     # failure links
        self.out = [[]]     # patterns that end at each node
        for p in patterns:
            node = 0
            for ch in p:
                nxt = self.goto[node].get(ch)
                if nxt is None:
                    self.goto.append({})
                    self.fail.append(0)
                    self.out.append([])
                    nxt = len(self.goto) - 1
                    self.goto[node][ch] = nxt
                node = nxt
            self.out[node].append(p)
        # breadth-first pass builds the failure links
        q = deque(self.goto[0].values())
        while q:
            node = q.popleft()
            for ch, nxt in self.goto[node].items():
                f = self.fail[node]
                while f and ch not in self.goto[f]:
                    f = self.fail[f]
                self.fail[nxt] = self.goto[f].get(ch, 0)
                self.out[nxt] = self.out[nxt] + self.out[self.fail[nxt]]
                q.append(nxt)

    def search(self, text):
        """Return the set of patterns that occur in text."""
        found, node = set(), 0
        for ch in text:
            while node and ch not in self.goto[node]:
                node = self.fail[node]
            node = self.goto[node].get(ch, 0)
            if self.out[node]:
                found.update(self.out[node])
        return found


# ---------- Detector ----------
class SignatureDetector(Detector):
    name = "signature"

    def __init__(self, patterns=None, method="aho"):
        self.patterns = [p.lower() for p in (patterns or DEFAULT_SIGNATURES)]
        self.method = method
        if method == "kmp":
            self.tables = {p: build_failure(p) for p in self.patterns}
        elif method == "aho":
            self.automaton = AhoCorasick(self.patterns)
        elif method != "naive":
            raise ValueError("method must be naive, kmp or aho")
        self.seen = set()       # (ip, pattern) pairs already alerted
        self.hits = Counter()   # signature hits per IP (feeds the ranking later)

    def _find(self, text):
        if self.method == "aho":
            return self.automaton.search(text)
        if self.method == "kmp":
            return {p for p in self.patterns if kmp_contains(text, p, self.tables[p])}
        return {p for p in self.patterns if naive_contains(text, p)}

    def process(self, event):
        alerts = []
        for p in sorted(self._find(event.path.lower())):
            self.hits[event.ip] += 1
            if (event.ip, p) in self.seen:
                continue
            self.seen.add((event.ip, p))
            alerts.append({"type": "SIGNATURE_MATCH", "ip": event.ip, "time": event.time_str,
                           "pattern": p, "detail": f"{event.ip} sent attack signature '{p}'"})
        return alerts


def run(detector, events):
    alerts = []
    for ev in events:
        alerts.extend(detector.process(ev))
    return alerts


if __name__ == "__main__":
    from ..parser import parse_file

    # ---- unit tests ----
    assert build_failure("ababaca") == [0, 0, 1, 2, 3, 0, 1]
    assert kmp_contains("xxabababacaxx", "ababaca") and not kmp_contains("abababab", "ababaca")
    assert naive_contains("hello world", "o w") and not naive_contains("hello", "xyz")
    ac = AhoCorasick(["he", "she", "his", "hers"])
    assert ac.search("ushers") == {"he", "she", "hers"}          # overlapping matches
    assert ac.search("xyz") == set()
    print("Unit tests passed")

    # ---- real log: all three methods must give the same alerts ----
    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample.log"
    events, bad = parse_file(path)
    results = {}
    for method in ("naive", "kmp", "aho"):
        d = SignatureDetector(method=method)
        t0 = time.perf_counter()
        results[method] = run(d, events)
        print(f"{method:<6} {len(results[method])} alerts in {(time.perf_counter() - t0) * 1000:.0f} ms")
    print("Same alerts from all three:", results["naive"] == results["kmp"] == results["aho"])
    for a in results["aho"][:3]:
        print(" ", a)

    # ---- scaling benchmark: more patterns, same text (takes ~10 seconds) ----
    rng = random.Random(3)
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    base_text = "".join(rng.choices(alphabet, k=40000))
    print("\nScaling benchmark: 40,000-character text")
    print(f"{'patterns':>9} {'naive':>10} {'KMP':>10} {'Aho-Corasick':>14}")
    for count in (5, 25, 100):
        pats = ["".join(rng.choices(alphabet, k=rng.randint(5, 8))) for _ in range(count)]
        text = base_text + "".join(pats[:3])        # plant 3 patterns so there is something to find
        t0 = time.perf_counter(); r1 = {p for p in pats if naive_contains(text, p)}; t1 = time.perf_counter() - t0
        t0 = time.perf_counter(); r2 = {p for p in pats if kmp_contains(text, p)}; t2 = time.perf_counter() - t0
        t0 = time.perf_counter(); r3 = AhoCorasick(pats).search(text); t3 = time.perf_counter() - t0
        assert r1 == r2 == r3
        print(f"{count:>9} {t1 * 1000:>8.0f}ms {t2 * 1000:>8.0f}ms {t3 * 1000:>12.0f}ms")