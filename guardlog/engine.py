"""Engine: runs every detector over the events and builds one report."""
import os
import random
import sys
import time
from collections import Counter

from .detectors.bloom import BloomFilter, ReputationDetector
from .detectors.signature import SignatureDetector
from .detectors.window import SlidingWindowDetector
from .generator import COMMON_PASSWORDS, get_attacker_ips
from .ranking import AttackerTracker

SEVERITY = {"BRUTE_FORCE": "High", "SIGNATURE_MATCH": "High",
            "KNOWN_BAD_IP": "Medium", "COMMON_PASSWORD_GUESSING": "Medium"}

ADVICE = {
    "BRUTE_FORCE": "Block {ip} at the firewall and add account lockout or rate limiting on /login.",
    "SIGNATURE_MATCH": "Block {ip} and review the targeted endpoint for the '{pattern}' attack.",
    "KNOWN_BAD_IP": "{ip} is in the threat feed. Block it and check what else it touched.",
    "COMMON_PASSWORD_GUESSING": "{ip} is guessing common passwords. Enforce a strong-password policy and MFA.",
}


def explain(alert):
    """Template explanation (no API needed, so the demo never depends on the internet)."""
    return ADVICE.get(alert["type"], "Investigate {ip}.").format(
        ip=alert["ip"], pattern=alert.get("pattern", ""))


def simulated_threat_feed(seed=42, n_random=50000):
    """Demo threat feed: random IPs plus 6 of the generator's attacker IPs."""
    rng = random.Random(seed + 1)
    feed = [f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            for _ in range(n_random)]
    return feed + get_attacker_ips(seed)[:6]


def load_passwords(path="data/common_passwords.txt", filler=20000):
    """Common-password list. Uses data/common_passwords.txt if you add one, else simulated filler."""
    pw = list(COMMON_PASSWORDS)
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            pw += [line.strip().lower() for line in f if line.strip()]
    else:
        pw += [f"leak{i}" for i in range(filler)]
    return pw


def build_filters(seed=42):
    """Build the two Bloom filters once. They are read-only, so runs can share them."""
    feed = simulated_threat_feed(seed)
    passwords = load_passwords()
    bad_ips = BloomFilter(len(feed), 0.001)
    for ip in feed:
        bad_ips.add(ip)
    common_pw = BloomFilter(len(passwords), 0.01)
    for pw in passwords:
        common_pw.add(pw)
    return bad_ips, common_pw


class Engine:
    def __init__(self, detectors):
        self.detectors = detectors
        self.tracker = AttackerTracker()

    def run(self, events, top_k=10):
        t0 = time.perf_counter()
        alerts = []
        for ev in events:                       # one pass over the data
            self.tracker.observe(ev)
            for d in self.detectors:
                alerts.extend(d.process(ev))
        for d in self.detectors:                # detectors that count hits per IP feed the ranking
            for ip, c in getattr(d, "hits", {}).items():
                self.tracker.add(ip, c)
        for a in alerts:
            a["severity"] = SEVERITY.get(a["type"], "Low")
            a["advice"] = explain(a)
        return {
            "alerts": alerts,
            "alert_counts": dict(Counter(a["type"] for a in alerts)),
            "top": self.tracker.top(top_k),
            "n_events": len(events),
            "seconds": time.perf_counter() - t0,
        }


def build_engine(filters, window=60, threshold=10):
    bad_ips, common_pw = filters
    return Engine([
        SlidingWindowDetector(window=window, threshold=threshold),
        SignatureDetector(method="aho"),
        ReputationDetector(bad_ips, common_pw),
    ])



if __name__ == "__main__":
    from .parser import parse_file

    path = sys.argv[1] if len(sys.argv) > 1 else "data/sample.log"
    events, bad = parse_file(path)
    report = build_engine(build_filters()).run(events)
    print(f"{report['n_events']} events analysed in {report['seconds'] * 1000:.0f} ms")
    print("Alerts by type:", report["alert_counts"])
    print("Top attackers:")
    for row in report["top"][:5]:
        print(f"  {row['ip']:<18} score={row['score']}")
    print("Example:", report["alerts"][0])
    print("Engine OK")