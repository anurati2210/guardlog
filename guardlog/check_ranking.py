"""Check: busy legitimate IPs must not appear in the top-attackers ranking."""
from collections import defaultdict

from .engine import build_engine, build_filters
from .parser import parse_lines
from .scenario import batch_sync, make_scenario

lines, attackers, busy = make_scenario()
batch, _ = batch_sync(lines, 0.2, 600, 1)
events, _ = parse_lines(batch)
filters = build_filters()

for tolerant in (False, True):
    report = build_engine(filters, tolerant=tolerant).run(events, 20)
    ips = [row["ip"] for row in report["top"]]
    n_busy = sum(1 for ip in ips if ip in busy)
    n_att = sum(1 for ip in ips if ip in attackers)
    label = "order-tolerant" if tolerant else "original      "
    print(f"{label}: top-20 holds {n_att} attackers and {n_busy} busy legitimate IPs")
    if tolerant:
        why = defaultdict(set)
        for a in report["alerts"]:
            if a["ip"] in busy:
                why[a["ip"]].add(a["type"])
        for ip, types in sorted(why.items()):
            print("   busy IP", ip, "raised:", ", ".join(sorted(types)))
        assert n_busy == 0, "a busy legitimate IP is still being ranked"
print("Ranking check passed")