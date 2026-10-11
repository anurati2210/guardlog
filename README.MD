# GuardLog: Login Attack Defender

Reads authentication logs and flags brute-force bursts, scanning, attack payloads and known-bad
IPs, then tells small teams who to block first. Built in 24 hours for Grevix AfterCode.

## Problem
Small organisations and campus labs have logs but no monitoring. GuardLog turns raw logs into a
short, ranked list of attackers and what to do about them.

## DAA concepts
| Component | Algorithm | Time | Naive baseline |
|---|---|---|---|
| Brute-force detection | Sliding window (deque) | O(1) amortized per event | O(n) rescan per event |
| Out-of-order logs | Per-IP sorted insertion (bisect) | O(log m) on time, O(m) late | trusting arrival order |
| Top attackers | Min-heap of size k | O(n log k) | full sort, O(n log n) |
| Known-bad lookup | Bloom filter | O(k) per lookup, tiny memory | set of all items |
| Attack signatures | Aho-Corasick | O(n + matches), any number of patterns | one scan per pattern |

Benchmark plots are in `benchmarks/`.

## Challenge 1: out-of-order logs
Logs synced from a remote server arrive late and out of order, so the original window detector
raised false alarms (73.6% of alerts false with 20% of logs delayed up to 10 minutes).
The order-tolerant detector keeps failures sorted by event time and re-checks only affected
windows: [paste your new/old numbers here: attackers caught, false-positive rate, events/s].

## Run it
pip install streamlit matplotlib pandas
streamlit run app.py

## Project layout
guardlog/ (generator, parser, detectors/, ranking, engine, disorder, scenario, bench), app.py,
BUILDLOG.MD