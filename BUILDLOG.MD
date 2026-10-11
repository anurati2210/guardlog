# Build Log

## Hour 0: Setup
- AI did:
- I decided: Python + Streamlit, engine separate from UI so challenge cards only touch one layer
- I rejected: databases, user accounts, real network capture (out of scope for 24 hours)

- generator uses a seed so benchmarks are repeatable; path is  last field because payloads contain spaces.
- ## Hour 1-2: Parser
- AI did: wrote the generator and parser boilerplate
- I decided: timestamps stored as epoch floats for fast window math; malformed lines counted and skipped instead of crashing

## Hour 2-4: Sliding window
- AI did: boilerplate for deque logic and unit tests
- I decided: 60s window, threshold 10, 60s cooldown to avoid alert floods; naive version kept for benchmarking
- I rejected: fixed time buckets (misses attacks that straddle a bucket boundary)

## Hour 5-6: Bloom filter
- AI did: boilerplate, unit tests, benchmark printing
- I decided: 1% false-positive for passwords, 0.1% for IPs; alert only after 3 common-password hits so a false positive can't trigger an alert alone; double hashing instead of k separate hash functions
- I rejected: storing the whole password list in a set (memory), and using it as the only defence (false positives)

## Hour 6-7: Signature matcher
- AI did: boilerplate, unit tests, benchmark printing
- I decided: Aho-Corasick as the default because signature lists grow; lowercase matching; one alert per (IP, pattern)
- I rejected: Python's built-in `in` as the "algorithm" (hides the DAA work); regex alternation (hard to analyse, can backtrack badly)

## Hour 7-8: Engine and dashboard (baseline)
- AI did: Streamlit layout and boilerplate
- I decided: one-pass engine over a shared detector interface; template advice instead of an API so the demo never fails offline; Bloom filters cached because they are read-only
- I rejected: database storage, live log tailing (not needed for the baseline)

## Benchmarks
- AI did: benchmark script and plotting boilerplate
- I decided: compare each algorithm to a naive baseline on growing input sizes; report results honestly, including where the naive version is competitive
- I rejected: 1M-line naive window runs (too slow to be useful)

## Challenge Card 1: out-of-order logs
- Analysis: only the sliding-window detector depends on order; ranking, Bloom filter and signatures are order-independent
- I decided: sorted per-IP insertion with retroactive burst check (alerts fire on arrival, no buffering); pruning by max lateness; regression test against the old detector on in-order logs
- I rejected: reorder buffer with watermark (would delay every alert by up to 10 minutes, which breaks near-real-time)


## Challenge Card 1: baseline measurement
- AI did: scenario generator and scoring boilerplate
- I decided: model the card as bulk log sync (delayed lines arrive as a batch), not just random jitter, because jitter alone did not break the old detector (0 legit IPs flagged); added busy-but-benign IPs (max 9 failures/60 s) so false positives are measurable
- Finding: old detector's deque stops popping when old-timestamp batches arrive behind newer events, so a batch counts as one burst


## Challenge Card 1: order-tolerant detector
- AI did: boilerplate, unit tests, evaluation table
- I decided: per-IP sorted failure times with insertion at the true event time and a re-check of only the windows containing the new line; fast path for on-time lines; pruning by max_lateness (900 s, above the 600 s requirement) so memory stays bounded; cooldown in event time; old detector kept for regression and comparison
- I rejected: reorder buffer with watermark (delays every alert by up to 10 minutes, breaks near-real-time); trusting arrival order; widening the threshold to hide false positives (would miss real attacks)
- Result: false-positive rate reduced from 49% (jitter) and 74% (batch) to below 5% (see table), all 12 attackers still caught, identical alerts on in-order logs


## Challenge Card 1: integration
- AI did: dashboard layout and boilerplate
- I decided: order-tolerant detector is the engine default (identical alerts on in-order logs, regression-tested); dashboard runs both detectors on the same delayed logs so the comparison is side by side; the delay is simulated as a bulk log sync because that is how the card says logs arrive; headline metric is false-positive ALERT rate, with IP-level rate reported alongside it
- Trade-off: order-tolerant detector is about 2.7x slower than the original (about 885k vs 2.4M events/s) but still far above real log volumes, and it removes the false alerts
- I rejected: reorder buffer (adds up to 10 minutes of alert delay)


## Reputation detector fix
- Finding: Bloom filter (1% false positives) plus a 3-hit threshold still raised alerts on busy legitimate IPs, because ~270 failed attempts means ~2.7 false hits on average
- I decided: password-guessing alert needs both 3+ hits AND at least 50% of the IP's failed attempts to be common passwords (real guessers use them almost every time, typos hit only by chance)
- I rejected: raising the hit threshold (just moves the problem to busier IPs); lowering the Bloom filter false-positive rate (costs more memory and still never reaches zero)