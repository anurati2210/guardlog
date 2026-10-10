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