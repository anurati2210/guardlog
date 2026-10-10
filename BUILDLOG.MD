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
