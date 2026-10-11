import pandas as pd
import streamlit as st

from guardlog.engine import build_engine, build_filters
from guardlog.generator import generate_logs, get_attacker_ips
from guardlog.parser import parse_lines
from guardlog.scenario import batch_sync, make_scenario, score
from guardlog.detectors.window import SlidingWindowDetector, run as run_detector

st.set_page_config(page_title="GuardLog", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_filters(seed):
    return build_filters(seed)


@st.cache_data
def make_data(n_lines, seed, with_busy, pct, interval_min):
    if with_busy:
        lines, attackers, busy = make_scenario(n_lines, seed)
    else:
        lines = generate_logs(n_lines, seed)
        attackers, busy = set(get_attacker_ips(seed)), set()
    stats = None
    if pct > 0:
        lines, stats = batch_sync(lines, frac=pct / 100, interval=interval_min * 60, seed=1)
    return lines, attackers, busy, stats


st.title("🛡️ GuardLog")
st.caption("Login attack defender: finds brute-force, scanning and attack payloads in your logs.")

with st.sidebar:
    st.header("Log source")
    source = st.radio("Choose data", ["Generate sample logs", "Upload a log file"])
    seed = 42
    uploaded = None
    with_busy = False
    if source == "Generate sample logs":
        n_lines = st.slider("Lines", 1000, 200000, 10000, step=1000)
        seed = int(st.number_input("Seed", value=42, step=1))
        with_busy = st.checkbox("Add busy legitimate IPs (to test false positives)", value=False)
    else:
        uploaded = st.file_uploader("Log file (.log or .txt)", type=["log", "txt"])

    st.header("Log sync delay (Challenge 1)")
    pct = st.slider("Share of logs delayed (%)", 0, 50, 0, step=5)
    interval_min = st.slider("Sync interval / max delay (minutes)", 1, 15, 10)
    handling = st.radio("Out-of-order handling", ["Order-tolerant (new)", "Original (assumes sorted)"])

    st.header("Detection settings")
    window = st.slider("Window (seconds)", 10, 300, 60, step=10)
    threshold = st.slider("Failed logins to raise an alert", 3, 50, 10)
    top_k = st.slider("Top attackers to show", 3, 20, 10)

if source == "Generate sample logs":
    lines, attackers, busy, stats = make_data(int(n_lines), seed, with_busy, pct, interval_min)
elif uploaded is not None:
    lines = uploaded.getvalue().decode("utf-8", errors="replace").splitlines()
    attackers, busy, stats = set(), set(), None
    if pct > 0:
        lines, stats = batch_sync(lines, frac=pct / 100, interval=interval_min * 60, seed=1)
else:
    st.info("Upload a log file in the sidebar, or switch to generated sample logs.")
    st.stop()

events, malformed = parse_lines(lines)
if not events:
    st.error("No valid log lines found. Expected: timestamp ip=... user=... action=... pw=... path=...")
    st.stop()

# Run both versions on the same (possibly delayed) logs, so they can be compared side by side
filters = get_filters(seed)
runs = {}
for tol in (False, True):
    eng = build_engine(filters, window, threshold, tol)
    runs[tol] = (eng, eng.run(events, top_k))
use_tolerant = handling.startswith("Order-tolerant")
engine, report = runs[use_tolerant]
alerts = report["alerts"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analysed", f"{len(events):,}")
c2.metric("Alerts", len(alerts))
c3.metric("Suspicious IPs", len({a["ip"] for a in alerts}))
c4.metric("Analysis time", f"{report['seconds'] * 1000:.0f} ms")
if malformed:
    st.caption(f"{malformed} malformed lines were skipped.")
if stats:
    st.caption(f"Log sync simulation: {stats['delayed']:,} lines delayed, {stats['out_of_order']:,} arrived "
               f"out of order, worst lateness {stats['max_lateness_s']} s.")

st.subheader("Out-of-order handling: original vs order-tolerant")
reachable = set()
if attackers:
    # Attackers that a perfectly sorted log would let the brute-force detector catch.
    # Scan-only and payload-only attackers never produce failed logins, so they are not its targets.
    reference = run_detector(SlidingWindowDetector(window=window, threshold=threshold),
                             sorted(events, key=lambda e: e.ts))
    reachable = {a["ip"] for a in reference} & attackers
rows, tolerant_ok = [], None
for tol, label in ((False, "Original (assumes sorted logs)"), (True, "Order-tolerant (new)")):
    brute = [a for a in runs[tol][1]["alerts"] if a["type"] == "BRUTE_FORCE"]
    row = {"Detector": label, "Brute-force alerts": len(brute)}
    if attackers:
        s = score(brute, attackers, busy)
        caught = len({a["ip"] for a in brute} & reachable)
        row["Attackers caught"] = f"{caught}/{len(reachable)}"
        row["Legit IPs flagged"] = s["legit_ips_flagged"]
        row["False-positive alerts"] = f"{s['fp_alert_rate'] * 100:.1f}%"
        if tol:
            tolerant_ok = s["fp_alert_rate"] < 0.05 and caught >= len(reachable)
    rows.append(row)
st.dataframe(pd.DataFrame(rows), hide_index=True)
if attackers:
    st.caption("Attackers caught is measured against the attackers a perfectly sorted log lets this detector catch.")
if tolerant_ok is True:
    st.success("Order-tolerant detector: false positives under 5% and every attacker caught.")
elif tolerant_ok is False:
    st.warning("Order-tolerant detector missed the 5% false-positive target or an attacker on this data.")
if not attackers:
    st.caption("False-positive rates need ground truth, so they are shown for generated sample logs only.")

if not alerts:
    st.success("No attacks detected in this log.")
    st.stop()

left, right = st.columns(2)
with left:
    st.subheader("Top attackers")
    st.bar_chart(pd.DataFrame(report["top"]).set_index("ip"))
with right:
    st.subheader("Alerts by type")
    st.bar_chart(pd.DataFrame({"alerts": report["alert_counts"]}))

st.subheader("What to do first")
for row in report["top"][:3]:
    first = next((a for a in alerts if a["ip"] == row["ip"]), None)
    if first:
        st.markdown(f"**{row['ip']}** (score {row['score']}): {first['advice']}")
    else:
        st.markdown(f"**{row['ip']}** (score {row['score']}): suspicious activity, no alert rule fired yet.")

st.subheader("All alerts")
types = sorted(report["alert_counts"])
chosen = st.multiselect("Filter by type", types, default=types)
df = pd.DataFrame(alerts)
shown = df[df["type"].isin(chosen)]
columns = [c for c in ["time", "severity", "type", "ip", "detail"] if c in shown.columns]
st.dataframe(shown[columns])

blocklist = "\n".join(sorted({a["ip"] for a in alerts}))
st.download_button("Download blocklist (.txt)", blocklist, "blocklist.txt")