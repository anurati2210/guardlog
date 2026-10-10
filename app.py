import pandas as pd
import streamlit as st

from guardlog.engine import build_engine, build_filters
from guardlog.generator import generate_logs
from guardlog.parser import parse_lines

st.set_page_config(page_title="GuardLog", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_filters(seed):
    return build_filters(seed)


@st.cache_data
def make_logs(n_lines, seed):
    return generate_logs(n_lines, seed)


st.title("🛡️ GuardLog")
st.caption("Login attack defender: finds brute-force, scanning and attack payloads in your logs.")

with st.sidebar:
    st.header("Log source")
    source = st.radio("Choose data", ["Generate sample logs", "Upload a log file"])
    seed = 42
    uploaded = None
    if source == "Generate sample logs":
        n_lines = st.slider("Lines", 1000, 200000, 10000, step=1000)
        seed = int(st.number_input("Seed", value=42, step=1))
    else:
        uploaded = st.file_uploader("Log file (.log or .txt)", type=["log", "txt"])
    st.header("Detection settings")
    window = st.slider("Window (seconds)", 10, 300, 60, step=10)
    threshold = st.slider("Failed logins to raise an alert", 3, 50, 10)
    top_k = st.slider("Top attackers to show", 3, 20, 10)

if source == "Generate sample logs":
    lines = make_logs(int(n_lines), seed)
elif uploaded is not None:
    lines = uploaded.getvalue().decode("utf-8", errors="replace").splitlines()
else:
    st.info("Upload a log file in the sidebar, or switch to generated sample logs.")
    st.stop()

events, malformed = parse_lines(lines)
if not events:
    st.error("No valid log lines found. Expected: timestamp ip=... user=... action=... pw=... path=...")
    st.stop()

report = build_engine(get_filters(seed), window, threshold).run(events, top_k)
alerts = report["alerts"]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events analysed", f"{len(events):,}")
c2.metric("Alerts", len(alerts))
c3.metric("Suspicious IPs", len({a["ip"] for a in alerts}))
c4.metric("Analysis time", f"{report['seconds'] * 1000:.0f} ms")
if malformed:
    st.caption(f"{malformed} malformed lines were skipped.")

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