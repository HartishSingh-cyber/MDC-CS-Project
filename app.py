import streamlit as st
from streamlit_autorefresh import st_autorefresh
from scapy.all import sniff, IP, TCP, UDP
from collections import deque
from threading import Thread, Lock
from datetime import datetime
import time
import csv
import os

st.set_page_config(page_title="AI-IDS Security Monitor", layout="wide")
st.title("AI-IDS: Live Security Monitor")
st.caption("Live packet monitoring with alert history and CSV logging.")

ALERT_FILE = "security_alerts.csv"
ALERT_FIELDS = ["Time", "Source IP", "Alert", "Status"]

if not os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, "w", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=ALERT_FIELDS).writeheader()

if "packets" not in st.session_state:
    st.session_state.packets = deque(maxlen=1000)
    st.session_state.alerts = deque(maxlen=200)
    st.session_state.lock = Lock()
    st.session_state.started = False
    st.session_state.packet_times = {}
    st.session_state.alerted_ips = set()

packets = st.session_state.packets
alerts = st.session_state.alerts
lock = st.session_state.lock
packet_times = st.session_state.packet_times
alerted_ips = st.session_state.alerted_ips

def capture_packet(packet):
    if IP not in packet:
        return

    now = time.time()
    src = packet[IP].src

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    else:
        protocol = "Other"

    with lock:
        times = packet_times.setdefault(src, deque())
        times.append(now)

        while times and now - times[0] > 10:
            times.popleft()

        rate = len(times)
        status = "WARNING: High packet rate" if rate >= 100 else "Normal"

        packets.appendleft({
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Source": src,
            "Destination": packet[IP].dst,
            "Protocol": protocol,
            "Size (bytes)": len(packet),
            "Source packets / 10 sec": rate,
            "Status": status
        })

        if rate >= 100 and src not in alerted_ips:
            alerted_ips.add(src)
            alert = {
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Source IP": src,
                "Alert": "100 or more packets within 10 seconds",
                "Status": "Needs investigation"
            }
            alerts.appendleft(alert)

            try:
                with open(ALERT_FILE, "a", newline="", encoding="utf-8") as f:
                    csv.DictWriter(f, fieldnames=ALERT_FIELDS).writerow(alert)
            except OSError:
                pass

def start_capture():
    try:
        sniff(prn=capture_packet, store=False)
    except Exception as e:
        with lock:
            alerts.appendleft({
                "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Source IP": "System",
                "Alert": str(e)[:150],
                "Status": "Capture error"
            })

if not st.session_state.started:
    st.session_state.started = True
    Thread(target=start_capture, daemon=True).start()

st_autorefresh(interval=1000, key="live_refresh")

with lock:
    recent = list(packets)
    alert_history = list(alerts)
    rates = {ip: len(times) for ip, times in packet_times.items()}

a, b, c = st.columns(3)
a.metric("Packets stored", len(recent))
b.metric("TCP packets", sum(p["Protocol"] == "TCP" for p in recent))
c.metric("UDP packets", sum(p["Protocol"] == "UDP" for p in recent))

st.subheader("Security status")
if alert_history:
    st.warning(f"{len(alert_history)} alert record(s) in this session.")
else:
    st.success("No high packet-rate alerts recorded in this session.")

st.subheader("Recent live traffic")
if recent:
    st.dataframe(recent, use_container_width=True, hide_index=True)
else:
    st.info("Waiting for packets. Open a website to generate traffic.")

st.subheader("Alert history")
if alert_history:
    st.dataframe(alert_history, use_container_width=True, hide_index=True)
else:
    st.info("No alerts yet. The threshold is for demonstration only.")

st.subheader("Saved alert log")
if os.path.exists(ALERT_FILE):
    with open(ALERT_FILE, "rb") as f:
        st.download_button(
            "Download security_alerts.csv",
            data=f.read(),
            file_name="security_alerts.csv",
            mime="text/csv"
        )
    st.caption(f"Log file location: {os.path.abspath(ALERT_FILE)}")

st.subheader("Top source packet rates")
if rates:
    st.dataframe(
        [{"Source IP": ip, "Packets in last 10 sec": count}
         for ip, count in sorted(rates.items(), key=lambda item: item[1], reverse=True)[:10]],
        use_container_width=True,
        hide_index=True
    )

st.caption(
    "Alerts are logged once per source IP per session when the source reaches "
    "100 packets within 10 seconds. This heuristic is not proof of an attack. "
    "The CSV persists across restarts; the live packet and alert tables do not."
)
