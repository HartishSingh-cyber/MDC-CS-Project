import streamlit as st
from streamlit_autorefresh import st_autorefresh
from scapy.all import sniff, IP, TCP, UDP
from collections import deque
from threading import Thread, Lock
from datetime import datetime
import time

st.set_page_config(page_title="AI-IDS Security Monitor", layout="wide")
st.title("AI-IDS: Live Security Monitor")
st.caption("Live network monitoring and demonstration alerts.")

if "packets" not in st.session_state:
    st.session_state.packets = deque(maxlen=1000)
    st.session_state.alerts = deque(maxlen=200)
    st.session_state.lock = Lock()
    st.session_state.started = False
    st.session_state.packet_times = {}

packets = st.session_state.packets
alerts = st.session_state.alerts
lock = st.session_state.lock
packet_times = st.session_state.packet_times

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

        record = {
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Source": src,
            "Destination": packet[IP].dst,
            "Protocol": protocol,
            "Size (bytes)": len(packet),
            "Source packets / 10 sec": rate,
            "Status": status
        }
        packets.appendleft(record)

        if rate == 100:
            alerts.appendleft({
                "Time": record["Time"],
                "Source IP": src,
                "Alert": "100 packets observed within 10 seconds",
                "Status": "Needs investigation"
            })

def start_capture():
    try:
        sniff(prn=capture_packet, store=False)
    except Exception as e:
        with lock:
            alerts.appendleft({
                "Time": datetime.now().strftime("%H:%M:%S"),
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

tcp_count = sum(p["Protocol"] == "TCP" for p in recent)
udp_count = sum(p["Protocol"] == "UDP" for p in recent)

a, b, c = st.columns(3)
a.metric("Packets stored", len(recent))
b.metric("TCP packets stored", tcp_count)
c.metric("UDP packets stored", udp_count)

st.subheader("Security status")
if alert_history:
    st.warning(f"{len(alert_history)} alert record(s) stored. Review them below.")
else:
    st.success("No high packet-rate alerts recorded yet.")

st.subheader("Recent live traffic")
if recent:
    st.dataframe(recent, use_container_width=True, hide_index=True)
else:
    st.info("Waiting for packets. Open a website to generate activity.")

st.subheader("Alert history")
if alert_history:
    st.dataframe(alert_history, use_container_width=True, hide_index=True)
else:
    st.info("Alerts will appear here if a source reaches the demonstration threshold.")

st.subheader("Top source packet rates")
if rates:
    st.dataframe(
        [{"Source IP": ip, "Packets in last 10 sec": count}
         for ip, count in sorted(rates.items(), key=lambda item: item[1], reverse=True)[:10]],
        use_container_width=True,
        hide_index=True
    )

st.caption(
    "Demonstration threshold: 100 packets from one source in 10 seconds. "
    "This is a heuristic, not proof of an attack. Alert history lasts for this "
    "Streamlit session and is not saved to disk."
)
