from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
from datetime import datetime

packet_count = 0
protocols = Counter()

def process_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1
    src = packet[IP].src
    dst = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
    elif UDP in packet:
        protocol = "UDP"
    elif ICMP in packet:
        protocol = "ICMP"
    else:
        protocol = "Other"

    protocols[protocol] += 1

    print(
        f"{datetime.now().strftime('%H:%M:%S')} | "
        f"Packet #{packet_count} | {protocol} | "
        f"{src} -> {dst} | {len(packet)} bytes"
    )

print("AI-IDS Live Packet Monitor")
print("Capturing packets. Press Ctrl+C to stop.")
sniff(prn=process_packet, store=False)
