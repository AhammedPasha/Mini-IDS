
from collections import Counter
from pathlib import Path

import pandas as pd
from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader


def analyze_pcap(file_path: str) -> pd.DataFrame:
    """
    Read a PCAP file and extract basic network packet features.

    Returns one DataFrame row per readable packet.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    records = []

    with PcapReader(str(path)) as packets:
        for packet_number, packet in enumerate(packets, start=1):
            source_ip = None
            destination_ip = None
            protocol = "OTHER"
            source_port = None
            destination_port = None

            if IP in packet:
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
            elif IPv6 in packet:
                source_ip = packet[IPv6].src
                destination_ip = packet[IPv6].dst

            if TCP in packet:
                protocol = "TCP"
                source_port = int(packet[TCP].sport)
                destination_port = int(packet[TCP].dport)
            elif UDP in packet:
                protocol = "UDP"
                source_port = int(packet[UDP].sport)
                destination_port = int(packet[UDP].dport)
            elif ICMP in packet:
                protocol = "ICMP"
            elif IPv6 in packet and packet[IPv6].nh == 58:
                protocol = "ICMPv6"

            records.append({
                "packet_number": packet_number,
                "timestamp": float(packet.time),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": protocol,
                "source_port": source_port,
                "destination_port": destination_port,
                "packet_length": len(packet),
            })

    columns = [
        "packet_number",
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_length",
    ]

    return pd.DataFrame(records, columns=columns)


def summarize_traffic(df: pd.DataFrame) -> dict:
    """Return a basic summary of analyzed packet traffic."""
    return {
        "total_packets": len(df),
        "unique_source_ips": int(df["source_ip"].nunique()),
        "unique_destination_ips": int(df["destination_ip"].nunique()),
        "protocol_counts": dict(Counter(df["protocol"])),
        "total_bytes": int(df["packet_length"].sum()),
    }
