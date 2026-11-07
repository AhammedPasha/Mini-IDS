
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, wrpcap

from ids.packet_analyzer import analyze_pcap, summarize_traffic


def test_analyze_pcap(tmp_path: Path):
    pcap_path = tmp_path / "sample.pcap"

    packets = [
        Ether() / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=51515, dport=443),
        Ether() / IP(src="192.168.1.10", dst="192.168.1.30")
        / UDP(sport=53000, dport=53),
    ]

    wrpcap(str(pcap_path), packets)

    df = analyze_pcap(str(pcap_path))

    assert len(df) == 2
    assert df.iloc[0]["source_ip"] == "192.168.1.10"
    assert df.iloc[0]["destination_port"] == 443
    assert df.iloc[0]["protocol"] == "TCP"
    assert df.iloc[1]["protocol"] == "UDP"

    summary = summarize_traffic(df)

    assert summary["total_packets"] == 2
    assert summary["unique_source_ips"] == 1
    assert summary["total_bytes"] > 0
