
from pathlib import Path

from scapy.all import Ether, IP, TCP, UDP, wrpcap


output_path = Path("data") / "sample_traffic.pcap"
output_path.parent.mkdir(parents=True, exist_ok=True)

packets = []

# Ordinary HTTPS and DNS traffic
packets.append(
    Ether() / IP(src="192.168.1.10", dst="192.168.1.20")
    / TCP(sport=51515, dport=443)
)

packets.append(
    Ether() / IP(src="192.168.1.10", dst="192.168.1.30")
    / UDP(sport=53000, dport=53)
)

# Synthetic traffic across multiple ports to test the scan rule
for port in range(1000, 1012):
    packets.append(
        Ether() / IP(src="192.168.1.50", dst="192.168.1.20")
        / TCP(sport=40000 + port, dport=port)
    )

# Synthetic traffic to a sensitive service port
packets.append(
    Ether() / IP(src="192.168.1.60", dst="192.168.1.20")
    / TCP(sport=52000, dport=445)
)

wrpcap(str(output_path), packets)

print(f"Created sample PCAP: {output_path}")
print(f"Packets written: {len(packets)}")
