from scapy.all import Ether, IP, TCP, wrpcap

packets = []

for i, port in enumerate([22, 80]):
    packets.append(
        Ether()
            / IP(src="192.168.1.50", dst="192.168.1.10")
            / TCP(sport=40000+i, dport=port, flags="S")
    )
packets.append(
    Ether()
            / IP(src="192.168.1.50", dst="192.168.1.10")
            / TCP(sport=40010, dport=port, flags="SA")
)

wrpcap("test_tcp_filter.pcap", packets)