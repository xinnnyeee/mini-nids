from scapy.all import Ether, IP, TCP, wrpcap

packets = []

for i, port in enumerate([22, 80, 443, 8080, 3306]):
    packets.append(
        Ether()
            / IP(src="192.168.1.50", dst="192.168.1.10")
            / TCP(sport=40000+i, dport=port, flags="S")
    )

wrpcap("practice.pcap", packets)