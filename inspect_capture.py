from scapy.all import rdpcap, IP, TCP

packets = rdpcap("practice.pcap")

for packet in packets: 
    if IP in packet and TCP in packet: 
        print(
            packet.time,
            packet[IP].src, 
            "->",
            packet[IP].dst,
            "destination port:",
            packet[TCP].dport,
        )