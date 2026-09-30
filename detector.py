from scapy.all import IP, TCP
from scapy.utils import PcapReader
from collections import deque, defaultdict
import argparse
from pathlib import Path


def scan_pcap(path, threshold=3, time_window=2): 
    recent_by_pair = {}
    syn_attempts = 0
    alerts = []

    with PcapReader(path) as capture: 
        for packet in capture: 
            if IP not in packet or TCP not in packet: 
                continue
            flags = int(packet[TCP].flags)
            syn_set = flags & 0x02
            ack_set = flags & 0x10

            if not syn_set or ack_set: 
                continue

            syn_attempts += 1
            key = (packet[IP].src, packet[IP].dst)
            timestamp = float(packet.time)
            port = int(packet[TCP].dport)

            if key not in recent_by_pair: 
                recent_by_pair[key] = {
                    "attempts": deque(),
                    "port_counts": defaultdict(int),
                    "best_ports": set(),
                }
            
            state = recent_by_pair[key]
            attempts = state["attempts"]
            port_counts = state["port_counts"]

            attempts.append((timestamp, port))
            port_counts[port] += 1

            while attempts and timestamp - attempts[0][0] > time_window:
                _, expired_port = attempts.popleft()
                port_counts[expired_port] -= 1
                if port_counts[expired_port] == 0:
                    del port_counts[expired_port]
            if len(port_counts) > len(state["best_ports"]):
                state["best_ports"] = set(port_counts)
        
        for (src, dst), state in recent_by_pair.items():
            best_ports = state["best_ports"]

            if len(best_ports) >= threshold:
                alerts.append({
                    "source": src, 
                    "destination": dst,
                    "distinct_ports": len(best_ports),
                    "ports": sorted(best_ports)
                })


    return alerts, syn_attempts



def main():
    parser = argparse.ArgumentParser(
        description="Detect possible TCP SYN port scans in a PCAP file."
    )
    parser.add_argument("pcap_file", help="Path to a .pcap or .pcapng file")
    parser.add_argument(
    "--threshold",
    type=int,
    default=3,
    help="Distinct destination ports needed to trigger an alert (default: 3)",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=2.0,
        help="Time window in seconds (default: 2)",
    )
    args = parser.parse_args()

    pcap_path = Path(args.pcap_file)
    if not pcap_path.is_file():
        parser.error(f"PCAP file not found {pcap_path}")

    alerts, syn_attempts = scan_pcap(args.pcap_file, args.threshold, args.window)
    print(f"Processed {syn_attempts} TCP SYN attempts.")

    if len(alerts) == 0:
        print("No possible port scan detected.")

    for i, alert in enumerate(alerts, start=1):
        print(
            f"Alert {i} [Source: {alert['source']}, "
            f"Destination: {alert['destination']}]: "
            f"Possible scan across {alert['distinct_ports']} distinct ports: "
            f"{alert['ports']}"
        )
    return alerts

if __name__ == "__main__":
    main()