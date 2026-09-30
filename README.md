# Mini NIDS

A small offline PCAP analyzer that flags possible TCP SYN port scans.

## What it detects

For each IPv4 source–destination pair, the detector counts distinct TCP
destination ports receiving initial SYN attempts (SYN set, ACK clear) in a
rolling time window. It reports the busiest window when the count reaches the
configured threshold.

This is a learning project, not a production intrusion detection system.
Alerts are heuristic and need investigation.

## Requirements

- Python 3.10+
- Scapy

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Run

```bash
python3 detector.py capture.pcap
python3 detector.py capture.pcap --threshold 5 --window 3
```

The detector reads PCAP/PCAPNG files locally and does not transmit packets.

## Limitations

- Currently analyzes IPv4 TCP traffic only.
- Uses a simple threshold that can produce false positives.
- Expects packets in timestamp order.
- Some captures may not contain connection handshakes, so SYN attempts may be absent.
- The detector is intended for offline learning and analysis, not real-time monitoring.

## Privacy

- Capture files can contain sensitive data. Use captures you own or are authorized to analyze, and avoid committing PCAP files to this repository.
