# Internet Topology Explorer (Traceroute Visualizer)



This Python project implements a custom traceroute engine and visualizer, supporting **ICMP**, **UDP**, and **TCP** probes. It captures RTT and protocol information hop-by-hop, saves the data to a file, and creates an interactive graph of the path to the target.

## 🧠 Features

- Packet sending using Scapy (ICMP, UDP, TCP SYN)
- RTT calculation and hostname resolution
- Timeout and error handling
- Interactive graph with:
  - Drag-and-drop nodes
  - Color-coded edges by protocol
  - Live node info panel
- CLI with options to specify:
  - Protocol
  - Hop limit
  - Specific IP to find
  - Target Address

## 📦 Requirements

- Python 3
- Scapy
- NetworkX
- Matplotlib

Install with:

```bash
pip install scapy networkx matplotlib
