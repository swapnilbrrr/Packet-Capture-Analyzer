# Packet Capture Analyzer

## Overview
**Packet Capture Analyzer** is a Python-based network analysis tool designed for SOC interns, cybersecurity enthusiasts, and researchers. It reads PCAP files, analyzes traffic for anomalies, detects suspicious behaviors such as SYN floods, port scans, and large packets, and produces a clear, structured report in both console and JSON format.

This project is modular and easily extensible for additional detection rules or integration with dashboards.

---

## Features

- Load PCAP files using Scapy
- Detect common network attacks:
  - SYN Flood
  - Port Scan
  - Large Packet anomalies
- Summarize traffic:
  - Total packets
  - Unique source IPs
  - Ports accessed and counts
- Save structured JSON report for automated workflows
- Modular code design for SOC-ready analysis

---

## Installation

### Requirements
- Python 3.10+  
- Scapy

```bash
pip install scapy
````

**Optional:** If you want live packet capture, install [Npcap](https://nmap.org/npcap/) (Windows) or libpcap (Linux/macOS).

---

## Project Structure

```
packet-capture-analyzer/
│
├── capture.py           # Generate sample PCAP with normal + attack traffic
├── helpers.py           # Utility functions: load PCAP, pretty print, save JSON
├── packet_analysis.py   # Main analysis logic applying detection rules
├── rules.py             # Detection rules: SYN flood, port scan, large packets
├── main.py              # CLI entry point, parses arguments and generates report
├── sample.pcap          # Sample PCAP file for testing
└── report.json          # Example JSON output
```

---

## Usage

```bash
# Analyze a sample pcap
python main.py sample.pcap

# Analyze and save report as JSON
python main.py sample.pcap --json
```

**Output Example (Console):**

```
===== PACKET ANALYZER REPORT =====
Total Packets: 21
Unique Source IPs: ['10.0.0.10', '10.0.0.4', '172.16.5.5', ...]
Ports Hit: {80: 12, 1234: 2, 22: 1, 135: 1, 443: 2, 8080: 1, 3306: 1}
SYN Flood Sources: ['172.16.5.5']
Port Scan Sources: ['172.16.5.5']
Large Packets: 1
==================================
```

**JSON Output (`report.json`):**

```json
{
    "Total Packets": 21,
    "Unique Source IPs": ["10.0.0.10", "10.0.0.4", ...],
    "Ports Hit": {"80": 12, "1234": 2, ...},
    "SYN Flood Sources": ["172.16.5.5"],
    "Port Scan Sources": ["172.16.5.5"],
    "Large Packets": 1
}
```

---

## How It Works (Flow)

1. **Load PCAP** → `helpers.load_pcap()` reads packets using Scapy
2. **Analyze Traffic** → `packet_analysis.analyze_packets()` applies detection rules:

   * Count packets and unique IPs
   * Track TCP destination ports
   * Detect SYN floods, port scans, large packets
3. **Generate Report**

   * Console output via `pretty_print()`
   * JSON export via `save_json_report()`

> Modular design allows easy integration of new detection rules.

---

## Author

**Swapnil Katuwal** – Cybersecurity enthusiast & SOC Intern

GitHub: [https://github.com/Swapnil-Katuwal](https://github.com/Swapnil-Katuwal)

---

## License

MIT License – Feel free to use, modify, and share.

---

## Future Improvements

* Live packet capture and real-time alerts
* Integration with SIEM dashboards
* Additional detection rules (DNS anomalies, ICMP flood, etc.)
* GUI interface for easier visualization
* Combine with Port Scanner Detector project for a unified SOC toolkit

