from rules import detect_syn_flood, detect_port_scan, detect_large_packets

def analyze_packets(packets):
    """Analyze packets and return a structured dictionary report"""
    if not packets:
        return {"Error": "No packets loaded"}

    # Total packets
    total = len(packets)

    # Unique source IPs
    src_ips = list({pkt["IP"].src for pkt in packets if pkt.haslayer("IP")})

    # Ports hit
    ports = {}
    for pkt in packets:
        if pkt.haslayer("TCP"):
            dport = pkt["TCP"].dport
            ports[dport] = ports.get(dport, 0) + 1

    # Rule-based detections
    syn_alerts = detect_syn_flood(packets)
    scan_alerts = detect_port_scan(packets)
    large_packets = detect_large_packets(packets)

    # Return structured report
    return {
        "Total Packets": total,
        "Unique Source IPs": src_ips,
        "Ports Hit": ports,
        "SYN Flood Sources": syn_alerts,
        "Port Scan Sources": scan_alerts,
        "Large Packets": len(large_packets)
    }
