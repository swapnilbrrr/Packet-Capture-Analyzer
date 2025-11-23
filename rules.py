def detect_syn_flood(packets, threshold=5):
    syn_sources = {}
    for pkt in packets:
        if pkt.haslayer("TCP") and pkt["TCP"].flags == "S":
            src = pkt["IP"].src
            syn_sources[src] = syn_sources.get(src, 0) + 1

    alerts = [ip for ip, count in syn_sources.items() if count > threshold]
    return alerts

def detect_port_scan(packets, port_threshold=5):
    target_ports = {}
    for pkt in packets:
        if pkt.haslayer("TCP") and pkt["TCP"].flags == "S":
            src = pkt["IP"].src
            dport = pkt["TCP"].dport
            target_ports.setdefault(src, set()).add(dport)

    alerts = [ip for ip, ports in target_ports.items() if len(ports) >= port_threshold]
    return alerts

def detect_large_packets(packets, size_threshold=1500):
    return [pkt for pkt in packets if len(pkt) > size_threshold]
