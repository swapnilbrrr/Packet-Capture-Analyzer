from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

def generate_pcap(filename="sample.pcap"):
    packets = []

    # Normal TCP + HTTP traffic
    packets.append(
        Ether()/IP(src="192.168.1.10", dst="192.168.1.1")/
        TCP(sport=1234, dport=80, flags="PA")/Raw(b"GET / HTTP/1.1")
    )
    packets.append(
        Ether()/IP(src="192.168.1.1", dst="192.168.1.10")/
        TCP(sport=80, dport=1234, flags="A")
    )

    # SYN Flood (attack traffic)
    for i in range(10):
        packets.append(
            Ether()/IP(src=f"10.0.0.{i+1}", dst="192.168.1.1")/
            TCP(sport=4000+i, dport=80, flags="S")
        )

    # Port Scan traffic
    attacker = "172.16.5.5"
    for port in [22, 80, 135, 443, 8080, 3306]:
        packets.append(
            Ether()/IP(src=attacker, dst="192.168.1.1")/
            TCP(sport=5555, dport=port, flags="S")
        )

    # UDP traffic (normal)
    packets.append(
        Ether()/IP(src="192.168.1.20", dst="192.168.1.1")/
        UDP(sport=55000, dport=53)/Raw(b"DNS query example")
    )

    # Large packet anomaly
    packets.append(
        Ether()/IP(src="192.168.1.30", dst="192.168.1.1")/
        TCP(sport=2222, dport=443, flags="PA")/Raw(b"A" * 2000)
    )

    # TCP RST packet (normal teardown)
    packets.append(
        Ether()/IP(src="192.168.1.1", dst="192.168.1.10")/
        TCP(sport=80, dport=1234, flags="R")
    )

    wrpcap(filename, packets)
    print(f"[INFO] {len(packets)} packets written to {filename}")

if __name__ == "__main__":
    generate_pcap()
