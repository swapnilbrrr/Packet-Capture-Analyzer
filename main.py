import argparse
from helpers import load_pcap, pretty_print, save_json_report
from packet_analysis import analyze_packets

def main():
    parser = argparse.ArgumentParser(description="Packet Capture Analyzer")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--json", action="store_true", help="Save report as JSON")
    args = parser.parse_args()

    packets = load_pcap(args.pcap_file)
    if not packets:
        return

    report = analyze_packets(packets)
    pretty_print(report)

    if args.json:
        save_json_report(report, "report.json")

if __name__ == "__main__":
    main()
