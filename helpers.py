import json
import logging
from scapy.all import rdpcap

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def load_pcap(file_path):
    """Load packets from a pcap file"""
    try:
        packets = rdpcap(file_path)
        logging.info(f"Loaded {len(packets)} packets from {file_path}")
        return packets
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error reading PCAP: {e}")
        return []

def pretty_print(report):
    """Print a dictionary report nicely"""
    print("\n===== PACKET ANALYZER REPORT =====")
    for key, value in report.items():
        print(f"{key}: {value}")
    print("==================================\n")

def save_json_report(report, filename="report.json"):
    """Save report dictionary to a JSON file"""
    try:
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Report saved as {filename}")
    except Exception as e:
        logging.error(f"Failed to save report: {e}")
