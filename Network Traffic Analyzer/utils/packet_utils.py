import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNSQR, DNSRR
import statistics

# Global variables
packet_counts = []
anomaly_count = 0
PACKET_WINDOW_SIZE = 100

# Select the network interface dynamically
def select_interface():
    interfaces = scapy.get_if_list()
    print("\nAvailable Network Interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
    choice = input("Select the interface to sniff (number): ")
    try:
        return interfaces[int(choice)]
    except (IndexError, ValueError):
        print("Invalid choice. Exiting.")
        exit()

# Packet handler for capturing and analyzing packets
def handle_packet(packet):
    global anomaly_count
    print(f"\n[{datetime.now()}] Packet captured: {packet.summary()}")
    detect_anomaly(packet)
    analyze_http(packet)
    analyze_dns(packet)
    store_packet_in_db(packet)

# Anomaly detection using Z-score
def detect_anomaly(packet):
    global anomaly_count
    packet_counts.append(1)
    if len(packet_counts) > PACKET_WINDOW_SIZE:
        try:
            z_scores = [(x - statistics.mean(packet_counts)) / statistics.stdev(packet_counts) for x in packet_counts]
            if abs(z_scores[-1]) > 2:
                print("Anomaly detected in traffic!")
                anomaly_count += 1
                trigger_alert("Anomaly detected in network traffic!")
            packet_counts.pop(0)
        except statistics.StatisticsError:
            pass  # Skip if not enough data for calculations

# Analyze HTTP packets
def analyze_http(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        print(f"HTTP Request - Method: {http_layer.Method.decode()}, Host: {http_layer.Host.decode()}")
    elif packet.haslayer(HTTPResponse):
        http_layer = packet[HTTPResponse]
        print(f"HTTP Response - Status Code: {http_layer.Status_Code}")

# Analyze DNS packets
def analyze_dns(packet):
    if packet.haslayer(DNSQR):
        dns_layer = packet[DNSQR]
        print(f"DNS Query - Name: {dns_layer.qname.decode()}")
    elif packet.haslayer(DNSRR):
        dns_layer = packet[DNSRR]
        print(f"DNS Response - Name: {dns_layer.rrname.decode()}, IP: {dns_layer.rdata}")