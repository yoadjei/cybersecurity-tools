import asyncio
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from datetime import datetime
import pyfiglet  # ASCII Art banner
from utils.packet_utils import handle_packet, select_interface
from utils.alert_utils import trigger_alert
from utils.db_utils import store_packet_in_db

# Function to show the banner
def show_banner():
    banner = pyfiglet.figlet_format("CYBERYAW")
    print(banner)
    print("-" * 30)
    print("Network Traffic Analyzer Tool")
    print("-" * 30)

# Call the banner function
show_banner()

# Global variables
packet_counts = []
anomaly_count = 0
PACKET_WINDOW_SIZE = 100

# Main function to start capturing packets
def main():
    interface = select_interface()
    try:
        asyncio.run(async_packet_capture(interface))
    except KeyboardInterrupt:
        print("\nStopping packet capture. Goodbye!")
        exit()

# Asynchronous packet capture
async def async_packet_capture(interface):
    print(f"\nStarting packet capture on interface: {interface}")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, scapy.sniff, {'iface': interface, 'prn': handle_packet, 'store': 0})

if name == "__main__":
    main()