import asyncio
import scapy.all as scapy
import pyfiglet
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

# Global variables for packet tracking
packet_counts = []
anomaly_count = 0
PACKET_WINDOW_SIZE = 100

# Main function to initiate packet capture
def main():
    # Get network interface to capture on
    interface = select_interface()  
    if not interface:
        print("Invalid interface selected. Exiting.")
        return
    
    try:
        # Start packet capture asynchronously
        asyncio.run(async_packet_capture(interface))
    except KeyboardInterrupt:
        print("\nStopping packet capture. Goodbye!")
        exit()

# Asynchronous packet capture function
async def async_packet_capture(interface):
    print(f"\nStarting packet capture on interface: {interface}")
    
    # Event loop for async packet capture with Scapy
    loop = asyncio.get_event_loop()
    
    # Run Scapy sniff in the background
    await loop.run_in_executor(None, scapy.sniff, {'iface': interface, 'prn': handle_packet, 'store': 0})

# Entry point to run the tool
if __name__ == "__main__":
    main()
