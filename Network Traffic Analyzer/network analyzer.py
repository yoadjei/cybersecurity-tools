import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS, DNSQR
import pyfiglet

# Function to show the banner
def show_banner():
    banner = pyfiglet.figlet_format("CYBERYAW")
    print(banner)
    print("-" * 30)
    print("Network Traffic Analyzer Tool")
    print("-" * 30)

# Handle the captured packet
def handle_packet(packet):
    try:
        if packet.haslayer(HTTPRequest):
            print(f"HTTP Request: {packet[HTTPRequest].Host} {packet[HTTPRequest].Path}")
        elif packet.haslayer(DNS):
            dns_query = packet[DNSQR].qname.decode()
            print(f"DNS Query: {dns_query}")
        else:
            print(f"Packet: {packet.summary()}")
    except Exception as e:
        print(f"Error handling packet: {e}")

# Select the network interface
def select_interface():
    interfaces = scapy.get_if_list()
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
    choice = int(input("Select the interface to sniff (number): "))
    if choice < 0 or choice >= len(interfaces):
        print("Invalid choice. Exiting.")
        return None
    return interfaces[choice]

# Main function to start capturing packets
def main():
    show_banner()
    interface = select_interface()
    if not interface:
        print("Invalid interface selected!")
        return
    try:
        print(f"\nStarting packet capture on interface: {interface}")
        scapy.sniff(iface=interface, prn=handle_packet, store=0)
    except KeyboardInterrupt:
        print("\nStopping packet capture. Goodbye!")
        exit()

if __name__ == "__main__":
    main()
