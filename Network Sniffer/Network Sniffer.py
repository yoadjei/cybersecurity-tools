
from scapy.all import sniff, Ether, IP, TCP, UDP
# Function to handle and analyze each packet
def packet_handler(packet):
    # Print general packet summary
    print(packet.summary())

    # Check if the packet has an Ethernet layer
    if packet.haslayer(Ether):
        print(f"Ethernet Frame: {packet[Ether].summary()}")

    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"IP Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check if the packet has a TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Segment: Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
            print(f"Flags: {tcp_layer.flags}")

        # Check if the packet has a UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Datagram: Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")

    # Print a separator line
    print("-" * 50)

# Function to start sniffing packets
def start_sniffing(interface):
    print(f"Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=packet_handler, store=0)

# Directly start sniffing packets on the 'eth0' network interface
start_sniffing("eth0")