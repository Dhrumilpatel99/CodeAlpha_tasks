from scapy.all import sniff, Ether, IP, TCP, UDP, get_if_list

def packet_sniffering(packet):
    """
    Callback the function to process the every network captured packets.

    """
    print("\n--- Network Packets are Captured ---")
    
    if packet.haslayer(Ether):
        print(f"Ethernet Frame: Source MAC: {packet[Ether].src}, Destination MAC: {packet[Ether].dst}")

    if packet.haslayer(IP):
        print(f"IP Packet: Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}")
        print(f"Protocol: {packet[IP].proto}")

    if packet.haslayer(TCP):
        print(f"TCP Segment: Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}")
    
    if packet.haslayer(UDP):
        print(f"UDP Datagram: Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}")

def main():

    """
    Main function to start the analysing the network packet sniffing.

    """
    # Specifying the network profile to sniffing the network on (e.g., "eth0" for Linux, "Wi-Fi" for Windows).
    NetProfile = input("Enter the network profile to sniffing the network on (e.g., eth0, Wi-Fi): ")
    print("Starting to analysis the network packet capture...")

    try:
        # Start sniffing
        sniff(iface=NetProfile, prn=packet_sniffering, store=False)
    except PermissionError:
        print("Permission error: Please you have to run the script as the administrator/root.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
