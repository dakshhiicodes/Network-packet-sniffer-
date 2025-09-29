from scapy.all import sniff


def packet_callback(packet):
    """Callback function to process each captured packet with improved formatting."""
    print("\n--- Packet Captured ---")

    # Check for Ethernet/MAC layer
    if packet.haslayer("Ether"):
        eth_layer = packet["Ether"]
        src_mac = eth_layer.src
        dst_mac = eth_layer.dst
        print(f"  Source MAC: {src_mac}")
        print(f"  Destination MAC: {dst_mac}")

    # Check for IP layer

    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        print(f"  Source IP: {src_ip}")
        print(f"  Destination IP: {dst_ip}")

        # Check for TCP
        if packet.haslayer("TCP"):
            tcp_layer = packet["TCP"]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            print(f"  Protocol: TCP")
            print(f"  Source Port: {src_port}")
            print(f"  Destination Port: {dst_port}")

        # Check for UDP
        elif packet.haslayer("UDP"):
            udp_layer = packet["UDP"]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            print(f"  Protocol: UDP")
            print(f"  Source Port: {src_port}")
            print(f"  Destination Port: {dst_port}")
        else:
            print("  Protocol: Other (not TCP or UDP)")
    else:
        print("  No IP layer in this packet.")


if __name__ == "__main__":
    print("Starting packet sniffing... (Press Ctrl+C to stop)")
    try:
        sniff(prn=packet_callback, count=5)  # capture 5 packets for testing
    except KeyboardInterrupt:
        print("\nStopped by user.")
    print("Finished sniffing.")
