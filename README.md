Network Packet Sniffer

Creating a network packet sniffer project can be a great way to understand network protocols, packet structures, and cybersecurity concepts. It provides hands-on experience in how data flows across networks and how various layers of the OSI model interact.

What is a Network Packet Sniffer?

A network packet sniffer is a tool or software application that captures, monitors, and analyzes network traffic passing through a computer or network interface.

It works by intercepting data packets (small units of data) that travel over the network and displaying their contents for inspection. This is done by putting the network interface into promiscuous mode, allowing it to capture all traffic — not just traffic intended for the host machine.

What Information Can It Capture?

A packet sniffer can extract detailed information from captured packets, including:

Source and Destination MAC Addresses
MAC (Media Access Control) addresses identify the physical network interfaces of the devices involved in communication. They operate at the Data Link Layer (Layer 2) of the OSI model and are crucial for identifying devices on the same local area network (LAN).

Source and Destination IP Addresses
IP addresses identify the endpoints of communication at the Network Layer (Layer 3). They are used to route packets between networks.

Protocols Used
Examples include TCP, UDP, ICMP, and higher-level protocols like HTTP, DNS, or FTP. This information helps determine the nature of the communication.

Port Numbers
These help identify specific services or applications on the host, such as HTTP (port 80) or HTTPS (port 443). Port numbers operate at the Transport Layer (Layer 4).

Payload (Actual Data Being Transmitted)
The data portion of the packet may include application-level messages like HTTP requests, credentials (if unencrypted), file transfers, or DNS queries.

The Role of MAC Addresses in Packet Sniffing

Including MAC addresses in packet analysis offers several benefits:

Identifying which physical devices are communicating on a network

Detecting ARP spoofing or MAC flooding attacks

Mapping IP addresses to hardware addresses for network diagnostics

Determining whether traffic is local or routed across network segments

Analyzing network topology and device behavior on switches and wireless networks

Note: MAC addresses are only visible within the same Layer 2 broadcast domain and are stripped at routing boundaries.

Common Uses of Packet Sniffers

Packet sniffers are commonly used by:

Network Administrators
For monitoring network health, troubleshooting issues, and analyzing performance.

Security Analysts
To detect malicious activity such as intrusions, unauthorized access, or data leaks.

Developers
For debugging network-based applications and ensuring data is transmitted correctly.

Hackers (Malicious or Ethical)
To intercept sensitive information, analyze vulnerabilities, or conduct penetration testing (with proper authorization).

Conclusion

Building a network packet sniffer provides valuable insight into how modern networks operate. It helps reinforce understanding of:

OSI layers

Protocol behavior

Real-world security risks

Network forensic analysis

You can build a simple packet sniffer using tools like Scapy (Python), libpcap (C/C++), or Wireshark for GUI-based exploration. It’s a rewarding hands-on project for students, professionals, and hobbyists interested in cybersecurity or networking.

*How It Works

The sniffer puts the network interface into promiscuous mode, allowing it to capture all packets on the network segment — not just those addressed to the device.

It captures live packets from the network interface.

Each packet is decoded and analyzed according to protocol layers:

Layer 2 (Ethernet) — MAC addresses

Layer 3 (IP) — IP addresses

Layer 4 (TCP/UDP) — Ports

Layer 7 (Application) — Optional parsing of payloads (e.g., HTTP) 

*Tools & Technologies You Can Use

Language	Library/Tool	Notes
Python	scapy, socket, pyshark	Easiest for beginners
C/C++	libpcap, WinPcap	Low-level access and high performance
Go	gopacket	Efficient and good for backend tools
Linux	tcpdump, Wireshark	Excellent for CLI/GUI-based analysis
Define the Scope of the Project

Choose what your sniffer should support. This implementation includes:

Capture live packets

Extract MAC addresses from Ethernet header

Show source/destination IPs

Identify protocols (TCP/UDP)

Display source/destination ports

Basic packet analysis with formatting

(Optional for future): Filtering, payload parsing, saving to PCAP, or GUI

*STEPS TO BUILD OUR TASK:
Task: Build a Network Packet Sniffer in Python Using Scapy
Step 1: Install Necessary Libraries

Subtask: Install Scapy and related libraries.

%pip install scapy scapy-python3

Reasoning: Scapy provides powerful packet-capturing and manipulation features using a Pythonic API.

Step 2: Import Required Modules

from scapy.all import sniff

Reasoning: sniff() is the main function for capturing live packets in Scapy.

Step 3: Define the Packet Callback Function (Initial Test)

def packet_callback(packet):
    """Callback function to process each captured packet."""
    print("Packet captured!")

Step 4: Start Sniffing (Basic Test)
print("Starting packet sniffing...")
sniff(prn=packet_callback, count=5)
print("Finished sniffing.")

Reasoning: Captures 5 packets and verifies that packet collection is working.

Step 5: Analyze Captured Packets (with MAC Address, IP, Ports, and Protocols)
def packet_callback(packet):
    """Callback function to process and display packet details."""
    print("\n--- Packet Captured ---")

    # Ethernet Layer (MAC Addresses)
    if packet.haslayer('Ether'):
        ether_layer = packet['Ether']
        src_mac = ether_layer.src
        dst_mac = ether_layer.dst
        print(f"  Source MAC: {src_mac}")
        print(f"  Destination MAC: {dst_mac}")
    else:
        print("  No Ethernet layer (MAC) found.")

    # IP Layer
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")

        # Transport Layer
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            print("  Protocol: TCP")
            print(f"  Source Port: {tcp_layer.sport}")
            print(f"  Destination Port: {tcp_layer.dport}")
        elif packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            print("  Protocol: UDP")
            print(f"  Source Port: {udp_layer.sport}")
            print(f"  Destination Port: {udp_layer.dport}")
        else:
            print("  Protocol: Other (not TCP/UDP)")
    else:
        print("  No IP layer in this packet.")

Step 6: Run the Sniffer with Enhanced Output
print("Starting packet sniffing...")
sniff(prn=packet_callback, count=5)
print("Finished sniffing.")


Sample Output:

--- Packet Captured ---
  Source MAC: 02:42:ac:11:00:02
  Destination MAC: 02:42:ac:11:00:01
  Source IP: 172.28.0.2
  Destination IP: 172.28.0.1
  Protocol: TCP
  Source Port: 8080
  Destination Port: 443

--- Packet Captured ---
  Source MAC: 02:42:ac:11:00:01
  Destination MAC: 02:42:ac:11:00:02
  Source IP: 172.28.0.1
  Destination IP: 172.28.0.2
  Protocol: TCP
  Source Port: 443
  Destination Port: 8080
...

*Summary: Data Analysis & Key Findings

Step Result/Outcome
Libraries Installed scapy and scapy-python3 successfully installed
Packet Capture Function	sniff() and packet_callback() implemented and working
MAC Address Extraction Extracted from Ethernet header using Scapy
IP & Port Analysis Extracted from IP and TCP/UDP headers
Protocol Identification Differentiated between TCP, UDP, and others
Output Formatting Improved with clear indentation and labels for readability

*Conclusion

Your basic packet sniffer is now fully functional, providing detailed visibility into:

MAC-level communication (Ethernet Layer)

IP-level routing (Network Layer)

TCP/UDP services (Transport Layer)

By analyzing MAC addresses alongside IPs and ports, you gain insights into local network behavior, device interactions, and potential vulnerabilities.

This project serves as a solid foundation for building more advanced network analysis and security tools.
