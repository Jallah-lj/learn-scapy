#!/usr/bin/env python3
"""
Script Name: layer_stacking.py
Description: Learn how Scapy stacks protocol layers to build complete packets
Author: Learn Scapy Repository
Date: 2024

This script demonstrates the powerful concept of layer stacking in Scapy.
Network packets are composed of multiple protocol layers (like an onion),
and Scapy makes it easy to combine them using the / operator.

Educational Purpose:
    - Understand the OSI model and protocol layers
    - Learn how to stack layers with /
    - Create complex multi-layer packets
    - Explore how layers interact
"""

from scapy.all import *

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def demo_basic_stacking():
    """Demonstrate basic layer stacking."""
    print_section("1. Basic Layer Stacking")
    
    print("[+] Building packets by stacking layers:\n")
    
    # Layer 3 (Network): IP
    print("  Step 1: Create IP layer")
    ip_layer = IP(dst="192.168.1.1")
    print(f"          {ip_layer.summary()}")
    
    # Layer 4 (Transport): TCP
    print("\n  Step 2: Create TCP layer")
    tcp_layer = TCP(dport=80)
    print(f"          {tcp_layer.summary()}")
    
    # Stack them together using /
    print("\n  Step 3: Stack IP / TCP")
    packet = ip_layer / tcp_layer
    print(f"          {packet.summary()}")
    
    # Or create in one line
    print("\n  Step 4: Create in one line (IP/TCP)")
    packet_oneline = IP(dst="192.168.1.1")/TCP(dport=80)
    print(f"          {packet_oneline.summary()}")

def demo_three_layer_stack():
    """Demonstrate three-layer stacking."""
    print_section("2. Three-Layer Stacking (Ethernet/IP/TCP)")
    
    # Layer 2, 3, and 4
    packet = Ether() / IP(dst="192.168.1.1") / TCP(dport=443)
    
    print("[+] Complete packet with 3 layers:")
    packet.show()
    
    print("\n[+] Layer breakdown:")
    print(f"    Layer 2 (Data Link): Ethernet")
    print(f"    Layer 3 (Network):   IP")
    print(f"    Layer 4 (Transport): TCP")
    
    print(f"\n[+] Each layer adds its own header:")
    print(f"    Total packet size: {len(packet)} bytes")

def demo_layer_access():
    """Demonstrate accessing specific layers."""
    print_section("3. Accessing Individual Layers")
    
    # Create a multi-layer packet
    packet = IP(dst="8.8.8.8")/TCP(dport=443, flags="S")/Raw(load="Hello")
    
    print("[+] Complete packet:")
    print(f"    {packet.summary()}\n")
    
    # Access IP layer
    print("[+] Accessing IP layer:")
    if packet.haslayer(IP):
        print(f"    Destination: {packet[IP].dst}")
        print(f"    Source: {packet[IP].src}")
        print(f"    TTL: {packet[IP].ttl}")
    
    # Access TCP layer
    print("\n[+] Accessing TCP layer:")
    if packet.haslayer(TCP):
        print(f"    Destination Port: {packet[TCP].dport}")
        print(f"    Source Port: {packet[TCP].sport}")
        print(f"    Flags: {packet[TCP].flags}")
    
    # Access payload
    print("\n[+] Accessing payload:")
    if packet.haslayer(Raw):
        print(f"    Payload: {packet[Raw].load}")

def demo_different_protocols():
    """Demonstrate stacking with different protocols."""
    print_section("4. Different Protocol Combinations")
    
    protocols = [
        ("Web Request (HTTP)", IP(dst="192.168.1.1")/TCP(dport=80, flags="PA")/Raw(load="GET / HTTP/1.1\r\n")),
        ("DNS Query", IP(dst="8.8.8.8")/UDP(dport=53)/DNS(qd=DNSQR(qname="example.com"))),
        ("Ping Request", IP(dst="8.8.8.8")/ICMP(type=8)),
        ("ARP Request", Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1")),
        ("HTTPS SYN", IP(dst="1.1.1.1")/TCP(dport=443, flags="S")),
    ]
    
    print("[+] Different packet types:\n")
    for i, (description, packet) in enumerate(protocols, 1):
        print(f"  {i}. {description}")
        print(f"     {packet.summary()}")
        print()

def demo_layer_removal():
    """Demonstrate removing layers from packets."""
    print_section("5. Removing and Replacing Layers")
    
    # Create a packet
    original = IP(dst="192.168.1.1")/TCP(dport=80)/Raw(load="data")
    print("[+] Original packet:")
    print(f"    {original.summary()}")
    
    # Remove payload
    without_payload = IP(dst="192.168.1.1")/TCP(dport=80)
    print("\n[+] Packet without payload:")
    print(f"    {without_payload.summary()}")
    
    # Replace TCP with UDP
    with_udp = IP(dst="192.168.1.1")/UDP(dport=53)
    print("\n[+] Replaced TCP with UDP:")
    print(f"    {with_udp.summary()}")

def demo_multiple_packets():
    """Demonstrate creating multiple related packets."""
    print_section("6. Creating Related Packets")
    
    print("[+] TCP Three-Way Handshake packets:\n")
    
    # SYN
    syn = IP(dst="192.168.1.1")/TCP(dport=80, flags="S", seq=1000)
    print("  1. SYN (Client → Server):")
    print(f"     {syn.summary()}")
    
    # SYN-ACK (simulated response)
    syn_ack = IP(dst="192.168.1.100")/TCP(sport=80, dport=12345, flags="SA", seq=2000, ack=1001)
    print("\n  2. SYN-ACK (Server → Client):")
    print(f"     {syn_ack.summary()}")
    
    # ACK
    ack = IP(dst="192.168.1.1")/TCP(dport=80, flags="A", seq=1001, ack=2001)
    print("\n  3. ACK (Client → Server):")
    print(f"     {ack.summary()}")
    
    print("\n[+] This demonstrates how packets build a conversation!")

def demo_layer_list():
    """Demonstrate listing all layers in a packet."""
    print_section("7. Listing All Layers")
    
    # Complex packet
    packet = Ether()/IP(dst="192.168.1.1")/TCP(dport=443)/Raw(load="secret data")
    
    print("[+] Packet structure:")
    packet.show()
    
    print("\n[+] Layer names in order:")
    layer_names = []
    layer = packet
    while layer:
        layer_names.append(layer.name)
        layer = layer.payload if hasattr(layer, 'payload') else None
    
    for i, name in enumerate(layer_names, 1):
        print(f"    {i}. {name}")

def demo_osi_model():
    """Demonstrate OSI model layers with examples."""
    print_section("8. OSI Model and Scapy Layers")
    
    print("""[+] OSI Model Mapping:

  Layer 7 (Application):  HTTP, DNS, FTP, SSH
                          → Raw(load="application data")
                          
  Layer 6 (Presentation): Encryption, Encoding
                          → Usually handled by applications
                          
  Layer 5 (Session):      Session management
                          → Usually handled by applications
                          
  Layer 4 (Transport):    TCP, UDP
                          → TCP(), UDP()
                          
  Layer 3 (Network):      IP, ICMP, ARP
                          → IP(), ICMP(), ARP()
                          
  Layer 2 (Data Link):    Ethernet, WiFi
                          → Ether(), Dot11()
                          
  Layer 1 (Physical):     Cables, Radio waves
                          → Handled by network hardware
""")
    
    print("[+] Example packet traversing the stack:")
    web_packet = Ether()/IP(dst="192.168.1.1")/TCP(dport=80)/Raw(load="GET /")
    
    print("\n  Reading from top to bottom (encapsulation):")
    print("    Application data: 'GET /'")
    print("    └─ TCP header added (port 80)")
    print("       └─ IP header added (destination 192.168.1.1)")
    print("          └─ Ethernet frame added")
    print(f"\n  Result: {web_packet.summary()}")

def demo_practical_examples():
    """Show practical examples of layer stacking."""
    print_section("9. Practical Examples")
    
    print("[+] Common packet constructions:\n")
    
    # Example 1: Ping
    print("  1. ICMP Ping:")
    ping = IP(dst="8.8.8.8")/ICMP()
    print(f"     {ping.summary()}")
    print(f"     Use case: Test if host is reachable")
    
    # Example 2: Port scan
    print("\n  2. TCP SYN Scan (port probe):")
    syn_scan = IP(dst="192.168.1.1")/TCP(dport=80, flags="S")
    print(f"     {syn_scan.summary()}")
    print(f"     Use case: Check if port is open")
    
    # Example 3: DNS query
    print("\n  3. DNS Query:")
    dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    print(f"     {dns_query.summary()}")
    print(f"     Use case: Resolve domain name to IP")
    
    # Example 4: ARP scan
    print("\n  4. ARP Request:")
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1/24")
    print(f"     {arp_req.summary()}")
    print(f"     Use case: Discover hosts on local network")

def main():
    """Main function to demonstrate layer stacking."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║             LAYER STACKING WITH SCAPY                        ║
║      Understanding Protocol Layers and Composition           ║
╚══════════════════════════════════════════════════════════════╝

This script demonstrates:
  • How to stack protocol layers using /
  • Accessing individual layers in a packet
  • Creating complex multi-layer packets
  • Understanding the OSI model
  • Practical examples of layer combinations

KEY CONCEPT: The / operator stacks layers, like building a sandwich!
             IP()/TCP() creates an IP packet with TCP inside it.

NOTE: This script doesn't send packets, no privileges needed!
    """)
    
    try:
        demo_basic_stacking()
        demo_three_layer_stack()
        demo_layer_access()
        demo_different_protocols()
        demo_layer_removal()
        demo_multiple_packets()
        demo_layer_list()
        demo_osi_model()
        demo_practical_examples()
        
        print("\n" + "="*70)
        print("  Tutorial Complete!")
        print("="*70)
        print("\nWhat you learned:")
        print("  ✓ How to stack protocol layers with /")
        print("  ✓ How to access individual layers")
        print("  ✓ How layers map to the OSI model")
        print("  ✓ Practical packet construction patterns")
        print("\nNext steps:")
        print("  - Learn about sending packets in sending_packets.py")
        print("  - Try creating custom packet combinations")
        print("  - Experiment with different protocol stacks")
        
    except KeyboardInterrupt:
        print("\n\n[!] Tutorial interrupted by user")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
