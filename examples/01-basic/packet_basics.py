#!/usr/bin/env python3
"""
Script Name: packet_basics.py
Description: Learn the basics of creating and inspecting packets with Scapy
Author: Learn Scapy Repository
Date: 2024

This script demonstrates fundamental packet operations:
- Creating packets from scratch
- Inspecting packet fields
- Modifying packet attributes
- Understanding packet layers

Educational Purpose:
    - Understand packet structure
    - Learn how to access and modify packet fields
    - Explore different protocols and their fields
"""

from scapy.all import *

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def demo_ip_packet():
    """Demonstrate creating and inspecting IP packets."""
    print_section("1. Creating IP Packets")
    
    # Create a basic IP packet
    ip_packet = IP()
    print("[+] Basic IP packet (default values):")
    ip_packet.show()
    
    # Create an IP packet with specific fields
    print("\n[+] IP packet with custom fields:")
    ip_packet_custom = IP(
        dst="192.168.1.1",
        src="192.168.1.100",
        ttl=64
    )
    ip_packet_custom.show()
    
    # Access individual fields
    print(f"\n[+] Accessing fields:")
    print(f"    Destination: {ip_packet_custom.dst}")
    print(f"    Source: {ip_packet_custom.src}")
    print(f"    TTL: {ip_packet_custom.ttl}")
    print(f"    Protocol: {ip_packet_custom.proto}")

def demo_tcp_packet():
    """Demonstrate creating TCP packets."""
    print_section("2. Creating TCP Packets")
    
    # Create a TCP packet
    tcp_packet = TCP()
    print("[+] Basic TCP packet:")
    tcp_packet.show()
    
    # TCP packet with specific ports and flags
    print("\n[+] TCP SYN packet (connection request):")
    tcp_syn = TCP(
        sport=12345,      # Source port
        dport=80,         # Destination port (HTTP)
        flags="S",        # SYN flag
        seq=1000          # Sequence number
    )
    tcp_syn.show()
    
    print(f"\n[+] TCP flags explained:")
    print(f"    S = SYN (synchronize, start connection)")
    print(f"    A = ACK (acknowledge)")
    print(f"    F = FIN (finish, close connection)")
    print(f"    R = RST (reset connection)")
    print(f"    P = PSH (push data)")

def demo_udp_packet():
    """Demonstrate creating UDP packets."""
    print_section("3. Creating UDP Packets")
    
    # Create a UDP packet
    udp_packet = UDP(sport=5353, dport=53)
    print("[+] UDP packet (for DNS query):")
    udp_packet.show()
    
    print(f"\n[+] Common UDP ports:")
    print(f"    53  = DNS")
    print(f"    67  = DHCP Server")
    print(f"    68  = DHCP Client")
    print(f"    123 = NTP")
    print(f"    161 = SNMP")

def demo_icmp_packet():
    """Demonstrate creating ICMP packets."""
    print_section("4. Creating ICMP Packets")
    
    # Create different types of ICMP packets
    icmp_echo = ICMP(type=8, code=0)  # Echo request (ping)
    print("[+] ICMP Echo Request (ping):")
    icmp_echo.show()
    
    icmp_reply = ICMP(type=0, code=0)  # Echo reply
    print("\n[+] ICMP Echo Reply:")
    icmp_reply.show()
    
    print(f"\n[+] Common ICMP types:")
    print(f"    0  = Echo Reply")
    print(f"    3  = Destination Unreachable")
    print(f"    8  = Echo Request (ping)")
    print(f"    11 = Time Exceeded")

def demo_arp_packet():
    """Demonstrate creating ARP packets."""
    print_section("5. Creating ARP Packets")
    
    # ARP request
    arp_request = ARP(
        op=1,  # 1 = request, 2 = reply
        pdst="192.168.1.1"
    )
    print("[+] ARP Request:")
    arp_request.show()
    
    print(f"\n[+] ARP is used to find MAC address from IP address")
    print(f"    op=1: ARP Request (who has this IP?)")
    print(f"    op=2: ARP Reply (I have this IP)")

def demo_packet_summary():
    """Demonstrate packet summary method."""
    print_section("6. Packet Summary")
    
    # Create various packets and show their summaries
    packets = [
        IP(dst="8.8.8.8")/ICMP(),
        IP(dst="192.168.1.1")/TCP(dport=80, flags="S"),
        IP(dst="1.1.1.1")/UDP(dport=53),
        Ether()/ARP(pdst="192.168.1.1")
    ]
    
    print("[+] Packet summaries (one-line description):\n")
    for i, pkt in enumerate(packets, 1):
        print(f"  {i}. {pkt.summary()}")

def demo_packet_fields():
    """Demonstrate accessing all packet fields."""
    print_section("7. Exploring Packet Fields")
    
    # Create a complete packet
    packet = IP(dst="192.168.1.1")/TCP(dport=443, flags="S")
    
    print("[+] Listing all fields in a packet:\n")
    
    # Show IP layer fields
    print("  IP Layer fields:")
    for field in packet[IP].fields:
        value = packet[IP].fields[field]
        print(f"    {field}: {value}")
    
    # Show TCP layer fields
    print("\n  TCP Layer fields:")
    for field in packet[TCP].fields:
        value = packet[TCP].fields[field]
        print(f"    {field}: {value}")

def demo_packet_modification():
    """Demonstrate modifying packet fields."""
    print_section("8. Modifying Packets")
    
    # Create a packet
    packet = IP(dst="8.8.8.8")/ICMP()
    print("[+] Original packet:")
    print(f"    {packet.summary()}")
    
    # Modify fields
    packet[IP].dst = "1.1.1.1"
    packet[IP].ttl = 32
    packet[ICMP].type = 13  # Timestamp request
    
    print("\n[+] Modified packet:")
    print(f"    {packet.summary()}")
    print(f"    New destination: {packet[IP].dst}")
    print(f"    New TTL: {packet[IP].ttl}")
    print(f"    New ICMP type: {packet[ICMP].type}")

def demo_packet_bytes():
    """Demonstrate converting packets to/from bytes."""
    print_section("9. Packet to Bytes Conversion")
    
    # Create a packet
    packet = IP(dst="192.168.1.1")/ICMP()
    
    # Convert to bytes
    packet_bytes = bytes(packet)
    print(f"[+] Packet as bytes (first 40 bytes):")
    print(f"    {packet_bytes[:40].hex()}")
    print(f"    Total length: {len(packet_bytes)} bytes")
    
    # Reconstruct from bytes
    reconstructed = IP(packet_bytes)
    print(f"\n[+] Reconstructed packet:")
    print(f"    {reconstructed.summary()}")

def demo_payload():
    """Demonstrate adding payload to packets."""
    print_section("10. Adding Payload to Packets")
    
    # Create a packet with payload
    packet_with_payload = IP(dst="192.168.1.1")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\n\r\n")
    
    print("[+] Packet with HTTP request payload:")
    packet_with_payload.show()
    
    # Access the payload
    if packet_with_payload.haslayer(Raw):
        payload = packet_with_payload[Raw].load
        print(f"\n[+] Payload content:")
        print(f"    {payload}")

def main():
    """Main function to demonstrate packet basics."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║               PACKET BASICS WITH SCAPY                       ║
║         Learn to Create and Inspect Packets                  ║
╚══════════════════════════════════════════════════════════════╝

This script demonstrates:
  • Creating different types of packets (IP, TCP, UDP, ICMP, ARP)
  • Inspecting packet fields and values
  • Modifying packet attributes
  • Converting packets to/from bytes
  • Adding payload to packets

NOTE: This script doesn't send any packets, so no privileges needed!
    """)
    
    try:
        # Run all demonstrations
        demo_ip_packet()
        demo_tcp_packet()
        demo_udp_packet()
        demo_icmp_packet()
        demo_arp_packet()
        demo_packet_summary()
        demo_packet_fields()
        demo_packet_modification()
        demo_packet_bytes()
        demo_payload()
        
        print("\n" + "="*70)
        print("  Tutorial Complete!")
        print("="*70)
        print("\nWhat you learned:")
        print("  ✓ How to create packets for different protocols")
        print("  ✓ How to access and modify packet fields")
        print("  ✓ How to inspect packet structure")
        print("  ✓ How to work with packet bytes")
        print("\nNext steps:")
        print("  - Learn about layer stacking in layer_stacking.py")
        print("  - Try creating your own custom packets")
        print("  - Experiment with different protocol combinations")
        
    except KeyboardInterrupt:
        print("\n\n[!] Tutorial interrupted by user")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
