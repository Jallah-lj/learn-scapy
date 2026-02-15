#!/usr/bin/env python3
"""
Script Name: sending_packets.py
Description: Learn different methods to send packets with Scapy
Author: Learn Scapy Repository
Date: 2024

Scapy provides several functions for sending packets, each with different
behaviors and use cases. This script demonstrates:
- send() - Send packets at layer 3 (IP)
- sendp() - Send packets at layer 2 (Ethernet)
- sr() - Send and receive multiple packets
- sr1() - Send and receive one packet
- srp() - Send and receive at layer 2

WARNING: This script sends actual network packets. Use responsibly!
         Requires root/administrator privileges.

Usage:
    sudo python3 sending_packets.py
"""

from scapy.all import *
import sys

def check_privileges():
    """Check if script has necessary privileges."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.close()
        return True
    except PermissionError:
        return False

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def demo_send():
    """Demonstrate send() function - Send packets at layer 3."""
    print_section("1. send() - Send at Layer 3 (IP)")
    
    print("""[+] send() sends packets at the IP layer (Layer 3)
    - Does NOT wait for responses
    - Returns None
    - Fast for sending many packets
    - Use when you don't need responses\n""")
    
    target = "8.8.8.8"
    print(f"[+] Sending ICMP ping to {target}...")
    
    packet = IP(dst=target)/ICMP()
    print(f"    Packet: {packet.summary()}")
    
    # Send the packet (no response received)
    send(packet, verbose=0)
    print("    [✓] Packet sent!")
    
    print("\n[+] Sending multiple packets:")
    packet2 = IP(dst=target)/ICMP(id=100, seq=1)
    packet3 = IP(dst=target)/ICMP(id=100, seq=2)
    
    # Send multiple packets at once
    send([packet2, packet3], verbose=0)
    print("    [✓] 2 packets sent!")

def demo_sendp():
    """Demonstrate sendp() function - Send at layer 2."""
    print_section("2. sendp() - Send at Layer 2 (Ethernet)")
    
    print("""[+] sendp() sends packets at the Ethernet layer (Layer 2)
    - Sends raw Ethernet frames
    - Used for ARP, custom L2 protocols
    - Requires Ether() layer
    - Does NOT wait for responses\n""")
    
    print("[+] Sending ARP request...")
    
    # Create ARP request packet
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1")
    print(f"    Packet: {arp_packet.summary()}")
    
    # Note: This might fail if not on the right network
    try:
        sendp(arp_packet, verbose=0)
        print("    [✓] ARP packet sent!")
    except Exception as e:
        print(f"    [!] Could not send (not on local network): {e}")

def demo_sr1():
    """Demonstrate sr1() function - Send and receive one packet."""
    print_section("3. sr1() - Send and Receive ONE Packet")
    
    print("""[+] sr1() sends a packet and waits for ONE response
    - Returns the first response received
    - Times out if no response
    - Perfect for request/reply protocols
    - Most commonly used function\n""")
    
    target = "8.8.8.8"
    print(f"[+] Sending ping to {target} and waiting for reply...")
    
    packet = IP(dst=target)/ICMP()
    print(f"    Packet: {packet.summary()}")
    
    # Send and receive one packet
    response = sr1(packet, timeout=2, verbose=0)
    
    if response:
        print(f"    [✓] Received response!")
        print(f"    Response: {response.summary()}")
        print(f"    Response time: measured by Scapy")
    else:
        print(f"    [✗] No response (timeout)")

def demo_sr():
    """Demonstrate sr() function - Send and receive multiple packets."""
    print_section("4. sr() - Send and Receive Multiple Packets")
    
    print("""[+] sr() sends packets and collects multiple responses
    - Returns (answered, unanswered) tuples
    - Waits for timeout or all responses
    - Good for scanning multiple targets
    - More powerful than sr1()\n""")
    
    print("[+] Pinging multiple hosts...")
    
    # Create multiple ICMP packets
    packets = [
        IP(dst="8.8.8.8")/ICMP(),
        IP(dst="1.1.1.1")/ICMP(),
        IP(dst="8.8.4.4")/ICMP()
    ]
    
    print("    Targets: 8.8.8.8, 1.1.1.1, 8.8.4.4")
    
    # Send and receive
    answered, unanswered = sr(packets, timeout=2, verbose=0)
    
    print(f"\n    [✓] Received {len(answered)} responses")
    print(f"    [✗] {len(unanswered)} packets unanswered")
    
    if answered:
        print("\n    Responses:")
        for sent, received in answered:
            print(f"      {received[IP].src} replied")

def demo_srp():
    """Demonstrate srp() function - Send and receive at layer 2."""
    print_section("5. srp() - Send and Receive at Layer 2")
    
    print("""[+] srp() sends at Layer 2 and collects responses
    - Like sr() but for Ethernet layer
    - Used for ARP scanning
    - Requires Ether() layer
    - Returns (answered, unanswered)\n""")
    
    print("[+] ARP scanning local network...")
    print("    Note: This only works on your local network")
    
    # Create ARP request for local network
    # This is just a demonstration - actual network may differ
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1/24")
    
    try:
        print(f"    Packet: {arp_request.summary()}")
        print("    [!] Skipping actual send (may not be on correct network)")
        # answered, unanswered = srp(arp_request, timeout=2, verbose=0)
        # print(f"    [✓] Found {len(answered)} hosts")
    except Exception as e:
        print(f"    [!] Error: {e}")

def demo_timing():
    """Demonstrate timing and performance considerations."""
    print_section("6. Timing and Performance")
    
    print("""[+] Considerations when sending packets:\n""")
    
    print("  • timeout parameter:")
    print("    - How long to wait for responses")
    print("    - Default is usually 2 seconds")
    print("    - Increase for slow networks")
    
    print("\n  • inter parameter:")
    print("    - Delay between packets")
    print("    - Useful to avoid flooding")
    print("    - Example: sr(packets, inter=0.1)  # 0.1s delay")
    
    print("\n  • verbose parameter:")
    print("    - 0 = silent")
    print("    - 1 = normal (default)")
    print("    - 2 = verbose")
    
    print("\n[+] Performance comparison:")
    print("""
    send()    - Fastest (no waiting)
    sr1()     - Fast (one response)
    sr()      - Medium (multiple responses)
    sendp()   - Fast (no waiting, L2)
    srp()     - Medium (multiple responses, L2)
    """)

def demo_advanced_options():
    """Demonstrate advanced sending options."""
    print_section("7. Advanced Options")
    
    print("[+] Common parameters for sending functions:\n")
    
    examples = [
        ("timeout=5", "Wait up to 5 seconds for responses"),
        ("inter=0.5", "Wait 0.5 seconds between packets"),
        ("retry=2", "Retry unanswered packets 2 times"),
        ("verbose=0", "Silent mode (no output)"),
        ("iface='eth0'", "Send on specific interface"),
        ("count=3", "Send packet 3 times"),
    ]
    
    for param, description in examples:
        print(f"    {param:20} - {description}")
    
    print("\n[+] Example with options:")
    print("""
    response = sr1(
        IP(dst="8.8.8.8")/ICMP(),
        timeout=5,
        verbose=0,
        retry=2
    )
    """)

def demo_function_summary():
    """Provide a summary of all sending functions."""
    print_section("8. Function Summary and When to Use")
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║  Function  │  Layer  │  Returns Response  │  Use Case             ║
╠════════════════════════════════════════════════════════════════════╣
║  send()    │  L3(IP) │  No                │  Fire and forget      ║
║  sendp()   │  L2(Eth)│  No                │  L2 fire and forget   ║
║  sr1()     │  L3(IP) │  First response    │  Single request/reply ║
║  sr()      │  L3(IP) │  All responses     │  Multiple targets     ║
║  srp()     │  L2(Eth)│  All responses     │  ARP, L2 scanning     ║
╚════════════════════════════════════════════════════════════════════╝
    """)
    
    print("[+] Quick decision guide:")
    print("""
    Need a response?
      ├─ No  → use send() or sendp()
      └─ Yes
          ├─ One packet   → use sr1()
          └─ Many packets → use sr() or srp()
    
    Working at Layer 2 (Ethernet)?
      └─ Yes → use sendp() or srp()
    """)

def main():
    """Main function."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║            SENDING PACKETS WITH SCAPY                        ║
║        Learn Different Methods to Send Packets              ║
╚══════════════════════════════════════════════════════════════╝

This script demonstrates:
  • send()  - Send packets at layer 3 (no response)
  • sendp() - Send packets at layer 2 (no response)
  • sr1()   - Send and receive ONE packet
  • sr()    - Send and receive multiple packets
  • srp()   - Send and receive at layer 2

⚠️  WARNING: This script sends real network packets!
    Only use on networks you own or have permission to test.
    """)
    
    if not check_privileges():
        print("[✗] Error: Root/administrator privileges required")
        print("    Run with: sudo python3 sending_packets.py")
        sys.exit(1)
    
    print("[✓] Running with appropriate privileges\n")
    
    try:
        demo_send()
        demo_sendp()
        demo_sr1()
        demo_sr()
        demo_srp()
        demo_timing()
        demo_advanced_options()
        demo_function_summary()
        
        print("\n" + "="*70)
        print("  Tutorial Complete!")
        print("="*70)
        print("\nWhat you learned:")
        print("  ✓ Different methods to send packets")
        print("  ✓ When to use each function")
        print("  ✓ How to handle responses")
        print("  ✓ Advanced options and timing")
        print("\nNext steps:")
        print("  - Learn about packet sniffing in basic_sniffing.py")
        print("  - Practice with different sending methods")
        print("  - Explore intermediate examples")
        
    except KeyboardInterrupt:
        print("\n\n[!] Script interrupted by user")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
