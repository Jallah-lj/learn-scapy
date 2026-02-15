#!/usr/bin/env python3
"""
Script Name: hello_scapy.py
Description: Your first Scapy script - Send an ICMP ping packet
Author: Learn Scapy Repository
Date: 2024

This is the simplest possible Scapy script. It creates an ICMP (ping) packet
and sends it to a target host, then waits for a response.

WARNING: This script requires root/administrator privileges to send packets.

Usage:
    sudo python3 hello_scapy.py
    
Educational Purpose:
    - Learn how to import Scapy
    - Create a simple packet
    - Send a packet and receive a response
    - Display packet information
"""

from scapy.all import *
import sys

def check_privileges():
    """Check if script is running with sufficient privileges."""
    try:
        # Try to create a raw socket (requires root/admin)
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.close()
        return True
    except PermissionError:
        return False

def ping_host(target="8.8.8.8"):
    """
    Send an ICMP ping to a target host.
    
    Args:
        target (str): IP address or hostname to ping
        
    Returns:
        bool: True if ping successful, False otherwise
    """
    print(f"\n{'='*60}")
    print(f"  Welcome to Scapy! Your First Packet Manipulation Script")
    print(f"{'='*60}\n")
    
    print(f"[+] Target: {target}")
    print(f"[+] Creating ICMP ping packet...\n")
    
    # Create an IP packet with ICMP layer
    # IP(dst=target) creates an IP header with destination
    # ICMP() creates an ICMP echo request (ping)
    packet = IP(dst=target)/ICMP()
    
    # Display the packet we created
    print("[+] Packet structure:")
    print("-" * 60)
    packet.show()
    print("-" * 60)
    
    print("\n[+] Sending packet and waiting for response...")
    
    try:
        # sr1() = Send and Receive 1 packet
        # timeout=2 means wait up to 2 seconds for response
        # verbose=1 shows minimal output
        response = sr1(packet, timeout=2, verbose=0)
        
        if response:
            print("\n[✓] SUCCESS! Received response:")
            print("-" * 60)
            response.show()
            print("-" * 60)
            
            # Extract useful information
            if response.haslayer(ICMP):
                icmp_type = response[ICMP].type
                icmp_code = response[ICMP].code
                print(f"\n[+] ICMP Type: {icmp_type} (0 = Echo Reply)")
                print(f"[+] ICMP Code: {icmp_code}")
                
            print(f"[+] Response from: {response[IP].src}")
            print(f"[+] TTL: {response[IP].ttl}")
            
            return True
        else:
            print("\n[✗] No response received (timeout)")
            return False
            
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        return False

def main():
    """Main function to run the hello_scapy example."""
    print("""
╔═══════════════════════════════════════════════════════════╗
║                   HELLO SCAPY!                            ║
║          Your First Network Packet Script                 ║
╚═══════════════════════════════════════════════════════════╝

This script demonstrates:
  1. Creating a packet (IP + ICMP)
  2. Sending the packet to a target
  3. Receiving and displaying the response

SAFETY NOTE: This script only sends a single ping packet,
             which is harmless. However, always use on networks
             you own or have permission to test!
    """)
    
    # Check for root/admin privileges
    if not check_privileges():
        print("[✗] Error: This script requires root/administrator privileges")
        print("    Run with: sudo python3 hello_scapy.py")
        sys.exit(1)
    
    try:
        # You can change the target here
        target = "8.8.8.8"  # Google's public DNS
        
        # Send the ping
        success = ping_host(target)
        
        if success:
            print("\n" + "="*60)
            print("  Congratulations! You've sent your first Scapy packet!")
            print("="*60)
            print("\nWhat happened:")
            print("  1. We created an IP packet with destination 8.8.8.8")
            print("  2. We added an ICMP (ping) layer to it")
            print("  3. We sent it using sr1() and got a response")
            print("  4. We analyzed the response packet")
            print("\nNext steps:")
            print("  - Try changing the target to another IP")
            print("  - Examine packet_basics.py to learn more")
            print("  - Read the documentation in docs/03-basic-concepts.md")
            
    except KeyboardInterrupt:
        print("\n\n[!] Script interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[✗] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
