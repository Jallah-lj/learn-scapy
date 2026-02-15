#!/usr/bin/env python3
"""
Script Name: basic_sniffing.py
Description: Learn how to capture and analyze network packets with Scapy
Author: Learn Scapy Repository
Date: 2024

Packet sniffing (capturing) is one of Scapy's most powerful features.
This script demonstrates:
- Basic packet capture with sniff()
- Filtering packets by protocol
- Analyzing captured packets
- Using callback functions
- Saving captured packets

WARNING: Packet sniffing requires root/administrator privileges.
         Only capture traffic on networks you own or have permission to monitor.

Usage:
    sudo python3 basic_sniffing.py
"""

from scapy.all import *
import sys
from datetime import datetime

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

def demo_basic_sniff():
    """Demonstrate basic packet sniffing."""
    print_section("1. Basic Packet Sniffing")
    
    print("""[+] sniff() captures packets from the network
    - Captures all traffic on the interface
    - Can filter by protocol, port, etc.
    - Returns a list of captured packets\n""")
    
    print("[+] Capturing 5 packets (any type)...")
    print("    (Generate some traffic: open a webpage, ping something)")
    
    # Capture 5 packets
    packets = sniff(count=5, timeout=10)
    
    print(f"\n[✓] Captured {len(packets)} packets")
    
    if packets:
        print("\n[+] Packet summaries:")
        for i, pkt in enumerate(packets, 1):
            print(f"    {i}. {pkt.summary()}")
    
    return packets

def demo_filter_by_protocol():
    """Demonstrate filtering packets by protocol."""
    print_section("2. Filtering by Protocol")
    
    print("""[+] BPF (Berkeley Packet Filter) syntax for filtering:
    - 'tcp'      - Only TCP packets
    - 'udp'      - Only UDP packets
    - 'icmp'     - Only ICMP packets
    - 'arp'      - Only ARP packets
    - 'ip'       - Only IP packets\n""")
    
    print("[+] Capturing 3 TCP packets...")
    print("    (Open a webpage to generate TCP traffic)")
    
    # Capture only TCP packets
    tcp_packets = sniff(filter="tcp", count=3, timeout=10)
    
    print(f"\n[✓] Captured {len(tcp_packets)} TCP packets")
    
    if tcp_packets:
        print("\n[+] TCP packet details:")
        for pkt in tcp_packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                print(f"    {pkt[IP].src}:{pkt[TCP].sport} → "
                      f"{pkt[IP].dst}:{pkt[TCP].dport} "
                      f"[{pkt[TCP].flags}]")

def demo_filter_by_port():
    """Demonstrate filtering by port."""
    print_section("3. Filtering by Port")
    
    print("""[+] Filter by specific ports:
    - 'port 80'        - HTTP traffic
    - 'port 443'       - HTTPS traffic
    - 'port 53'        - DNS traffic
    - 'tcp port 22'    - SSH traffic
    - 'dst port 80'    - Traffic TO port 80\n""")
    
    print("[+] Capturing 3 packets on port 80 or 443 (web traffic)...")
    print("    (Browse a website to generate traffic)")
    
    # Capture web traffic
    web_packets = sniff(filter="tcp port 80 or tcp port 443", count=3, timeout=10)
    
    print(f"\n[✓] Captured {len(web_packets)} web packets")
    
    if web_packets:
        print("\n[+] Web traffic:")
        for pkt in web_packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                port = pkt[TCP].dport
                proto = "HTTP" if port == 80 else "HTTPS"
                print(f"    {proto}: {pkt[IP].src} → {pkt[IP].dst}")

def demo_callback_function():
    """Demonstrate using callback functions."""
    print_section("4. Using Callback Functions")
    
    print("""[+] Callback functions process packets in real-time
    - Function called for each captured packet
    - Useful for live analysis
    - Can take action based on packet content\n""")
    
    # Define a callback function
    packet_count = [0]  # Use list to modify in nested function
    
    def packet_callback(pkt):
        """Process each packet as it's captured."""
        packet_count[0] += 1
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Analyze packet
        if pkt.haslayer(IP):
            protocol = "OTHER"
            if pkt.haslayer(TCP):
                protocol = "TCP"
            elif pkt.haslayer(UDP):
                protocol = "UDP"
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
            
            print(f"    [{timestamp}] {protocol:5} | "
                  f"{pkt[IP].src:15} → {pkt[IP].dst:15} | "
                  f"Size: {len(pkt):4} bytes")
    
    print("[+] Capturing packets with callback (5 packets)...")
    print("    (Real-time display)")
    print()
    
    # Sniff with callback
    sniff(prn=packet_callback, count=5, timeout=10)
    
    print(f"\n[✓] Processed {packet_count[0]} packets")

def demo_packet_analysis():
    """Demonstrate analyzing captured packets."""
    print_section("5. Analyzing Captured Packets")
    
    print("[+] Capturing 3 packets for detailed analysis...")
    
    packets = sniff(count=3, timeout=10)
    
    if packets:
        print(f"\n[✓] Analyzing {len(packets)} packets\n")
        
        for i, pkt in enumerate(packets, 1):
            print(f"[Packet {i}]")
            print(f"  Summary: {pkt.summary()}")
            
            # Layer analysis
            if pkt.haslayer(Ether):
                print(f"  Ethernet: {pkt[Ether].src} → {pkt[Ether].dst}")
            
            if pkt.haslayer(IP):
                print(f"  IP: {pkt[IP].src} → {pkt[IP].dst}")
                print(f"      Protocol: {pkt[IP].proto}, TTL: {pkt[IP].ttl}")
            
            if pkt.haslayer(TCP):
                print(f"  TCP: Port {pkt[TCP].sport} → {pkt[TCP].dport}")
                print(f"       Flags: {pkt[TCP].flags}")
            
            if pkt.haslayer(UDP):
                print(f"  UDP: Port {pkt[UDP].sport} → {pkt[UDP].dport}")
            
            if pkt.haslayer(Raw):
                payload = pkt[Raw].load[:50]  # First 50 bytes
                print(f"  Payload: {payload}")
            
            print()

def demo_save_packets():
    """Demonstrate saving captured packets."""
    print_section("6. Saving Captured Packets")
    
    print("""[+] Save packets to PCAP files for later analysis
    - wrpcap() writes packets to file
    - rdpcap() reads packets from file
    - Compatible with Wireshark\n""")
    
    print("[+] Capturing 5 packets to save...")
    
    packets = sniff(count=5, timeout=10)
    
    if packets:
        filename = "/tmp/captured_packets.pcap"
        wrpcap(filename, packets)
        print(f"\n[✓] Saved {len(packets)} packets to {filename}")
        
        # Read them back
        loaded_packets = rdpcap(filename)
        print(f"[✓] Loaded {len(loaded_packets)} packets from file")
        
        print("\n[+] You can analyze this file with:")
        print(f"    - Wireshark: wireshark {filename}")
        print(f"    - tcpdump: tcpdump -r {filename}")
        print(f"    - Scapy: rdpcap('{filename}')")

def demo_sniff_options():
    """Demonstrate various sniff() options."""
    print_section("7. Sniff Options and Parameters")
    
    print("""[+] Common sniff() parameters:

  count=N           - Stop after N packets
  timeout=N         - Stop after N seconds
  filter="..."      - BPF filter string
  prn=func          - Callback function for each packet
  iface="eth0"      - Specific network interface
  store=False       - Don't store packets (save memory)
  
[+] Filter examples:

  "tcp"                      - All TCP packets
  "udp and port 53"          - DNS queries/responses
  "icmp"                     - Ping packets
  "tcp and dst port 80"      - HTTP requests
  "src host 192.168.1.1"     - From specific IP
  "net 192.168.1.0/24"       - Specific subnet
  "not arp"                  - Everything except ARP
  "tcp[13] & 2 != 0"         - TCP SYN packets (advanced)
    """)

def demo_live_monitoring():
    """Demonstrate live packet monitoring."""
    print_section("8. Live Packet Monitoring")
    
    print("""[+] Monitor packets in real-time (press Ctrl+C to stop)
    
    This is useful for:
    - Debugging network issues
    - Monitoring specific traffic
    - Real-time security monitoring\n""")
    
    print("[+] Monitoring HTTP/HTTPS traffic for 10 seconds...")
    print("    (Browse websites to see traffic)")
    print()
    
    def monitor_callback(pkt):
        """Monitor and display web traffic."""
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            
            if dport == 80 or sport == 80:
                print(f"    [HTTP]  {pkt[IP].src}:{sport} → "
                      f"{pkt[IP].dst}:{dport}")
            elif dport == 443 or sport == 443:
                print(f"    [HTTPS] {pkt[IP].src}:{sport} → "
                      f"{pkt[IP].dst}:{dport}")
    
    try:
        sniff(filter="tcp port 80 or tcp port 443", 
              prn=monitor_callback, 
              timeout=10, 
              store=False)
        print("\n[✓] Monitoring complete")
    except KeyboardInterrupt:
        print("\n[!] Monitoring stopped by user")

def main():
    """Main function."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║            PACKET SNIFFING WITH SCAPY                        ║
║          Learn to Capture and Analyze Packets               ║
╚══════════════════════════════════════════════════════════════╝

This script demonstrates:
  • Basic packet capture with sniff()
  • Filtering by protocol and port
  • Using callback functions
  • Analyzing packet contents
  • Saving packets to files

⚠️  WARNING: Packet sniffing requires root/admin privileges.
    Only capture traffic on networks you own or have permission!
    """)
    
    if not check_privileges():
        print("[✗] Error: Root/administrator privileges required")
        print("    Run with: sudo python3 basic_sniffing.py")
        sys.exit(1)
    
    print("[✓] Running with appropriate privileges\n")
    
    try:
        demo_basic_sniff()
        demo_filter_by_protocol()
        demo_filter_by_port()
        demo_callback_function()
        demo_packet_analysis()
        demo_save_packets()
        demo_sniff_options()
        demo_live_monitoring()
        
        print("\n" + "="*70)
        print("  Tutorial Complete!")
        print("="*70)
        print("\nWhat you learned:")
        print("  ✓ How to capture packets with sniff()")
        print("  ✓ Filtering packets by protocol and port")
        print("  ✓ Using callback functions for real-time processing")
        print("  ✓ Analyzing and saving captured packets")
        print("\nNext steps:")
        print("  - Explore intermediate examples")
        print("  - Learn about advanced filtering")
        print("  - Build your own packet sniffer tool")
        
    except KeyboardInterrupt:
        print("\n\n[!] Script interrupted by user")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
