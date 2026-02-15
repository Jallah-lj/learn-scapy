#!/usr/bin/env python3
"""
Script Name: packet_sniffing.py
Description: Advanced packet sniffing techniques with filtering and analysis
Author: Learn Scapy Repository
Date: 2024

This script demonstrates intermediate packet sniffing techniques:
- Advanced BPF filtering
- Protocol-specific analysis
- Traffic statistics
- Custom packet filtering
- Real-time traffic monitoring

WARNING: Requires root/administrator privileges.
         Only use on networks you own or have permission to monitor.

Usage:
    sudo python3 packet_sniffing.py
"""

from scapy.all import *
from collections import defaultdict
from datetime import datetime
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

class PacketSniffer:
    """Advanced packet sniffer with statistics and filtering."""
    
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.start_time = None
        
    def analyze_packet(self, packet):
        """Analyze a single packet and update statistics."""
        self.packet_count += 1
        
        if self.start_time is None:
            self.start_time = datetime.now()
        
        # Protocol statistics
        if packet.haslayer(TCP):
            self.protocol_stats['TCP'] += 1
            if packet.haslayer(IP):
                self.port_stats[packet[TCP].dport] += 1
        elif packet.haslayer(UDP):
            self.protocol_stats['UDP'] += 1
            if packet.haslayer(IP):
                self.port_stats[packet[UDP].dport] += 1
        elif packet.haslayer(ICMP):
            self.protocol_stats['ICMP'] += 1
        elif packet.haslayer(ARP):
            self.protocol_stats['ARP'] += 1
        else:
            self.protocol_stats['OTHER'] += 1
        
        # IP statistics
        if packet.haslayer(IP):
            self.ip_stats[packet[IP].src] += 1
    
    def display_packet(self, packet):
        """Display packet information in real-time."""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        info = f"[{timestamp}] Packet #{self.packet_count:4d}"
        
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            proto = "OTHER"
            details = ""
            
            if packet.haslayer(TCP):
                proto = "TCP"
                details = f":{packet[TCP].sport} → :{packet[TCP].dport} [{packet[TCP].flags}]"
            elif packet.haslayer(UDP):
                proto = "UDP"
                details = f":{packet[UDP].sport} → :{packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                details = f" type={packet[ICMP].type}"
            
            info += f" | {proto:5} | {src:15} → {dst:15}{details}"
        
        elif packet.haslayer(ARP):
            info += f" | ARP   | {packet[ARP].psrc:15} → {packet[ARP].pdst:15}"
        
        print(info)
    
    def print_statistics(self):
        """Print collected statistics."""
        print("\n" + "="*70)
        print("  PACKET CAPTURE STATISTICS")
        print("="*70)
        
        if self.start_time:
            duration = (datetime.now() - self.start_time).total_seconds()
            print(f"\nCapture Duration: {duration:.2f} seconds")
            print(f"Total Packets: {self.packet_count}")
            print(f"Average Rate: {self.packet_count/duration:.2f} packets/sec")
        
        # Protocol breakdown
        print("\n[+] Protocol Distribution:")
        for proto, count in sorted(self.protocol_stats.items(), 
                                   key=lambda x: x[1], reverse=True):
            percentage = (count / self.packet_count) * 100
            print(f"    {proto:8} : {count:5} packets ({percentage:5.1f}%)")
        
        # Top talkers
        if self.ip_stats:
            print("\n[+] Top 5 Source IPs:")
            for ip, count in sorted(self.ip_stats.items(), 
                                   key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {ip:15} : {count:5} packets")
        
        # Top ports
        if self.port_stats:
            print("\n[+] Top 5 Destination Ports:")
            for port, count in sorted(self.port_stats.items(), 
                                     key=lambda x: x[1], reverse=True)[:5]:
                port_name = self.get_port_name(port)
                print(f"    {port:5} ({port_name:8}) : {count:5} packets")
    
    @staticmethod
    def get_port_name(port):
        """Get common port name."""
        port_names = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-ALT"
        }
        return port_names.get(port, "UNKNOWN")

def demo_basic_sniffing():
    """Demonstrate basic sniffing with display."""
    print("\n" + "="*70)
    print("  1. Basic Packet Sniffing with Real-time Display")
    print("="*70 + "\n")
    
    print("[+] Capturing 10 packets (any protocol)...")
    print("    Generate traffic: browse web, ping, etc.\n")
    
    sniffer = PacketSniffer()
    
    def callback(pkt):
        sniffer.analyze_packet(pkt)
        sniffer.display_packet(pkt)
    
    sniff(prn=callback, count=10, timeout=15)
    sniffer.print_statistics()

def demo_tcp_traffic():
    """Demonstrate capturing and analyzing TCP traffic."""
    print("\n" + "="*70)
    print("  2. TCP Traffic Analysis")
    print("="*70 + "\n")
    
    print("[+] Capturing TCP packets (10 packets or 15 seconds)...")
    print("    Open websites to generate TCP traffic\n")
    
    sniffer = PacketSniffer()
    
    def tcp_callback(pkt):
        sniffer.analyze_packet(pkt)
        
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            flag_str = []
            
            if flags & 0x02: flag_str.append("SYN")
            if flags & 0x10: flag_str.append("ACK")
            if flags & 0x01: flag_str.append("FIN")
            if flags & 0x04: flag_str.append("RST")
            if flags & 0x08: flag_str.append("PSH")
            
            print(f"[TCP] {pkt[IP].src}:{pkt[TCP].sport} → "
                  f"{pkt[IP].dst}:{pkt[TCP].dport} "
                  f"[{','.join(flag_str)}] Seq:{pkt[TCP].seq}")
    
    sniff(filter="tcp", prn=tcp_callback, count=10, timeout=15)
    sniffer.print_statistics()

def demo_dns_monitoring():
    """Demonstrate monitoring DNS queries."""
    print("\n" + "="*70)
    print("  3. DNS Query Monitoring")
    print("="*70 + "\n")
    
    print("[+] Monitoring DNS queries (10 queries or 20 seconds)...")
    print("    Browse websites to generate DNS queries\n")
    
    def dns_callback(pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            # DNS Query
            if pkt[DNS].qr == 0 and pkt[DNS].qd:
                query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                print(f"[DNS Query] {pkt[IP].src} → {query}")
            
            # DNS Response
            elif pkt[DNS].qr == 1 and pkt[DNS].an:
                query = pkt[DNS].qd.qname.decode('utf-8', errors='ignore')
                # Get first answer
                if pkt[DNS].an:
                    answer = pkt[DNS].an.rdata
                    print(f"[DNS Reply] {query} → {answer}")
    
    sniff(filter="udp port 53", prn=dns_callback, count=10, timeout=20)

def demo_http_traffic():
    """Demonstrate capturing HTTP traffic."""
    print("\n" + "="*70)
    print("  4. HTTP Traffic Monitoring")
    print("="*70 + "\n")
    
    print("[+] Monitoring HTTP requests (5 requests or 20 seconds)...")
    print("    Browse HTTP (not HTTPS) websites\n")
    print("    Note: HTTPS traffic is encrypted and won't show details\n")
    
    def http_callback(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # HTTP Request
                if payload_str.startswith(('GET', 'POST', 'HEAD', 'PUT')):
                    lines = payload_str.split('\r\n')
                    request_line = lines[0]
                    
                    # Extract Host header
                    host = "unknown"
                    for line in lines[1:]:
                        if line.lower().startswith('host:'):
                            host = line.split(':', 1)[1].strip()
                            break
                    
                    print(f"[HTTP Request] {request_line}")
                    print(f"              Host: {host}")
                
                # HTTP Response
                elif payload_str.startswith('HTTP/'):
                    lines = payload_str.split('\r\n')
                    status_line = lines[0]
                    print(f"[HTTP Response] {status_line}")
            
            except:
                pass
    
    sniff(filter="tcp port 80", prn=http_callback, count=5, timeout=20)

def demo_custom_filter():
    """Demonstrate custom packet filtering."""
    print("\n" + "="*70)
    print("  5. Custom Packet Filtering")
    print("="*70 + "\n")
    
    print("[+] Capturing packets with custom filter...")
    print("    Filter: Large packets (>500 bytes) OR SSH traffic\n")
    
    def custom_filter(pkt):
        """Custom filter function."""
        # Large packets
        if len(pkt) > 500:
            return True
        
        # SSH traffic
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                return True
        
        return False
    
    def display_callback(pkt):
        size = len(pkt)
        proto = "UNKNOWN"
        
        if pkt.haslayer(TCP):
            proto = f"TCP:{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            proto = f"UDP:{pkt[UDP].dport}"
        
        print(f"[Captured] Size: {size:4} bytes | Protocol: {proto}")
    
    packets = sniff(lfilter=custom_filter, prn=display_callback, 
                   count=5, timeout=15)
    
    print(f"\n[✓] Captured {len(packets)} packets matching criteria")

def demo_save_filtered():
    """Demonstrate saving filtered packets."""
    print("\n" + "="*70)
    print("  6. Saving Filtered Packets")
    print("="*70 + "\n")
    
    print("[+] Capturing web traffic (HTTP/HTTPS) to save...")
    
    packets = sniff(filter="tcp port 80 or tcp port 443", 
                   count=5, timeout=15)
    
    if packets:
        filename = "/tmp/web_traffic.pcap"
        wrpcap(filename, packets)
        print(f"\n[✓] Saved {len(packets)} packets to {filename}")
        print(f"    Analyze with: wireshark {filename}")
        print(f"    Or in Python: rdpcap('{filename}')")
    else:
        print("\n[!] No web traffic captured")

def main():
    """Main function."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║          ADVANCED PACKET SNIFFING WITH SCAPY                 ║
║        Filtering, Analysis, and Traffic Monitoring          ║
╚══════════════════════════════════════════════════════════════╝

This script demonstrates:
  • Real-time packet display with statistics
  • Protocol-specific analysis (TCP, DNS, HTTP)
  • Custom packet filtering
  • Traffic statistics and reporting
  • Saving filtered packets

⚠️  WARNING: Requires root/admin privileges.
    Only use on networks you own or have permission to monitor!
    """)
    
    if not check_privileges():
        print("[✗] Error: Root/administrator privileges required")
        print("    Run with: sudo python3 packet_sniffing.py")
        sys.exit(1)
    
    print("[✓] Running with appropriate privileges")
    
    try:
        demo_basic_sniffing()
        demo_tcp_traffic()
        demo_dns_monitoring()
        demo_http_traffic()
        demo_custom_filter()
        demo_save_filtered()
        
        print("\n" + "="*70)
        print("  All Demonstrations Complete!")
        print("="*70)
        print("\nWhat you learned:")
        print("  ✓ Advanced packet capture techniques")
        print("  ✓ Protocol-specific filtering and analysis")
        print("  ✓ Real-time traffic statistics")
        print("  ✓ Custom packet filtering")
        print("\nNext steps:")
        print("  - Build your own packet analyzer")
        print("  - Explore advanced examples")
        print("  - Create custom monitoring tools")
        
    except KeyboardInterrupt:
        print("\n\n[!] Script interrupted by user")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
