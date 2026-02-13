#!/usr/bin/env python3
"""
Port Scanner using Scapy
=========================
This script demonstrates how to scan for open ports on a target host.

⚠️  ETHICAL USE ONLY: Only scan hosts you own or have explicit permission to scan.
⚠️  Unauthorized port scanning is illegal in many jurisdictions.

Author: learn-scapy project
Date: 2026-02-13
"""

from scapy.all import *
import sys


def tcp_syn_scan(target_ip, port):
    """
    Perform a TCP SYN scan on a single port
    
    Args:
        target_ip: Target IP address
        port: Port number to scan
        
    Returns:
        True if port is open, False otherwise
    """
    # Create SYN packet
    syn_packet = IP(dst=target_ip)/TCP(dport=port, flags='S')
    
    # Send packet and wait for response
    response = sr1(syn_packet, timeout=1, verbose=0)
    
    # Check if we got a response
    if response is None:
        return False
    
    # Check if port is open (SYN-ACK response)
    if response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            # Send RST to close connection
            rst_packet = IP(dst=target_ip)/TCP(dport=port, flags='R')
            send(rst_packet, verbose=0)
            return True
        elif response.getlayer(TCP).flags == 0x14:  # RST-ACK
            return False
    
    return False

def scan_ports(target_ip, port_range):
    """
    Scan a range of ports on target IP
    
    Args:
        target_ip: Target IP address
        port_range: List or range of ports to scan
    """
    print(f"\n{'='*60}")
    print(f"Scanning {target_ip}")
    print(f"{'='*60}\n")
    
    open_ports = []
    
    for port in port_range:
        sys.stdout.write(f"\rScanning port {port}...")
        sys.stdout.flush()
        
        if tcp_syn_scan(target_ip, port):
            open_ports.append(port)
            print(f"\r[+] Port {port} is OPEN")
    
    print(f"\n{'='*60}")
    print("Scan Complete!")
    print(f"{'='*60}")
    
    if open_ports:
        print(f"\n✅ Found {len(open_ports)} open port(s):")
        for port in open_ports:
            print(f"  • Port {port}")
    else:
        print("\n❌ No open ports found")

def scan_common_ports(target_ip):
    """Scan commonly used ports"""
    common_ports = [
        21,   # FTP
        22,   # SSH
        23,   # Telnet
        25,   # SMTP
        53,   # DNS
        80,   # HTTP
        110,  # POP3
        143,  # IMAP
        443,  # HTTPS
        3306, # MySQL
        3389, # RDP
        5432, # PostgreSQL
        8080, # HTTP Alternate
    ]
    
    print("\n🔍 Scanning common ports...")
    scan_ports(target_ip, common_ports)

def main():
    """Main function"""
    print("🎓 TCP Port Scanner using Scapy")
    print("⚠️  Use responsibly and ethically!\n")
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("❌ This script requires root/administrator privileges")
        print("Please run with sudo or as Administrator")
        sys.exit(1)
    
    # Example usage
    target = "127.0.0.1"  # Localhost for safe testing
    
    print(f"Target: {target}")
    print("⚠️  Make sure you have permission to scan this host!\n")
    
    # Scan common ports
    scan_common_ports(target)
    
    print("\n💡 How it works:")
    print("  1. Sends TCP SYN packet to each port")
    print("  2. Waits for SYN-ACK response (port open)")
    print("  3. Sends RST to close connection")
    print("  4. No response or RST-ACK means port is closed")
    
    print("\n📚 Learn more:")
    print("  - SYN scan is also called 'half-open' scan")
    print("  - It's stealthier than full TCP connection")
    print("  - But still detectable by IDS/IPS systems")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)