#!/usr/bin/env python3
"""
Script Name: dns_query.py
Description: Learn DNS queries and responses with Scapy
Author: Learn Scapy Repository
Date: 2024

This script demonstrates DNS operations with Scapy:
- Creating DNS queries
- Sending DNS requests
- Parsing DNS responses
- Different DNS record types
- Custom DNS servers
- DNS troubleshooting

WARNING: Requires root/administrator privileges for raw packet sending.

Usage:
    sudo python3 dns_query.py
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

def demo_basic_dns_query():
    """Demonstrate basic DNS query."""
    print_section("1. Basic DNS Query (A Record)")
    
    print("[+] Creating DNS query for google.com...")
    
    # Create DNS query packet
    dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    
    print("[+] Packet structure:")
    dns_query.show()
    
    print("\n[+] Sending query and waiting for response...")
    
    try:
        response = sr1(dns_query, timeout=3, verbose=0)
        
        if response and response.haslayer(DNS):
            print("\n[✓] Received DNS response!")
            
            # Extract answers
            if response[DNS].ancount > 0:
                print(f"\n[+] Answers ({response[DNS].ancount} record(s)):")
                
                for i in range(response[DNS].ancount):
                    answer = response[DNS].an[i]
                    print(f"    {i+1}. {answer.rrname.decode()} → {answer.rdata}")
            else:
                print("[!] No answers in response")
        else:
            print("[✗] No response received")
    
    except Exception as e:
        print(f"[✗] Error: {e}")

def demo_dns_record_types():
    """Demonstrate different DNS record types."""
    print_section("2. Different DNS Record Types")
    
    queries = [
        ("google.com", "A", "IPv4 address"),
        ("google.com", "AAAA", "IPv6 address"),
        ("google.com", "MX", "Mail exchange"),
        ("google.com", "NS", "Name servers"),
        ("google.com", "TXT", "Text records"),
    ]
    
    print("[+] Querying different record types:\n")
    
    for domain, qtype, description in queries:
        print(f"  [{qtype:4}] {domain} ({description})")
        
        try:
            # Create query with specific type
            dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
                rd=1, 
                qd=DNSQR(qname=domain, qtype=qtype)
            )
            
            response = sr1(dns_query, timeout=2, verbose=0)
            
            if response and response.haslayer(DNS) and response[DNS].ancount > 0:
                # Display first answer
                answer = response[DNS].an[0]
                result = answer.rdata
                
                # Format MX records specially
                if qtype == "MX" and hasattr(answer, 'exchange'):
                    result = f"{answer.preference} {answer.exchange.decode()}"
                # Format NS records
                elif qtype == "NS":
                    result = answer.rdata.decode() if isinstance(answer.rdata, bytes) else answer.rdata
                # Format TXT records
                elif qtype == "TXT":
                    result = answer.rdata
                
                print(f"        → {result}")
            else:
                print(f"        → No records found")
        
        except Exception as e:
            print(f"        → Error: {e}")
        
        print()

def demo_reverse_dns():
    """Demonstrate reverse DNS lookup."""
    print_section("3. Reverse DNS Lookup (PTR Record)")
    
    ip_address = "8.8.8.8"
    print(f"[+] Reverse lookup for {ip_address}...")
    
    # Convert IP to PTR format (8.8.8.8 → 8.8.8.8.in-addr.arpa)
    ip_parts = ip_address.split('.')
    ptr_name = '.'.join(reversed(ip_parts)) + '.in-addr.arpa'
    
    print(f"    PTR query: {ptr_name}")
    
    try:
        dns_query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
            rd=1,
            qd=DNSQR(qname=ptr_name, qtype="PTR")
        )
        
        response = sr1(dns_query, timeout=3, verbose=0)
        
        if response and response.haslayer(DNS) and response[DNS].ancount > 0:
            hostname = response[DNS].an[0].rdata
            print(f"\n[✓] {ip_address} → {hostname.decode() if isinstance(hostname, bytes) else hostname}")
        else:
            print("\n[!] No PTR record found")
    
    except Exception as e:
        print(f"\n[✗] Error: {e}")

def demo_multiple_queries():
    """Demonstrate querying multiple domains."""
    print_section("4. Multiple DNS Queries")
    
    domains = ["google.com", "github.com", "python.org", "scapy.net"]
    
    print("[+] Querying multiple domains:\n")
    
    # Create multiple query packets
    queries = []
    for domain in domains:
        query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        queries.append(query)
    
    print(f"    Sending {len(queries)} queries...")
    
    # Send all queries and collect responses
    answered, unanswered = sr(queries, timeout=3, verbose=0)
    
    print(f"    Received {len(answered)} responses\n")
    
    if answered:
        print("[+] Results:")
        for sent, received in answered:
            if received.haslayer(DNS) and received[DNS].ancount > 0:
                domain = sent[DNS].qd.qname.decode()
                ip = received[DNS].an[0].rdata
                print(f"    {domain:20} → {ip}")

def demo_custom_dns_server():
    """Demonstrate using different DNS servers."""
    print_section("5. Using Different DNS Servers")
    
    dns_servers = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("208.67.222.222", "OpenDNS"),
    ]
    
    domain = "example.com"
    print(f"[+] Querying {domain} using different DNS servers:\n")
    
    for dns_ip, dns_name in dns_servers:
        print(f"  [{dns_name}]")
        
        try:
            query = IP(dst=dns_ip)/UDP(dport=53)/DNS(
                rd=1,
                qd=DNSQR(qname=domain)
            )
            
            response = sr1(query, timeout=2, verbose=0)
            
            if response and response.haslayer(DNS) and response[DNS].ancount > 0:
                ip = response[DNS].an[0].rdata
                print(f"    {domain} → {ip}")
            else:
                print(f"    No response")
        
        except Exception as e:
            print(f"    Error: {e}")
        
        print()

def demo_dns_flags():
    """Demonstrate DNS flags and options."""
    print_section("6. DNS Flags and Options")
    
    print("""[+] DNS Flags:
    
    rd (Recursion Desired)    - Ask server to resolve recursively
    ra (Recursion Available)  - Server can do recursive queries
    aa (Authoritative Answer) - Response from authoritative server
    tc (Truncated)            - Message was truncated
    qr (Query/Response)       - 0=query, 1=response
    """)
    
    domain = "google.com"
    print(f"[+] Querying {domain} with recursion flag...")
    
    query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
        rd=1,  # Recursion desired
        qd=DNSQR(qname=domain)
    )
    
    response = sr1(query, timeout=3, verbose=0)
    
    if response and response.haslayer(DNS):
        dns = response[DNS]
        print(f"\n[+] Response flags:")
        print(f"    QR (Query/Response): {dns.qr} (1=response)")
        print(f"    RD (Recursion Desired): {dns.rd}")
        print(f"    RA (Recursion Available): {dns.ra}")
        print(f"    AA (Authoritative): {dns.aa}")

def demo_dns_query_builder():
    """Interactive DNS query builder."""
    print_section("7. Building Custom DNS Queries")
    
    print("""[+] DNS Query Components:
    
    IP Layer:
      - dst: DNS server IP (e.g., "8.8.8.8")
      
    UDP Layer:
      - dport: 53 (DNS port)
      - sport: Random source port (default)
      
    DNS Layer:
      - rd: Recursion desired (0 or 1)
      - qd: Query data (DNSQR)
      
    DNSQR (Query):
      - qname: Domain to query
      - qtype: Record type (A, AAAA, MX, etc.)
      - qclass: Query class (default: IN for Internet)
    """)
    
    print("\n[+] Example queries:\n")
    
    examples = [
        {
            "desc": "Basic A record query",
            "code": 'IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))'
        },
        {
            "desc": "MX record query",
            "code": 'IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype="MX"))'
        },
        {
            "desc": "No recursion query",
            "code": 'IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=0, qd=DNSQR(qname="example.com"))'
        },
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"  {i}. {example['desc']}:")
        print(f"     {example['code']}")
        print()

def demo_dns_cache_poisoning_detection():
    """Demonstrate DNS response validation (security awareness)."""
    print_section("8. DNS Response Validation")
    
    print("""[+] DNS Security Considerations:
    
    When receiving DNS responses, always validate:
      1. Transaction ID matches the query
      2. Response comes from the expected server
      3. Answer makes sense for the query
      4. DNSSEC validation (when available)
    
    This helps prevent:
      - DNS cache poisoning
      - Man-in-the-middle attacks
      - DNS spoofing
    """)
    
    domain = "example.com"
    print(f"\n[+] Querying {domain} with validation...")
    
    # Create query with specific ID
    query_id = 12345
    query = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(
        id=query_id,
        rd=1,
        qd=DNSQR(qname=domain)
    )
    
    print(f"    Query ID: {query_id}")
    
    response = sr1(query, timeout=3, verbose=0)
    
    if response and response.haslayer(DNS):
        print(f"\n[+] Validation checks:")
        print(f"    ✓ Response ID: {response[DNS].id}")
        print(f"    ✓ ID matches: {response[DNS].id == query_id}")
        print(f"    ✓ Source IP: {response[IP].src}")
        print(f"    ✓ Is response: {response[DNS].qr == 1}")
        
        if response[DNS].id == query_id and response[IP].src == "8.8.8.8":
            print("\n[✓] Response validated successfully!")
        else:
            print("\n[!] Response validation failed - possible attack!")

def main():
    """Main function."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║              DNS QUERIES WITH SCAPY                          ║
║        Learn DNS Resolution and Troubleshooting             ║
╚══════════════════════════════════════════════════════════════╝

This script demonstrates:
  • Creating and sending DNS queries
  • Different DNS record types (A, AAAA, MX, NS, TXT, PTR)
  • Using different DNS servers
  • Understanding DNS flags and options
  • DNS response validation
  • Security considerations

⚠️  WARNING: Requires root/admin privileges for raw packet sending.
    """)
    
    if not check_privileges():
        print("[✗] Error: Root/administrator privileges required")
        print("    Run with: sudo python3 dns_query.py")
        sys.exit(1)
    
    print("[✓] Running with appropriate privileges")
    
    try:
        demo_basic_dns_query()
        demo_dns_record_types()
        demo_reverse_dns()
        demo_multiple_queries()
        demo_custom_dns_server()
        demo_dns_flags()
        demo_dns_query_builder()
        demo_dns_cache_poisoning_detection()
        
        print("\n" + "="*70)
        print("  All Demonstrations Complete!")
        print("="*70)
        print("\nWhat you learned:")
        print("  ✓ How to create and send DNS queries")
        print("  ✓ Different DNS record types and their uses")
        print("  ✓ Working with multiple DNS servers")
        print("  ✓ DNS security and validation")
        print("\nNext steps:")
        print("  - Build a DNS enumeration tool")
        print("  - Create a custom DNS resolver")
        print("  - Explore DNS tunneling (advanced)")
        
    except KeyboardInterrupt:
        print("\n\n[!] Script interrupted by user")
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
