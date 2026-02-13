# Intermediate Examples

This directory contains several intermediate examples demonstrating various network-related tasks using Scapy.

## Scripts

### 1. packet_sniffing.py
- **Description:** This script demonstrates how to capture network packets in real-time. It allows you to analyze the packets that pass through a network interface.
- **How to Run:** Run the script with root privileges to ensure access to network interfaces. Use the command: `sudo python packet_sniffing.py`

### 2. arp_scan.py
- **Description:** This script performs an ARP scan of the local network to identify active devices. It sends ARP requests and listens for responses from devices.
- **How to Run:** Execute the script in an environment with network access. Use the command: `python arp_scan.py`

### 3. port_scanner.py
- **Description:** This script scans a target IP for open ports. It demonstrates TCP SYN and ACK scanning techniques.
- **How to Run:** Specify the target IP as a command-line argument. Use the command: `python port_scanner.py <target_ip>`

### 4. dns_query.py
- **Description:** This script queries DNS records for a specified domain name. It helps in understanding how DNS resolution works.
- **How to Run:** Run the script providing a domain name as an argument. Use the command: `python dns_query.py <domain_name>`