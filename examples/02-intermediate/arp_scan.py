# ARP Network Scanner
# Author: Jallah-lj
# Date: 2026-02-13
# This script performs ARP scanning to discover active hosts on a local network.
# Please use this script responsibly and ethically. Unauthorized scanning can be illegal in many jurisdictions.
# Always ensure you have permission to scan a network before using this tool.

import scapy.all as scapy

def scan(ip):
    # This function scans the specified IP address or subnet.
    arp_request = scapy.ARP(pdst=ip)  # Create ARP request
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')  # Create broadcast frame
    arp_request_broadcast = broadcast / arp_request  # Combine the two packets
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # Send the packets and receive the response

    active_hosts = []  # List to store active hosts
    for element in answered_list:
        host_info = {'ip': element[1].psrc, 'mac': element[1].hwsrc}  # Extract IP and MAC addresses
        active_hosts.append(host_info)  # Add to the list
    return active_hosts  # Return the list of active hosts


def print_results(active_hosts):
    # This function prints the results of the scan.
    print("Active devices:")
    print("IP Address\t\tMAC Address")
    print("---------------------------------")
    for host in active_hosts:
        print(f"{host['ip']}\t\t{host['mac']}")  # Print each active host's IP and MAC address


def scan_subnet(subnet):
    # This function scans an entire subnet.
    print(f"Scanning the subnet: {subnet}")
    active_hosts = scan(subnet)  # Call scan function for the subnet
    print_results(active_hosts)  # Call function to print results


def check_single_host(ip):
    # This function checks a single host.
    print(f"Checking IP: {ip}")
    active_hosts = scan(ip)  # Call scan function for the single IP
    print_results(active_hosts)  # Print results


# Example usage:
# Uncomment the lines below to perform scans
# scan_subnet('192.168.1.0/24')  # Scan entire subnet
# check_single_host('192.168.1.1')  # Check single host
