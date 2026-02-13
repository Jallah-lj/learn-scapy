# Scapy Cheat Sheet

## Common Commands

### Import Scapy
```python
from scapy.all import *
```

### Packet Creation
- **IP Packet**:  
```python
ip = IP(dst='www.example.com')
```
- **TCP Packet**:   
```python
tcp = TCP(dport=80)
```
- **Complete Packet**:  
```python
packet = ip/tcp
```

### Sending Packets
- **Send a Packet**:  
```python
send(packet)
```
- **Send and Receive packets**:  
```python
ans, unans = sr(packet)
```

### Sniffing Packets
- **Sniff with a filter**:  
```python
sniff(filter='tcp', count=10)
```
- **Sniffing all packets**:  
```python
sniff()
```

### Protocol Layers
- **Ethernet Layer**:  
```python
e = Ether()
```
- **IP Layer**:   
```python
ip = IP()
```
- **TCP Layer**:  
```python
tcp = TCP()
```
- **UDP Layer**:  
```python
udp = UDP()
```

### Filters
- **Filter by Protocol**:  
```python
filter='icmp'
```
- **Filter by Port**:  
```python
filter='tcp and port 80'
```

### Useful Functions
- **Show Protocol Fields**:  
```python
packet.show()
```
- **Summary of Packet**:  
```python
packet.summary()
```
- **Sr Packet**:  
```python
ans, unans = sr(IP(dst='8.8.8.8')/ICMP())
```

---

### Examples
- **Ping a host**:  
```python
ans, unans = sr(IP(dst='www.example.com')/ICMP())
```
- **ARP Request**:  
```python
arp_request = ARP(pdst='192.168.0.1')
ans = sr1(arp_request)
```

---

## Notes
- Ensure you have the necessary permissions to run Scapy commands.
- Use Scapy in a safe environment to avoid network issues.

# End of Cheat Sheet