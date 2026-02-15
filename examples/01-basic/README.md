# Basic Examples - Getting Started with Scapy

Welcome to the beginner-friendly Scapy examples! These scripts will teach you the fundamental concepts of network packet manipulation.

## 📚 Learning Order

Work through these examples in order for the best learning experience:

1. **hello_scapy.py** - Your first Scapy script
2. **packet_basics.py** - Creating and inspecting packets
3. **layer_stacking.py** - Understanding protocol layers
4. **sending_packets.py** - Different ways to send packets
5. **basic_sniffing.py** - Capturing network packets

## 📖 Script Descriptions

### 1. hello_scapy.py - Your First Scapy Script

**What you'll learn:**
- How to import and use Scapy
- Creating a simple ICMP (ping) packet
- Sending a packet and receiving a response
- Displaying packet information

**Requires:** Root/administrator privileges

**Usage:**
```bash
sudo python3 hello_scapy.py
```

**Key concepts:**
- Basic packet creation with `IP()` and `ICMP()`
- Using `sr1()` to send and receive
- Analyzing responses

---

### 2. packet_basics.py - Creating and Inspecting Packets

**What you'll learn:**
- Creating different types of packets (IP, TCP, UDP, ICMP, ARP)
- Inspecting packet fields and values
- Modifying packet attributes
- Converting packets to/from bytes
- Adding payload to packets

**Requires:** No special privileges (doesn't send packets)

**Usage:**
```bash
python3 packet_basics.py
```

**Key concepts:**
- Packet structure and fields
- Accessing packet attributes
- Protocol-specific fields (TCP flags, ICMP types, etc.)
- Working with packet bytes

---

### 3. layer_stacking.py - Understanding Protocol Layers

**What you'll learn:**
- How network protocols are layered (OSI model)
- Stacking layers using the `/` operator
- Accessing individual layers in packets
- Creating complex multi-layer packets
- Understanding encapsulation

**Requires:** No special privileges

**Usage:**
```bash
python3 layer_stacking.py
```

**Key concepts:**
- Layer stacking: `IP()/TCP()` creates IP packet with TCP inside
- OSI model layers (2, 3, 4, 7)
- Accessing layers with `packet[IP]`, `packet[TCP]`, etc.
- Building complete packets from multiple protocols

**Important concept:**
```python
# These are equivalent:
packet = IP(dst="192.168.1.1") / TCP(dport=80)
# vs
ip = IP(dst="192.168.1.1")
tcp = TCP(dport=80)
packet = ip / tcp
```

---

### 4. sending_packets.py - Different Ways to Send Packets

**What you'll learn:**
- `send()` - Send at layer 3 (IP), no response
- `sendp()` - Send at layer 2 (Ethernet), no response
- `sr1()` - Send and receive ONE packet
- `sr()` - Send and receive multiple packets
- `srp()` - Send and receive at layer 2
- When to use each function
- Timeout and retry options

**Requires:** Root/administrator privileges

**Usage:**
```bash
sudo python3 sending_packets.py
```

**Key concepts:**
- Different sending functions for different needs
- Handling responses vs fire-and-forget
- Layer 2 vs Layer 3 sending
- Performance and timing considerations

**Quick reference:**
| Function | Layer | Gets Response? | Use Case |
|----------|-------|----------------|----------|
| `send()` | L3 | No | Fast sending, no reply needed |
| `sendp()` | L2 | No | Ethernet-level sending |
| `sr1()` | L3 | Yes (first) | Request/reply protocols |
| `sr()` | L3 | Yes (all) | Multiple targets |
| `srp()` | L2 | Yes (all) | ARP, L2 scanning |

---

### 5. basic_sniffing.py - Capturing Network Packets

**What you'll learn:**
- Capturing packets with `sniff()`
- Filtering by protocol (TCP, UDP, ICMP, etc.)
- Filtering by port (HTTP, HTTPS, DNS, etc.)
- Using callback functions for real-time processing
- Analyzing captured packets
- Saving packets to PCAP files

**Requires:** Root/administrator privileges

**Usage:**
```bash
sudo python3 basic_sniffing.py
```

**Key concepts:**
- Basic packet capture
- BPF (Berkeley Packet Filter) syntax
- Real-time packet processing with callbacks
- Packet storage and analysis
- Working with PCAP files

**Common filters:**
```python
sniff(filter="tcp")                      # All TCP
sniff(filter="tcp port 80")              # HTTP traffic
sniff(filter="udp and port 53")          # DNS
sniff(filter="icmp")                     # Ping packets
sniff(filter="src host 192.168.1.1")     # From specific IP
```

---

## 🎯 Prerequisites

Before starting:

1. **Python 3.6+** installed
2. **Scapy installed**: `pip install scapy`
3. **Root/admin access** for scripts that send/capture packets
4. **Basic networking knowledge** helpful but not required
5. **Permission** to test on your network

## ⚙️ Running the Scripts

### On Linux/Mac:

```bash
# Scripts that don't need privileges:
python3 packet_basics.py
python3 layer_stacking.py

# Scripts that need root:
sudo python3 hello_scapy.py
sudo python3 sending_packets.py
sudo python3 basic_sniffing.py
```

### On Windows:

```cmd
# Run Command Prompt as Administrator

# Scripts that don't need privileges:
python packet_basics.py
python layer_stacking.py

# Scripts that need admin:
python hello_scapy.py
python sending_packets.py
python basic_sniffing.py
```

## 🔍 Troubleshooting

### "Permission denied" error
- **Linux/Mac**: Run with `sudo`
- **Windows**: Run Command Prompt as Administrator

### "No module named 'scapy'"
```bash
pip install scapy
# or
pip3 install scapy
```

### "Npcap is not installed" (Windows)
- Download and install Npcap from https://npcap.com/
- Enable "WinPcap API-compatible mode"
- Restart your computer

### Packets not being captured
- Make sure you're running with proper privileges
- Check that you're on an active network interface
- Try generating traffic (ping something, open a webpage)

## 📝 Learning Tips

1. **Read the code comments** - Each script is heavily commented
2. **Experiment** - Modify values and see what happens
3. **Run scripts multiple times** - Try different scenarios
4. **Use a safe environment** - Test in VMs or isolated networks
5. **Take notes** - Write down what you learn
6. **Ask questions** - Open an issue if something's unclear

## 🎓 What to Do After Completing These Examples

After mastering these basics:

1. **Read the documentation** in `docs/03-basic-concepts.md`
2. **Try the exercises** in `exercises/beginner/`
3. **Move to intermediate examples** in `examples/02-intermediate/`
4. **Build your own tools** using what you learned

## ⚠️ Safety and Ethics

**IMPORTANT REMINDERS:**

- ✅ Only use on networks you **own** or have **explicit permission** to test
- ✅ Use in **isolated environments** for learning (VMs, home lab)
- ✅ Understand **legal implications** in your jurisdiction
- ❌ Never use on networks without authorization
- ❌ Unauthorized network scanning/sniffing is **illegal** in many countries

**These tools are for educational purposes only!**

## 📚 Additional Resources

- **Official Scapy Docs**: https://scapy.readthedocs.io/
- **Scapy Cheat Sheet**: `../../resources/cheatsheet.md`
- **Protocol Reference**: `../../resources/protocols.md`
- **Installation Guide**: `../../docs/02-installation.md`

## 💡 Common Questions

### Q: Do I need to understand networking before starting?
**A:** Basic understanding helps, but you'll learn as you go! The scripts explain concepts as they're used.

### Q: Why do some scripts need root/admin privileges?
**A:** Sending raw packets and capturing network traffic requires low-level system access. This is a security feature of modern operating systems.

### Q: Can I use these scripts in production?
**A:** These are educational examples. For production use, you'd need additional error handling, security considerations, and testing.

### Q: What if a script doesn't work?
**A:** Check the troubleshooting section above, ensure you have proper privileges, and verify your network is active. If still stuck, open an issue!

### Q: How long does it take to learn these basics?
**A:** Most people can complete all five scripts in 2-4 hours. Take your time and experiment!

---

## 🚀 Quick Start

Start your Scapy journey now:

```bash
# 1. Install Scapy
pip install scapy

# 2. Run your first script
sudo python3 hello_scapy.py

# 3. Keep learning!
```

**Happy Learning! 🎉**

If you find these examples helpful, please star the repository and share with others!
