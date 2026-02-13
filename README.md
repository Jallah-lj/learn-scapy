# Learn Scapy - A Complete Guide to Network Packet Manipulation

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

> 🎓 A comprehensive educational repository for learning network packet manipulation with Scapy

## 📖 What is Scapy?

Scapy is a powerful Python-based interactive packet manipulation program and library. It allows you to:

- **Create** custom network packets from scratch
- **Send** packets over the network
- **Capture** and sniff network traffic
- **Decode** and analyze packets
- **Manipulate** existing packets

## 🎯 Why Learn Scapy?

- **Career Growth**: Essential skill for cybersecurity professionals
- **Network Understanding**: Deep dive into how networks actually work
- **Security Testing**: Test firewalls, IDS/IPS systems, and network defenses
- **Protocol Analysis**: Understand protocols at the packet level
- **Automation**: Automate network tasks and testing
- **Research**: Develop proof-of-concepts and security tools

## 🚀 Quick Start

### Installation

```bash
# Install Scapy using pip
pip install scapy

# Verify installation
python3 -c "import scapy; print(scapy.__version__)"
```

### Your First Scapy Script

```python
from scapy.all import *

# Create a simple ICMP ping packet
packet = IP(dst="8.8.8.8")/ICMP()

# Send and receive response
response = sr1(packet, timeout=2)

# Display the response
if response:
    response.show()
```

## 📚 Repository Structure

```
learn-scapy/
├── README.md                    # You are here!
├── docs/                        # Comprehensive documentation
│   ├── 01-introduction.md      # What is Scapy and why use it
│   ├── 02-installation.md      # Installation for all platforms
│   ├── 03-basic-concepts.md    # Networking and Scapy fundamentals
│   ├── 04-advanced-topics.md   # Advanced techniques
│   └── 05-best-practices.md    # Ethics, security, and best practices
├── examples/                    # Hands-on code examples
│   ├── 01-basic/               # Beginner-friendly examples
│   ├── 02-intermediate/        # Network scanning and sniffing
│   ├── 03-advanced/            # Custom protocols and injection
│   └── 04-projects/            # Real-world projects
├── exercises/                   # Practice exercises
│   ├── beginner/               # Start here
│   ├── intermediate/           # Level up
│   ├── advanced/               # Master level
│   └── solutions/              # Solutions for all exercises
├── resources/                   # Reference materials
│   ├── cheatsheet.md           # Quick reference guide
│   ├── protocols.md            # Protocol documentation
│   └── useful-links.md         # External resources
└── requirements.txt             # Python dependencies
```

## 🎓 Learning Path

### Level 1: Beginner (Start Here!)
1. Read `docs/01-introduction.md` and `docs/02-installation.md`
2. Complete examples in `examples/01-basic/`
3. Practice with `exercises/beginner/`
4. **Goal**: Understand packet creation and basic sending

### Level 2: Intermediate
1. Read `docs/03-basic-concepts.md`
2. Complete examples in `examples/02-intermediate/`
3. Practice with `exercises/intermediate/`
4. **Goal**: Master packet sniffing and network scanning

### Level 3: Advanced
1. Read `docs/04-advanced-topics.md` and `docs/05-best-practices.md`
2. Complete examples in `examples/03-advanced/`
3. Practice with `exercises/advanced/`
4. **Goal**: Create custom protocols and advanced tools

### Level 4: Projects
1. Build real-world tools in `examples/04-projects/`
2. Create your own security tools
3. Contribute back to this repository
4. **Goal**: Apply skills to real scenarios

## 🛠️ Prerequisites

- **Python 3.6+**: Basic Python knowledge required
- **Networking Basics**: Understanding of TCP/IP, OSI model helpful
- **Linux/Mac/Windows**: Works on all platforms
- **Root/Admin Access**: Required for packet sending/sniffing

## ⚠️ Safety and Ethics

**CRITICAL: READ BEFORE PROCEEDING**

- ✅ **Only use on networks you own or have explicit permission to test**
- ✅ **Use isolated lab environments for learning**
- ✅ **Understand the legal implications in your jurisdiction**
- ❌ **Never use these techniques on networks without authorization**
- ❌ **Unauthorized network scanning/sniffing is illegal in many countries**

**This repository is for educational purposes only.** The authors are not responsible for misuse of this information.

## 💻 How to Use This Repository

### 1. Clone the Repository
```bash
git clone https://github.com/Jallah-lj/learn-scapy.git
cd learn-scapy
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Start Learning
```bash
# Read the introduction
cat docs/01-introduction.md

# Run your first example
cd examples/01-basic
python3 hello_scapy.py
```

### 4. Practice
Work through examples and exercises in order, from basic to advanced.

## 🤝 Contributing

We welcome contributions from classmates and the community!

### Ways to Contribute:
- 🐛 Report bugs or issues
- 💡 Suggest new examples or topics
- 📝 Improve documentation
- ✨ Add new exercises
- 🔧 Fix errors or typos

### How to Contribute:
1. Fork this repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit (`git commit -m 'Add amazing feature'`)
5. Push (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## 📖 Resources

### Official Documentation
- [Scapy Official Docs](https://scapy.readthedocs.io/)
- [Scapy GitHub](https://github.com/secdev/scapy)

### Learning Resources
- [Scapy Cheat Sheet](resources/cheatsheet.md)
- [Protocol Reference](resources/protocols.md)
- [Useful Links](resources/useful-links.md)

### Community
- [Stack Overflow - Scapy Tag](https://stackoverflow.com/questions/tagged/scapy)
- [Reddit - r/netsec](https://www.reddit.com/r/netsec/)

## 🏆 Skills You'll Gain

By completing this repository, you will:

- ✅ Understand network protocols at a deep level
- ✅ Be able to create and manipulate packets
- ✅ Perform network reconnaissance and scanning
- ✅ Analyze network traffic
- ✅ Build custom security tools
- ✅ Troubleshoot network issues
- ✅ Prepare for cybersecurity careers

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

Created by **Jallah-lj** to help classmates and fellow learners master network packet manipulation.

## 🌟 Acknowledgments

- Thanks to the Scapy development team
- Thanks to all contributors and classmates
- Inspired by the cybersecurity community

## 📞 Support

- **Issues**: Open an issue on GitHub
- **Questions**: Use GitHub Discussions
- **Suggestions**: Open a feature request

---

**⭐ If you find this repository helpful, please star it and share with your classmates!**

**Happy Learning! 🚀**