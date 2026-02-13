# Installing Scapy

This guide will help you install Scapy on Windows, Linux, and macOS.

## System Requirements

- **Python 3.6 or higher**
- **Administrator/Root privileges** (for packet sending/sniffing)
- **Internet connection** (for installation)

## Quick Installation

For most users, installation is simple:

```bash
pip install scapy
```

That's it! But read on for platform-specific details and troubleshooting.

## Platform-Specific Installation

### Linux (Ubuntu/Debian)

#### Method 1: Using pip (Recommended)

```bash
# Update package list
sudo apt update

# Install Python and pip
sudo apt install python3 python3-pip

# Install Scapy
pip3 install scapy

# Verify installation
python3 -c "import scapy; print(scapy.__version__)"
```

#### Method 2: Using apt

```bash
sudo apt update
sudo apt install python3-scapy
```

#### Additional Dependencies (Optional)

For full functionality:

```bash
# For plotting and visualization
sudo apt install tcpdump graphviz imagemagick

# For additional protocol support
sudo apt install python3-pyx
```

### macOS

#### Method 1: Using pip (Recommended)

```bash
# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python

# Install Scapy
pip3 install scapy

# Verify installation
python3 -c "import scapy; print(scapy.__version__)"
```

#### Method 2: Using Homebrew

```bash
brew install scapy
```

#### Additional Tools

```bash
# Install libpcap for better packet capture
brew install libpcap

# Install tcpdump
brew install tcpdump
```

### Windows

#### Method 1: Using pip (Recommended)

1. **Install Python**
   - Download from [python.org](https://www.python.org/downloads/)
   - During installation, check "Add Python to PATH"
   - Verify: Open Command Prompt and type `python --version`

2. **Install Npcap** (Required for Windows)
   - Download from [npcap.com](https://npcap.com/#download)
   - Run installer with "WinPcap API-compatible Mode" checked
   - Restart your computer

3. **Install Scapy**
   ```cmd
   pip install scapy
   ```

4. **Verify Installation**
   ```cmd
   python -c "import scapy; print(scapy.__version__)"
   ```

#### Method 2: Using Anaconda

```cmd
# Install Anaconda from anaconda.com
# Then:
conda install -c conda-forge scapy
```

#### Troubleshooting Windows

If you get errors:

1. **Install Visual C++ Redistributable**
   - Download from Microsoft's website
   
2. **Run as Administrator**
   - Right-click Command Prompt → "Run as administrator"

3. **Check Npcap Installation**
   ```cmd
   # Should show network interfaces
   python -c "from scapy.all import *; print(get_if_list())"
   ```

## Verification

After installation, verify Scapy works:

### Test 1: Import Scapy

```python
python3 -c "import scapy; print('Scapy version:', scapy.__version__)"
```

Expected output:
```
Scapy version: 2.5.0
```

### Test 2: Create a Packet

```python
python3 -c "from scapy.all import *; pkt = IP(dst='8.8.8.8'); print(pkt)"
```

Expected output:
```
<IP  dst=8.8.8.8 |>
```

### Test 3: List Network Interfaces

```python
python3 -c "from scapy.all import *; print(get_if_list())"
```

This should list your network interfaces.

## Virtual Environment Setup (Recommended)

Using a virtual environment keeps your system Python clean:

### Linux/macOS

```bash
# Create project directory
mkdir scapy-learning
cd scapy-learning

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Scapy
pip install scapy

# Verify
python -c "import scapy; print(scapy.__version__)"

# When done, deactivate
deactivate
```

### Windows

```cmd
# Create project directory
mkdir scapy-learning
cd scapy-learning

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install Scapy
pip install scapy

# Verify
python -c "import scapy; print(scapy.__version__)"

# When done, deactivate
deactivate
```

## Installing from Source

For the latest development version:

```bash
# Clone the repository
git clone https://github.com/secdev/scapy
cd scapy

# Install
pip install .
```

## Additional Packages (Optional)

For enhanced functionality:

```bash
# IPython for better interactive shell
pip install ipython

# Matplotlib for packet visualization
pip install matplotlib

# Cryptography for encryption examples
pip install cryptography

# PyX for graph generation
pip install pyx
```

## Docker Installation (Alternative)

Run Scapy in a Docker container:

```bash
# Pull Scapy image
docker pull secdev/scapy

# Run Scapy container
docker run -it --net=host --privileged secdev/scapy
```

## Troubleshooting

### Common Issues

#### Issue: "Permission Denied" when sniffing

**Solution**: Run with elevated privileges
```bash
# Linux/macOS
sudo python3 your_script.py

# Windows
# Run Command Prompt as Administrator
```

#### Issue: "No module named 'scapy'"

**Solutions**:
1. Verify installation: `pip list | grep scapy`
2. Check Python version: `python --version`
3. Reinstall: `pip uninstall scapy && pip install scapy`

#### Issue: On Windows, "Npcap is not installed"

**Solution**: Install Npcap from [npcap.com](https://npcap.com/)

#### Issue: Can't see network interfaces

**Linux**: Add user to netdev group
```bash
sudo usermod -aG netdev $USER
# Log out and log back in
```

**Windows**: Restart after installing Npcap

#### Issue: Import errors on Linux

**Solution**: Install additional dependencies
```bash
sudo apt install tcpdump libpcap-dev
```

### Getting Help

If you still have issues:

1. **Check Scapy documentation**: [scapy.readthedocs.io](https://scapy.readthedocs.io/)
2. **GitHub Issues**: [github.com/secdev/scapy/issues](https://github.com/secdev/scapy/issues)
3. **Stack Overflow**: Search for "scapy" tag
4. **This repository**: Open an issue

## Version Check

Different Scapy versions may have different features:

```python
from scapy.all import *

# Check version
print(f"Scapy version: {scapy.__version__}")

# Check Python version
import sys
print(f"Python version: {sys.version}")
```

## Recommended Setup

For the best learning experience:

1. **Python 3.8+**: Latest stable Python
2. **Virtual Environment**: Isolate your project
3. **IPython**: Better interactive experience
4. **Lab Environment**: Separate network for testing

## Next Steps

Now that Scapy is installed:

1. **[Basic Concepts](03-basic-concepts.md)** - Learn networking fundamentals
2. **[First Example](../examples/01-basic/hello_scapy.py)** - Run your first script
3. **Interactive Mode** - Try Scapy interactively: `sudo scapy`

---

**Installation complete! Time to start manipulating packets! 🚀**