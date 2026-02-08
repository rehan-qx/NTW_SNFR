# Network Packet Sniffer - Documentation

Professional network traffic analysis tool for capturing and analyzing network packets.

## 📋 Project Overview

This project gives you the capability to capture and analyze network packets. This tool is designed for educational purposes and helps in understanding network protocols.

## ✨ Features

### Basic Sniffer (network_sniffer.py)
- ✅ Raw socket-based packet capturing
- ✅ No external dependencies (pure Python)
- ✅ Ethernet frame parsing
- ✅ IPv4 packet analysis
- ✅ TCP/UDP/ICMP protocol support
- ✅ Payload inspection
- ✅ Cross-platform support (Linux/Windows/Mac)
- ✅ Colorful terminal output
- ✅ Export captured data

### Advanced Sniffer (scapy_sniffer.py)
- ✅ Scapy-powered deep packet inspection
- ✅ Multiple protocol support (ARP, DNS, HTTP, etc.)
- ✅ BPF filtering capabilities
- ✅ Detailed statistics
- ✅ PCAP file export
- ✅ Real-time packet analysis
- ✅ Advanced filtering options

## 🔧 Installation

### Prerequisites
```bash
# Python 3.6 or higher required
python3 --version
```

### Setup

#### For Basic Sniffer (network_sniffer.py)
```bash
# No additional dependencies required!
# Just run directly with sudo/admin privileges
```

#### For Advanced Sniffer (scapy_sniffer.py)
```bash
# Install required packages
pip install -r requirements.txt

# Or install manually
pip install scapy colorama
```

## 🚀 Usage

### Basic Sniffer

#### Linux/Mac:
```bash
# Capture 10 packets (default)
sudo python3 network_sniffer.py

# Capture 50 packets
sudo python3 network_sniffer.py -c 50

# Continuous capture (press Ctrl+C to stop)
sudo python3 network_sniffer.py -c 0

# Save to file
sudo python3 network_sniffer.py -c 20 -o captured_packets.txt
```

#### Windows (Run Command Prompt as Administrator):
```bash
python network_sniffer.py -c 20
```

### Advanced Sniffer

```bash
# Basic capture
sudo python3 scapy_sniffer.py -c 20

# Capture only TCP traffic
sudo python3 scapy_sniffer.py -c 50 -f "tcp"

# Capture HTTP traffic
sudo python3 scapy_sniffer.py -f "tcp port 80" -c 30

# Capture on specific interface
sudo python3 scapy_sniffer.py -i eth0 -c 100

# Save to PCAP file (can open in Wireshark)
sudo python3 scapy_sniffer.py -c 100 -o capture.pcap

# Capture DNS queries
sudo python3 scapy_sniffer.py -f "udp port 53" -c 20

# Monitor specific host
sudo python3 scapy_sniffer.py -f "host 192.168.1.1" -c 50
```

## 🎯 Command Line Arguments

### network_sniffer.py
| Argument | Description | Default |
|----------|-------------|---------|
| `-c, --count` | Number of packets to capture (0 = infinite) | 10 |
| `-i, --interface` | Network interface to use | Default |
| `-o, --output` | Output file to save results | None |

### scapy_sniffer.py
| Argument | Description | Default |
|----------|-------------|---------|
| `-c, --count` | Number of packets to capture (0 = infinite) | 10 |
| `-i, --interface` | Network interface to use | Default |
| `-f, --filter` | BPF filter string | None |
| `-o, --output` | Output PCAP file | None |

## 📊 BPF Filter Examples

BPF (Berkeley Packet Filter) filters allow you to capture specific traffic:

```bash
# Protocol filters
tcp                    # Only TCP packets
udp                    # Only UDP packets
icmp                   # Only ICMP packets

# Port filters
port 80                # Traffic on port 80
port 443               # HTTPS traffic
port 22                # SSH traffic
port 53                # DNS traffic

# Host filters
host 192.168.1.1       # Traffic to/from specific IP
src host 192.168.1.1   # Traffic from specific IP
dst host 192.168.1.1   # Traffic to specific IP

# Combined filters
tcp and port 80        # TCP traffic on port 80
udp and port 53        # DNS queries
tcp and dst port 443   # Outgoing HTTPS
host 8.8.8.8 and icmp  # ICMP to/from Google DNS

# Network filters
net 192.168.1.0/24     # Traffic in subnet
```

## 📖 Understanding the Output

### Ethernet Layer
```
[ETHERNET LAYER]
  Source MAC:      aa:bb:cc:dd:ee:ff
  Destination MAC: 11:22:33:44:55:66
  Type:            2048 (IPv4)
```

### IP Layer
```
[IP LAYER]
  Version:         4
  Header Length:   20 bytes
  TTL:             64
  Protocol:        TCP
  Source IP:       192.168.1.10
  Destination IP:  8.8.8.8
```

### TCP Layer
```
[TCP SEGMENT]
  Source Port:     52341
  Dest Port:       443
  Sequence:        123456789
  Acknowledgment:  987654321
  Flags:           SYN, ACK
```

## 🔍 What Each Tool Shows

### Network Concepts Covered:

1. **Data Link Layer (Layer 2)**
   - MAC addresses
   - Ethernet frames
   - ARP protocol

2. **Network Layer (Layer 3)**
   - IP addressing
   - IP headers
   - ICMP messages
   - Routing information

3. **Transport Layer (Layer 4)**
   - TCP connections
   - UDP datagrams
   - Port numbers
   - TCP flags (SYN, ACK, FIN, etc.)

4. **Application Layer (Layer 7)**
   - DNS queries/responses
   - HTTP requests
   - Protocol-specific data

## ⚠️ Important Notes

### Permissions Required
- **Linux/Mac**: Must run with `sudo` for raw socket access
- **Windows**: Must run Command Prompt as Administrator

### Legal & Ethical Considerations
⚠️ **IMPORTANT**: 
- Only capture traffic on networks you own or have explicit permission to monitor
- Capturing others' network traffic without permission is illegal
- Use for educational purposes only
- Respect privacy and data protection laws

### Troubleshooting

#### "Permission denied" error
```bash
# Solution: Run with sudo (Linux/Mac)
sudo python3 network_sniffer.py

# Solution: Run as Administrator (Windows)
# Right-click Command Prompt → Run as Administrator
```

#### "Scapy not found" error
```bash
# Install scapy
pip install scapy
```

#### "No module named 'colorama'" error
```bash
# Install colorama
pip install colorama
```

#### Can't see any packets
```bash
# Check network interfaces
# Linux/Mac:
ifconfig
ip addr show

# Windows:
ipconfig

# Then specify interface:
sudo python3 scapy_sniffer.py -i eth0
```

## 📚 Learning Resources

### Understanding Network Protocols:
1. **TCP/IP Model**: Understand the 4-layer model
2. **OSI Model**: Learn the 7-layer reference model
3. **Packet Structure**: Study how packets are encapsulated
4. **Common Ports**: Learn standard service ports

### Recommended Reading:
- RFC 793 (TCP)
- RFC 791 (IP)
- RFC 768 (UDP)
- Wireshark User Guide

## 🎓 Educational Use Cases

### Lab Exercises:
1. **Basic Protocol Analysis**
   - Capture and analyze TCP three-way handshake
   - Observe DNS query/response
   - Monitor ICMP ping packets

2. **Traffic Pattern Recognition**
   - Identify different protocol signatures
   - Analyze packet sizes and frequencies
   - Understand traffic flows

3. **Security Awareness**
   - Observe unencrypted HTTP traffic
   - See the difference with HTTPS
   - Understand why encryption matters

## 📝 Sample Output

```
================================================================================
PACKET #1 | Time: 14:23:45.123
================================================================================

[SUMMARY]
  Ether / IP / TCP 192.168.1.10:52341 > 142.250.185.46:443 S

[ETHERNET LAYER]
  Source MAC:      a4:5e:60:d2:3f:1a
  Destination MAC: 00:1a:2b:3c:4d:5e
  Type:            2048 (IPv4)

[IP LAYER]
  Version:         4
  Header Length:   20 bytes
  TTL:             64
  Protocol:        6 (TCP)
  Source IP:       192.168.1.10
  Destination IP:  142.250.185.46
  Packet Length:   60 bytes

[TCP SEGMENT]
  Source Port:     52341
  Dest Port:       443
  Sequence:        1234567890
  Acknowledgment:  0
  Flags:           SYN
  Window Size:     65535

================================================================================
```

## 🔐 Security Best Practices

1. **Never capture sensitive data** in production environments
2. **Delete captures** containing personal/sensitive information
3. **Use filtered captures** to minimize unnecessary data collection
4. **Secure your capture files** - they may contain sensitive info
5. **Follow your organization's security policies**

## 📦 Project Structure

```
network-sniffer/
├── network_sniffer.py      # Basic sniffer (no dependencies)
├── scapy_sniffer.py        # Advanced sniffer (uses Scapy)
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── examples/              # Example outputs (optional)
```

## 🤝 Contributing
  
  ### Welcome to contribution

## 📄 License

*Educational use only. Follow local laws and regulations*

## 👨‍💻 Author

*Muhammad Rehan Afzal [N1xR00t~#]*


## 📞 Support

If you have face any error to run this code:
1. Check documentation thoroughly
2. Review error messages carefully
3. Ensure proper permissions (sudo/admin)
4. Verify all dependencies are installed

---

**Happy Packet Sniffing! 🚀**

*Remember: Use responsibly and ethically!*
