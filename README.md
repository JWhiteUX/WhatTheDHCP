# WhatTheDHCP 🔍

A comprehensive network analysis toolkit for DHCP server detection, network troubleshooting, and rogue DHCP server identification.

**GitHub Repository:** https://github.com/JWhiteUX/WhatTheDHCP.git

## 🎯 Purpose

WhatTheDHCP helps network administrators and security professionals:
- **Detect active DHCP servers** on a network using multiple methods
- **Identify rogue DHCP servers** that could compromise network security
- **Troubleshoot DHCP-related connectivity issues**
- **Analyze network configuration** and active hosts
- **Monitor DHCP traffic** in real-time

## 🚀 Features

### DHCP Detection Methods
- **Current Configuration Analysis** - Examines active DHCP leases and system configuration
- **Network Port Scanning** - Scans for devices with DHCP ports (67/UDP) open
- **ARP Table Analysis** - Identifies potential DHCP servers based on network behavior
- **DHCP Renewal Testing** - Forces DHCP renewal to capture server responses
- **Router Interface Detection** - Checks common router IPs for DHCP services

### Security & Analysis
- **Rogue DHCP Detection** - Identifies multiple DHCP servers indicating potential security issues
- **Confidence Scoring** - Rates detection methods from HIGH to LOW confidence
- **Network Scanning** - Discovers active hosts and services
- **Traffic Monitoring** - Real-time DHCP packet capture and analysis

### Cross-Platform Support
- **macOS** - Full support using native tools (`ipconfig`, `ifconfig`, `route`)
- **Linux** - Full support using standard utilities (`dhclient`, `ip`, `netstat`)

## 📋 Requirements

### Core Dependencies
```bash
# Python 3.6+
python3 --version

# Network utilities (usually pre-installed)
ping, arp, route/ip
```

### Optional Dependencies
```bash
# For advanced scanning features
sudo apt-get install nmap        # Linux
brew install nmap               # macOS

# For traffic monitoring
tcpdump                         # Usually pre-installed

# For enhanced network scanning
sudo apt-get install arp-scan   # Linux (optional)
```

## 🔧 Installation

1. **Clone or download the scripts:**
```bash
git clone https://github.com/JWhiteUX/WhatTheDHCP.git
cd WhatTheDHCP
```

2. **Make scripts executable:**
```bash
chmod +x dhcp_discovery.py
chmod +x network_analyzer.sh
```

3. **Install optional dependencies:**
```bash
# macOS
brew install nmap

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install nmap tcpdump

# CentOS/RHEL
sudo yum install nmap tcpdump
```

## 🚀 Usage

### Quick Start - Python Script
```bash
# Basic DHCP server detection
./dhcp_discovery.py

# Enable debug output for troubleshooting
./dhcp_discovery.py --debug
```

### Quick Start - Bash Script
```bash
# Show current network configuration
./network_analyzer.sh info

# Run comprehensive analysis
./network_analyzer.sh all

# Scan for active hosts
./network_analyzer.sh scan
```

### Common Use Cases

#### 1. Detect Rogue DHCP Servers
```bash
# Run both tools for comprehensive detection
./dhcp_discovery.py
./network_analyzer.sh dhcp-nmap
```

#### 2. Troubleshoot DHCP Issues
```bash
# Check current configuration
./network_analyzer.sh info

# Force DHCP renewal
./network_analyzer.sh renew

# Monitor DHCP traffic
./network_analyzer.sh monitor
```

#### 3. Network Security Audit
```bash
# Complete network analysis
./network_analyzer.sh all

# Check for service conflicts
./network_analyzer.sh services
./network_analyzer.sh arp
```

## 📊 Understanding Results

### Confidence Levels
- **🟢 HIGH** - Active DHCP lease or successful renewal (reliable)
- **🟡 MEDIUM** - Open DHCP ports detected via network scan
- **🟠 LOW** - Potential DHCP server based on IP patterns or ping responses

### Warning Signs
- **Multiple HIGH confidence servers** = Likely rogue DHCP server
- **Conflicting lease information** = Network configuration issues
- **Duplicate MAC addresses** = Potential network conflicts

## 📖 Detailed Command Reference

### Python Script Options
```bash
./dhcp_discovery.py [OPTIONS]

Options:
  -d, --debug    Enable detailed debug output
  -h, --help     Show help message
```

### Bash Script Commands
```bash
./network_analyzer.sh [COMMAND]

Commands:
  info          Show current network configuration
  scan          Scan for active hosts on network
  dhcp-nmap     Use nmap to detect DHCP servers
  dhcp-python   Run Python DHCP discovery tool
  arp           Analyze ARP table for conflicts
  monitor       Monitor DHCP traffic (requires sudo)
  renew         Release and renew DHCP lease
  services      Check for DHCP services on network
  all           Run all non-interactive checks
  help          Show help message
```

## 🔐 Security Considerations

### Permissions Required
- **Basic detection** - No special permissions needed
- **Network scanning** - May require `sudo` for some nmap operations
- **DHCP renewal** - Requires `sudo` to modify network configuration
- **Traffic monitoring** - Requires `sudo` for tcpdump access

### Network Impact
- **Minimal** - Most detection methods are passive
- **DHCP renewal** - Briefly interrupts network connectivity
- **Network scanning** - Generates network traffic (usually harmless)

## 🛠️ Troubleshooting

### Common Issues

#### "Command not found" errors
```bash
# Install missing dependencies
brew install nmap               # macOS
sudo apt-get install nmap      # Linux
```

#### "Permission denied" errors
```bash
# Use sudo for privileged operations
sudo ./network_analyzer.sh monitor
sudo ./network_analyzer.sh renew
```

#### No DHCP servers detected
- Check if network uses static IP configuration
- Verify network connectivity
- Try running with `--debug` flag for more information
- Ensure you're on the correct network interface

#### Script fails on specific platforms
- Check debug output for specific error messages
- Verify required system utilities are installed
- Some features may not be available on all platforms

### Debug Mode
Enable debug mode for detailed troubleshooting:
```bash
./dhcp_discovery.py --debug
```

## 🤝 Contributing

### Reporting Issues
Please report issues on the [GitHub repository](https://github.com/JWhiteUX/WhatTheDHCP/issues):
- Include your operating system and version
- Provide debug output when possible
- Describe the expected vs actual behavior

### Feature Requests
Submit feature requests via [GitHub Issues](https://github.com/JWhiteUX/WhatTheDHCP/issues):
- Additional detection methods
- Support for other operating systems
- Enhanced reporting formats

## ⚖️ Legal & Ethical Use

**Important:** These tools are intended for:
- ✅ Network administration on networks you own/manage
- ✅ Authorized security testing and auditing
- ✅ Troubleshooting legitimate network issues

**Do not use for:**
- ❌ Unauthorized network scanning or reconnaissance
- ❌ Attacking or disrupting networks you don't own
- ❌ Any illegal or unethical activities

Always ensure you have proper authorization before running these tools on any network.

## 📝 License

This project is provided as-is for educational and legitimate network administration purposes. Use responsibly and in accordance with applicable laws and regulations.

---

**WhatTheDHCP** - Making DHCP detection and network troubleshooting straightforward and reliable.