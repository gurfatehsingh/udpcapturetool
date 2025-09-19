Synchronized Multi-Point Network Capture Tool
=============================================

A Python tool for capturing UDP traffic simultaneously across multiple network points with NTP time synchronization for precise packet correlation and flow analysis.

System Compatibility
--------------------

✅ **Windows 10/11** (Primary focus)\
✅ **Linux** (Ubuntu, CentOS, RHEL, etc.)\
✅ **macOS** (Intel and Apple Silicon)

Requirements
------------

### Windows Requirements

**Essential Software:**

1.  **Python 3.8+** - [Download from python.org](https://www.python.org/downloads/)
2.  **Wireshark** - [Download from wireshark.org](https://www.wireshark.org/download.html)
    -   **Important**: Install with "TShark" command-line tools enabled
    -   Add Wireshark installation directory to PATH (usually `C:\Program Files\Wireshark\`)
3.  **Npcap** - Packet capture driver (usually included with Wireshark)
    -   Ensure "WinPcap API-compatible mode" is enabled during installation

**Python Dependencies:**

bash

```
pip install ntplib
```

**Administrator Privileges:**

-   Run Command Prompt or PowerShell as Administrator
-   Required for network interface access

### Linux Requirements

**Package Installation (Ubuntu/Debian):**

bash

```
sudo apt update
sudo apt install python3 python3-pip tcpdump tshark
pip3 install ntplib
```

**Package Installation (CentOS/RHEL):**

bash

```
sudo yum install python3 python3-pip tcpdump wireshark-cli
# or for newer versions:
sudo dnf install python3 python3-pip tcpdump wireshark-cli
pip3 install ntplib
```

**Root Privileges:**

-   Run with `sudo` or configure capabilities for non-root capture

### macOS Requirements

**Using Homebrew:**

bash

```
brew install python3 wireshark
pip3 install ntplib
```

**Administrator Privileges:**

-   Run with `sudo` for packet capture access

Installation & Setup
--------------------

### 1\. Download the Script

Save the Python script as `network_capture.py`

### 2\. Install Dependencies

bash

```
pip install ntplib
```

### 3\. Find Network Interface Names

**Windows:**

cmd

```
# List available interfaces
tshark -D
# or
netsh interface show interface
```

**Linux:**

bash

```
# List network interfaces
ip link show
# or
ifconfig -a
```

**macOS:**

bash

```
# List network interfaces
ifconfig -l
# or detailed view
ifconfig -a
```

### 4\. Configure Capture Points

Create or edit `capture_config.json`:

**Windows Example:**

json

```
{
  "capture_points": [
    {"name": "wifi_adapter", "interface": "Wi-Fi", "filter": "udp"},
    {"name": "ethernet", "interface": "Ethernet", "filter": "udp"},
    {"name": "vpn_adapter", "interface": "OpenVPN TAP", "filter": "udp"}
  ],
  "capture_duration": 300,
  "ntp_servers": ["time.windows.com", "pool.ntp.org"],
  "output_dir": "C:\\captures"
}
```

**Linux/macOS Example:**

json

```
{
  "capture_points": [
    {"name": "eth0", "interface": "eth0", "filter": "udp"},
    {"name": "wlan0", "interface": "wlan0", "filter": "udp"},
    {"name": "bridge0", "interface": "br0", "filter": "udp"}
  ],
  "capture_duration": 300,
  "ntp_servers": ["pool.ntp.org", "time.google.com"],
  "output_dir": "./captures"
}
```

Usage
-----

### Basic Capture

bash

```
# Windows (as Administrator)
python network_capture.py

# Linux/macOS (as root/sudo)
sudo python3 network_capture.py
```

### Analyze Previous Capture

bash

```
python network_capture.py analyze "C:\captures\capture_20241219_143022"
# or on Unix
python3 network_capture.py analyze "./captures/capture_20241219_143022"
```

Configuration Options
---------------------

### Capture Filters

Customize packet filtering for each interface:

json

```
{
  "capture_points": [
    {"name": "router", "interface": "eth0", "filter": "udp and host 192.168.1.1"},
    {"name": "server", "interface": "eth1", "filter": "udp port 53 or udp port 5060"},
    {"name": "client", "interface": "wlan0", "filter": "udp and net 10.0.0.0/24"}
  ]
}
```

### Common Filter Examples:

-   `"udp"` - All UDP traffic
-   `"udp port 53"` - DNS traffic only
-   `"udp and host 192.168.1.100"` - UDP to/from specific host
-   `"udp and portrange 5000-6000"` - UDP port range
-   `"udp and greater 1000"` - UDP packets larger than 1000 bytes

### Time Synchronization

json

```
{
  "ntp_servers": [
    "time.windows.com",    // Windows default
    "pool.ntp.org",        // Global pool
    "time.google.com",     // Google NTP
    "time.cloudflare.com"  // Cloudflare NTP
  ],
  "sync_tolerance": 0.1    // Acceptable sync difference in seconds
}
```

Troubleshooting
---------------

### Windows Issues

**"tshark not found":**

cmd

```
# Add Wireshark to PATH or use full path
set PATH=%PATH%;C:\Program Files\Wireshark
```

**Permission Denied:**

-   Run as Administrator
-   Ensure Npcap is properly installed
-   Check Windows Defender/Antivirus blocking

**Interface Not Found:**

-   Use exact interface names from `tshark -D`
-   Some interfaces may need different names (e.g., "Local Area Connection")

### Linux Issues

**Permission Denied:**

bash

```
# Option 1: Run with sudo
sudo python3 network_capture.py

# Option 2: Grant capture capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
```

**tcpdump not found:**

bash

```
# Install missing packages
sudo apt install tcpdump  # Ubuntu/Debian
sudo yum install tcpdump  # CentOS/RHEL
```

### General Issues

**NTP Sync Failure:**

-   Check internet connectivity
-   Try different NTP servers
-   Allow NTP traffic through firewall (UDP port 123)

**Large File Sizes:**

-   Adjust capture filters to be more specific
-   Reduce capture duration
-   Enable file rotation in config

**Analysis Errors:**

-   Ensure tshark is in PATH
-   Check PCAP file permissions
-   Verify capture completed successfully

Output Files
------------

Each capture creates a timestamped directory containing:

-   `pointX.pcap` - Raw packet capture files
-   `metadata.json` - Capture session information
-   Console output with analysis results

Advanced Usage
--------------

### Custom Analysis

Extend the `UDPFlowAnalyzer` class for specific analysis needs:

-   Protocol-specific parsing
-   Custom correlation algorithms
-   Integration with network monitoring systems

### Automated Deployment

Deploy across multiple machines using:

-   Configuration management (Ansible, Puppet)
-   Remote execution (SSH, WinRM)
-   Centralized log collection

Performance Considerations
--------------------------

-   **Disk I/O**: High traffic may require fast storage (SSD recommended)
-   **Memory**: Large captures need sufficient RAM for analysis
-   **CPU**: Multi-threaded capture scales with core count
-   **Network**: Ensure capture doesn't impact production traffic

Support
-------

For issues specific to:

-   **Wireshark/tshark**: [Wireshark Documentation](https://www.wireshark.org/docs/)
-   **tcpdump**: [tcpdump Manual](https://www.tcpdump.org/manpages/)
-   **Python ntplib**: [ntplib Documentation](https://pypi.org/project/ntplib/)
