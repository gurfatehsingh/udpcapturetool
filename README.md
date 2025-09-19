<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg" alt="Platform Support">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
</p>
A Python tool for capturing UDP traffic simultaneously across multiple network points with NTP time synchronization for precise packet correlation and flow analysis.
🚀 Features

Multi-point synchronized capture across 7+ network locations
NTP time synchronization for precise packet correlation
Cross-platform support (Windows, Linux, macOS)
Real-time UDP flow analysis and packet drop detection
Configurable capture filters and duration
Automatic flow correlation using multiple identification methods

📋 System Compatibility
Windows, Linux and MacOS 

⚙️ Requirements
Windows Requirements

⚠️ Important: Run as Administrator for network interface access

Essential Software:
SoftwareVersionDownload Python3.8+python.org - Add to PATH during installation
WiresharkLatestwireshark.org Enable "TShark" command-line tools Npca pLatest Included with Wireshark, Enable "WinPcap API-compatible mode"

Python Dependencies:
pip install ntplib
Linux Requirements
<details>
<summary><b>Ubuntu/Debian Setup</b></summary>
```bash
sudo apt update
sudo apt install python3 python3-pip tcpdump tshark
pip3 install ntplib
```
</details>
<details>
<summary><b>CentOS/RHEL Setup</b></summary>
```bash
# For CentOS 7/RHEL 7
sudo yum install python3 python3-pip tcpdump wireshark-cli
For CentOS 8+/RHEL 8+
sudo dnf install python3 python3-pip tcpdump wireshark-cli
pip3 install ntplib
</details>

> **📝 Note**: Requires root privileges or sudo access

### macOS Requirements
```bash
# Using Homebrew
brew install python3 wireshark
pip3 install ntplib

📝 Note: Requires sudo for packet capture access

🛠️ Installation & Setup
1️⃣ Download the Script
bashgit clone <repository-url>
# or download network_capture.py directly
2️⃣ Install Dependencies
bashpip install ntplib
3️⃣ Find Network Interface Names
<details>
<summary><b>🪟 Windows</b></summary>
```cmd
# List available interfaces
tshark -D
Alternative method
netsh interface show interface

**Example Output:**

\Device\NPF_{12345678-1234-1234-1234-123456789012} (Wi-Fi)
\Device\NPF_{87654321-4321-4321-4321-210987654321} (Ethernet)

</details>

<details>
<summary><b>🐧 Linux</b></summary>
```bash
# List network interfaces
ip link show

# Alternative methods
ifconfig -a
nmcli device status
</details>
<details>
<summary><b>🍎 macOS</b></summary>
```bash
# List network interfaces  
ifconfig -l
Detailed view
ifconfig -a
</details>

### 4️⃣ Configure Capture Points

Create `capture_config.json` in the same directory:

<details>
<summary><b>🪟 Windows Configuration Example</b></summary>
```json
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
</details>
<details>
<summary><b>🐧 Linux/🍎 macOS Configuration Example</b></summary>
```json
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
</details>
🚀 Usage
📊 Basic Capture
<details>
<summary><b>🪟 Windows (Run as Administrator)</b></summary>
```cmd
# Open Command Prompt as Administrator
python network_capture.py
```
</details>
<details>
<summary><b>🐧 Linux / 🍎 macOS</b></summary>
```bash
# Run with sudo privileges
sudo python3 network_capture.py
```
</details>
📈 Analyze Previous Capture
bash# Windows
python network_capture.py analyze "C:\captures\capture_20241219_143022"

# Linux/macOS
python3 network_capture.py analyze "./captures/capture_20241219_143022"
⚙️ Configuration Options
🔍 Capture Filters
Customize packet filtering for each interface:
json{
  "capture_points": [
    {
      "name": "router", 
      "interface": "eth0", 
      "filter": "udp and host 192.168.1.1"
    },
    {
      "name": "server", 
      "interface": "eth1", 
      "filter": "udp port 53 or udp port 5060"
    },
    {
      "name": "client", 
      "interface": "wlan0", 
      "filter": "udp and net 10.0.0.0/24"
    }
  ]
}
📝 Common Filter Examples
FilterDescriptionUse Case"udp"All UDP trafficGeneral monitoring"udp port 53"DNS traffic onlyDNS troubleshooting"udp and host 192.168.1.100"UDP to/from specific hostServer monitoring"udp and portrange 5000-6000"UDP port rangeApplication-specific"udp and greater 1000"Large UDP packetsFragmentation analysis
⏰ Time Synchronization
json{
  "ntp_servers": [
    "time.windows.com",    // Windows default
    "pool.ntp.org",        // Global pool
    "time.google.com",     // Google NTP
    "time.cloudflare.com"  // Cloudflare NTP
  ],
  "sync_tolerance": 0.1    // Acceptable sync difference in seconds
}
🔧 Troubleshooting
🪟 Windows Issues
<details>
<summary><b>"tshark not found" Error</b></summary>
Solution:
cmd# Option 1: Add Wireshark to PATH
set PATH=%PATH%;C:\Program Files\Wireshark

# Option 2: Use full path in config
# Edit capture_config.json to use full tshark path
Permanent Fix:

Open System Properties → Advanced → Environment Variables
Add C:\Program Files\Wireshark to PATH
Restart Command Prompt

</details>
<details>
<summary><b>Permission Denied Errors</b></summary>
Checklist:

 Running as Administrator
 Npcap properly installed
 Windows Defender/Antivirus not blocking
 UAC (User Account Control) configured

Solutions:

Right-click Command Prompt → "Run as Administrator"
Reinstall Wireshark with Npcap
Add script to antivirus exceptions

</details>
<details>
<summary><b>Interface Not Found</b></summary>
Debug Steps:
cmd# List all interfaces
tshark -D

# Check network connections
netsh interface show interface
Common Issues:

Use exact interface names from tshark -D
Some interfaces named "Local Area Connection X"
Virtual adapters may have complex names

</details>
🐧 Linux Issues
<details>
<summary><b>Permission Denied</b></summary>
Option 1: Run with sudo
bashsudo python3 network_capture.py
Option 2: Grant capture capabilities
bashsudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
Option 3: Add user to netdev group
bashsudo usermod -a -G netdev $USER
# Logout and login again
</details>
<details>
<summary><b>Missing Dependencies</b></summary>
```bash
# Ubuntu/Debian
sudo apt install tcpdump tshark python3-pip
CentOS/RHEL
sudo yum install tcpdump wireshark-cli python3-pip
Fedora
sudo dnf install tcpdump wireshark-cli python3-pip
</details>

### 🍎 macOS Issues

<details>
<summary><b>Permission Issues</b></summary>
```bash
# Run with sudo
sudo python3 network_capture.py

# Or grant permissions to user
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
</details>
🌐 General Issues
<details>
<summary><b>NTP Sync Failures</b></summary>
Troubleshooting:

 Check internet connectivity: ping pool.ntp.org
 Try different NTP servers
 Allow NTP traffic through firewall (UDP port 123)
 Check corporate firewall restrictions

Firewall Commands:
bash# Linux: Allow NTP
sudo ufw allow out 123/udp

# Windows: Check firewall rules in Windows Defender
</details>
<details>
<summary><b>Large File Sizes</b></summary>
Solutions:

Adjust capture filters to be more specific
Reduce capture duration in config
Enable file rotation
Use SSD storage for better I/O

Example Config:
json{
  "capture_duration": 60,
  "pcap_rotation_size": "50M"
}
</details>
<details>
<summary><b>Analysis Errors</b></summary>
Common Fixes:

Ensure tshark is in PATH
Check PCAP file permissions
Verify capture completed successfully
Check disk space during capture

Debug Commands:
bash# Test tshark manually
tshark -r capture_file.pcap -c 10

# Check file integrity
file capture_file.pcap
</details>
📁 Output Files
Each capture session creates a timestamped directory containing:
captures/
└── capture_20241219_143022/
    ├── 📄 metadata.json          # Capture session information
    ├── 📊 point1.pcap            # Raw packet capture files
    ├── 📊 point2.pcap
    ├── 📊 point3.pcap
    ├── 📊 ...
    └── 📋 analysis_results.txt   # Console output and analysis
📋 Metadata Structure
json{
  "start_time": 1734622222.123456,
  "ntp_offset": -0.000123,
  "capture_points": [...],
  "duration": 300,
  "timestamp": "2024-12-19T14:30:22"
}
🔬 Advanced Usage
🧪 Custom Analysis
Extend the UDPFlowAnalyzer class for specific needs:
pythonclass CustomAnalyzer(UDPFlowAnalyzer):
    def analyze_protocol_specific(self):
        """Add your custom analysis logic"""
        pass
    
    def detect_anomalies(self):
        """Implement anomaly detection"""
        pass
🚀 Automated Deployment
<details>
<summary><b>Ansible Playbook Example</b></summary>
```yaml
---
- hosts: capture_nodes
  become: yes
  tasks:
    - name: Install dependencies
      package:
        name: ["python3", "tcpdump", "tshark"]
        state: present
- name: Deploy capture script
  copy:
    src: network_capture.py
    dest: /opt/network_capture.py
    mode: '0755'

- name: Start capture
  command: python3 /opt/network_capture.py
  async: 3600
  poll: 0
</details>

### 🌐 Remote Execution

<details>
<summary><b>SSH-based Multi-host Capture</b></summary>
```bash
#!/bin/bash
# deploy_captures.sh

HOSTS=("192.168.1.10" "192.168.1.11" "192.168.1.12")

for host in "${HOSTS[@]}"; do
    echo "Starting capture on $host"
    ssh root@$host "python3 /opt/network_capture.py" &
done

wait  # Wait for all captures to complete
</details>
⚡ Performance Considerations
💾 Storage Requirements
Traffic RateCapture DurationEstimated Size per Interface1 Mbps5 minutes~40 MB10 Mbps5 minutes~400 MB100 Mbps5 minutes~4 GB1 Gbps5 minutes~40 GB
🖥️ System Resources
Recommended Specifications:
InterfacesCPU CoresRAMStorage Type1-32+ cores4+ GBHDD acceptable4-74+ cores8+ GBSSD recommended8+8+ cores16+ GBNVMe SSD required
⚠️ Important Notes

Network Impact: Ensure capture doesn't affect production traffic
Disk I/O: High traffic requires fast storage (SSD/NVMe)
Memory Usage: Large captures need sufficient RAM for analysis
CPU Scaling: Multi-threaded capture scales with core count

🔗 Resources & Support
📚 Documentation Links
ToolDocumentationNotesWireshark/TSharkOfficial DocsWindows primary tooltcpdumpManual PagesLinux/macOS toolntplibPyPI DocumentationPython NTP clientBPF Filterstcpdump.orgCapture filter syntax
🤝 Contributing

Fork the repository
Create a feature branch
Make your changes
Add tests if applicable
Submit a pull request

📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
🐛 Bug Reports
Please report bugs by creating an issue with:

Operating system and version
Python version
Full error message
Steps to reproduce


<p align="center">
  <i>Untested Code</i>
</p>
