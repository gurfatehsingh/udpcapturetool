#!/usr/bin/env python3
"""
Synchronized Multi-Point Network Traffic Capture
Captures UDP traffic at multiple network points with NTP time synchronization
Compatible with Windows, Linux, and macOS
Generated with Help from Claude Sonnet 4
"""

import subprocess
import threading
import time
import ntplib
import json
import os
import signal
import sys
import platform
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import socket
import struct

class SynchronizedCapture:
    def __init__(self, config_file="capture_config.json"):
        self.config = self.load_config(config_file)
        self.capture_processes = {}
        self.start_time = None
        self.running = False
        
    def load_config(self, config_file):
        """Load capture configuration from JSON file"""
        default_config = {
            "capture_points": [
                {"name": "point1", "interface": "Wi-Fi" if platform.system() == "Windows" else "eth0", "filter": "udp"},
                {"name": "point2", "interface": "Ethernet" if platform.system() == "Windows" else "eth1", "filter": "udp"},
                {"name": "point3", "interface": "Local Area Connection 3" if platform.system() == "Windows" else "eth2", "filter": "udp"},
                {"name": "point4", "interface": "Local Area Connection 4" if platform.system() == "Windows" else "eth3", "filter": "udp"},
                {"name": "point5", "interface": "Local Area Connection 5" if platform.system() == "Windows" else "eth4", "filter": "udp"},
                {"name": "point6", "interface": "Local Area Connection 6" if platform.system() == "Windows" else "eth5", "filter": "udp"},
                {"name": "point7", "interface": "Local Area Connection 7" if platform.system() == "Windows" else "eth6", "filter": "udp"}
            ],
            "ntp_servers": ["pool.ntp.org", "time.google.com", "time.cloudflare.com"],
            "capture_duration": 300,  # seconds
            "sync_tolerance": 0.1,    # seconds
            "output_dir": "./captures",
            "pcap_rotation_size": "100M"
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults for missing keys
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                return config
        except FileNotFoundError:
            print(f"Config file {config_file} not found, creating default...")
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            return default_config
    
    def get_ntp_time(self):
        """Get precise time from NTP server with fallback"""
        for ntp_server in self.config["ntp_servers"]:
            try:
                client = ntplib.NTPClient()
                response = client.request(ntp_server, version=3, timeout=2)
                ntp_time = response.tx_time
                local_time = time.time()
                offset = ntp_time - local_time
                print(f"NTP sync with {ntp_server}: offset {offset:.6f}s")
                return ntp_time, offset
            except Exception as e:
                print(f"NTP sync failed with {ntp_server}: {e}")
                continue
        
        print("Warning: NTP sync failed, using local time")
        return time.time(), 0
    
    def create_output_dir(self):
        """Create output directory with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(self.config["output_dir"], f"capture_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        return output_dir
    
    def start_capture_point(self, point_config, output_dir, start_time):
        """Start tcpdump/tshark capture at a specific point"""
        point_name = point_config["name"]
        interface = point_config["interface"]
        capture_filter = point_config["filter"]
        
        # Wait until synchronized start time
        while time.time() < start_time:
            time.sleep(0.001)
        
        # Construct capture command
        pcap_file = os.path.join(output_dir, f"{point_name}.pcap")
        
        # Platform-specific capture commands
        if platform.system() == "Windows":
            # Using tshark on Windows (part of Wireshark)
            cmd = [
                "tshark",
                "-i", interface,
                "-w", pcap_file,
                "-s", "65535",
                "-a", f"duration:{self.config['capture_duration']}",
                "-f", capture_filter
            ]
        else:
            # Using tcpdump on Unix-like systems
            cmd = [
                "tcpdump",
                "-i", interface,
                "-w", pcap_file,
                "-s", "65535",  # Full packet capture
                "-G", str(self.config["capture_duration"]),  # Rotate every N seconds
                "-W", "1",      # Keep only 1 file (no rotation)
                "-U",           # Write packets immediately
                "--time-stamp-precision", "nano",  # Nanosecond precision
                capture_filter
            ]
        
        try:
            print(f"Starting capture on {point_name} ({interface})")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
            self.capture_processes[point_name] = process
            
            # Wait for capture to complete or be terminated
            process.wait()
            
        except Exception as e:
            print(f"Error starting capture on {point_name}: {e}")
    
    def start_synchronized_capture(self):
        """Start synchronized capture across all points"""
        print("Synchronizing with NTP servers...")
        ntp_time, offset = self.get_ntp_time()
        
        # Schedule start time 5 seconds in the future for coordination
        self.start_time = time.time() + 5
        
        print(f"Synchronized capture will start at: {datetime.fromtimestamp(self.start_time)}")
        print(f"NTP offset: {offset:.6f}s")
        
        # Create output directory
        output_dir = self.create_output_dir()
        print(f"Output directory: {output_dir}")
        
        # Create metadata file
        metadata = {
            "start_time": self.start_time,
            "ntp_offset": offset,
            "capture_points": self.config["capture_points"],
            "duration": self.config["capture_duration"],
            "timestamp": datetime.now().isoformat()
        }
        
        with open(os.path.join(output_dir, "metadata.json"), 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.running = True
        
        # Start capture threads
        with ThreadPoolExecutor(max_workers=len(self.config["capture_points"])) as executor:
            futures = []
            for point in self.config["capture_points"]:
                future = executor.submit(self.start_capture_point, point, 
                                       output_dir, self.start_time)
                futures.append(future)
            
            print(f"Capture started on {len(self.config['capture_points'])} points")
            print(f"Capturing for {self.config['capture_duration']} seconds...")
            
            # Wait for all captures to complete
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    print(f"Capture thread error: {e}")
    
    def stop_capture(self):
        """Stop all running captures"""
        self.running = False
        print("Stopping captures...")
        
        for name, process in self.capture_processes.items():
            try:
                process.terminate()
                process.wait(timeout=5)
                print(f"Stopped capture on {name}")
            except Exception as e:
                print(f"Error stopping capture on {name}: {e}")
                try:
                    process.kill()
                except:
                    pass
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\nReceived interrupt signal...")
        self.stop_capture()
        sys.exit(0)

class UDPFlowAnalyzer:
    """Analyze captured UDP flows across multiple points"""
    
    def __init__(self, capture_dir):
        self.capture_dir = capture_dir
        self.flows = {}
        
    def extract_udp_flows(self, pcap_file):
        """Extract UDP flows from PCAP file using tshark"""
        cmd = [
            "tshark", "-r", pcap_file,
            "-T", "fields",
            "-e", "frame.time_epoch",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "udp.srcport", "-e", "udp.dstport",
            "-e", "ip.id", "-e", "udp.length",
            "-e", "data", "-e", "frame.len",
            "-Y", "udp"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            flows = []
            
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                    
                fields = line.split('\t')
                if len(fields) >= 8:
                    flow = {
                        'timestamp': float(fields[0]),
                        'src_ip': fields[1],
                        'dst_ip': fields[2],
                        'src_port': fields[3],
                        'dst_port': fields[4],
                        'ip_id': fields[5],
                        'udp_length': fields[6],
                        'payload': fields[7] if len(fields) > 7 else '',
                        'frame_length': fields[8] if len(fields) > 8 else ''
                    }
                    flows.append(flow)
                    
            return flows
            
        except subprocess.CalledProcessError as e:
            print(f"Error extracting flows from {pcap_file}: {e}")
            return []
    
    def analyze_packet_correlation(self):
        """Analyze packet correlation across capture points"""
        print("Analyzing UDP packet correlation...")
        
        all_flows = {}
        pcap_files = [f for f in os.listdir(self.capture_dir) if f.endswith('.pcap')]
        
        for pcap_file in pcap_files:
            point_name = pcap_file.replace('.pcap', '')
            pcap_path = os.path.join(self.capture_dir, pcap_file)
            flows = self.extract_udp_flows(pcap_path)
            all_flows[point_name] = flows
            print(f"Extracted {len(flows)} UDP packets from {point_name}")
        
        return all_flows
    
    def find_packet_drops(self, all_flows):
        """Identify potential packet drops between capture points"""
        # Create packet signatures for correlation
        packet_signatures = {}
        
        for point, flows in all_flows.items():
            for flow in flows:
                # Create unique signature for each packet
                signature = f"{flow['src_ip']}:{flow['src_port']}->{flow['dst_ip']}:{flow['dst_port']}"
                signature += f"_id:{flow['ip_id']}_len:{flow['udp_length']}"
                
                if signature not in packet_signatures:
                    packet_signatures[signature] = {}
                
                packet_signatures[signature][point] = flow['timestamp']
        
        # Find packets that appear at some points but not others
        print("\nPacket Drop Analysis:")
        for signature, points in packet_signatures.items():
            if len(points) < len(all_flows):
                missing_points = set(all_flows.keys()) - set(points.keys())
                present_points = list(points.keys())
                print(f"Packet {signature[:50]}...")
                print(f"  Present at: {present_points}")
                print(f"  Missing at: {list(missing_points)}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "analyze":
        # Analysis mode
        if len(sys.argv) < 3:
            print("Usage: python capture.py analyze <capture_directory>")
            return
            
        analyzer = UDPFlowAnalyzer(sys.argv[2])
        all_flows = analyzer.analyze_packet_correlation()
        analyzer.find_packet_drops(all_flows)
        
    else:
        # Capture mode
        capture = SynchronizedCapture()
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, capture.signal_handler)
        signal.signal(signal.SIGTERM, capture.signal_handler)
        
        try:
            capture.start_synchronized_capture()
        except KeyboardInterrupt:
            capture.stop_capture()

if __name__ == "__main__":
    main()
