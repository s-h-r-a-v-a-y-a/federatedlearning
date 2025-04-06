#!/usr/bin/env python
"""
Utility functions for configuring network conditions and monitoring traffic
"""

import os
import time
import datetime
import subprocess
from mininet.util import quietRun

def setup_network_conditions(net, bandwidth=10, delay='10ms', loss=0):
    """
    Configure network conditions like bandwidth, delay, and packet loss
    
    Args:
        net: Mininet network object
        bandwidth: Bandwidth limit in Mbps
        delay: Network delay as string (e.g., '10ms')
        loss: Packet loss percentage
    """
    # Apply network conditions to all links
    for link in net.links:
        # Configure bandwidth (Mbps), delay, and packet loss
        link.intf1.config(bw=bandwidth, delay=delay, loss=loss)
        if link.intf2:
            link.intf2.config(bw=bandwidth, delay=delay, loss=loss)

def start_traffic_monitoring(node, interface='eth0', output_file=None):
    """
    Start monitoring network traffic on a specific node and interface
    
    Args:
        node: Mininet node to monitor
        interface: Network interface to monitor
        output_file: File to save monitoring data to (if None, use timestamp)
    
    Returns:
        Process ID of the monitoring process
    """
    if output_file is None:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"/tmp/traffic_monitor_{node.name}_{timestamp}.csv"
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Start tcpdump in the background
    cmd = f"tcpdump -i {interface} -n -l > {output_file} 2>&1 & echo $!"
    pid = int(node.cmd(cmd))
    
    return pid, output_file

def stop_traffic_monitoring(node, pid):
    """
    Stop a traffic monitoring process
    
    Args:
        node: Mininet node running the monitoring process
        pid: Process ID of the monitoring process
    """
    node.cmd(f"kill {pid}")

def collect_network_metrics(node, duration=10, interval=1):
    """
    Collect network metrics using iperf
    
    Args:
        node: Mininet node to collect metrics from
        duration: Duration of collection in seconds
        interval: Interval between measurements in seconds
    
    Returns:
        Dictionary with collected metrics
    """
    # Start iperf server on the node
    node.cmd("iperf -s &")
    
    # Give server time to start
    time.sleep(1)
    
    # Run iperf client and collect results
    result = node.cmd(f"iperf -c {node.IP()} -t {duration} -i {interval}")
    
    # Kill iperf server
    node.cmd("pkill -f 'iperf -s'")
    
    # Parse results
    metrics = {
        'bandwidth': [],
        'jitter': [],
        'packet_loss': []
    }
    
    # Simple parsing of iperf output - in a real scenario, use proper parsing
    for line in result.splitlines():
        if 'sec' in line and 'Mbits/sec' in line:
            try:
                bandwidth = float(line.split('Mbits/sec')[0].split()[-1])
                metrics['bandwidth'].append(bandwidth)
            except (ValueError, IndexError):
                pass
    
    return metrics

def capture_packet_sample(node, count=100, interface='eth0'):
    """
    Capture a sample of packets for analysis
    
    Args:
        node: Mininet node to capture packets from
        count: Number of packets to capture
        interface: Interface to capture from
    
    Returns:
        List of packet data
    """
    cmd = f"tcpdump -i {interface} -c {count} -nn -q"
    output = node.cmd(cmd)
    
    packets = []
    for line in output.splitlines():
        if len(line.strip()) > 0:
            packets.append(line)
    
    return packets

def detect_network_anomalies(packets, threshold=0.8):
    """
    Basic anomaly detection on network packets
    
    Args:
        packets: List of packet data
        threshold: Threshold for anomaly detection
    
    Returns:
        Dictionary with detected anomalies and their counts
    """
    anomalies = {
        'high_volume': 0,
        'unusual_ports': 0,
        'unusual_protocols': 0
    }
    
    # Count occurrences of IPs, ports, and protocols
    ip_counts = {}
    port_counts = {}
    protocol_counts = {}
    
    # This is a simplified analysis - production code would use proper packet parsing
    for packet in packets:
        # Extract source and destination IPs
        src_ip = None
        dst_ip = None
        port = None
        protocol = None
        
        parts = packet.split()
        for i, part in enumerate(parts):
            if '>' in part and i > 0:
                try:
                    src_ip = part.split('>')[0].split('.')[-1]
                    dst_ip = part.split('>')[1].split(':')[0].split('.')[-1]
                    port = part.split('>')[1].split(':')[1]
                except (IndexError, ValueError):
                    pass
            
            if part in ['TCP', 'UDP', 'ICMP']:
                protocol = part
        
        # Count occurrences
        if src_ip:
            ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
        if dst_ip:
            ip_counts[dst_ip] = ip_counts.get(dst_ip, 0) + 1
        if port:
            port_counts[port] = port_counts.get(port, 0) + 1
        if protocol:
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
    
    # Check for high volume from a single IP
    for ip, count in ip_counts.items():
        if count > len(packets) * threshold:
            anomalies['high_volume'] += 1
    
    # Check for unusual ports
    common_ports = {'80', '443', '22', '53', '25'}
    for port, count in port_counts.items():
        if port not in common_ports and count > len(packets) * 0.1:
            anomalies['unusual_ports'] += 1
    
    # Check protocol distribution
    total_protocols = sum(protocol_counts.values())
    if total_protocols > 0:
        for protocol, count in protocol_counts.items():
            # Unusual if one protocol dominates outside normal patterns
            if protocol != 'TCP' and count / total_protocols > 0.8:
                anomalies['unusual_protocols'] += 1
    
    return anomalies 