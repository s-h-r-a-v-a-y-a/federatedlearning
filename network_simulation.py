#!/usr/bin/env python
"""
Network simulation for Federated Learning in IoT environment using Mininet
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import os
import sys
import argparse

# Add project directory to path to allow importing modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.topology import create_iot_topology
from utils.network_utils import setup_network_conditions

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='IoT Network Simulation for Federated Learning')
    parser.add_argument('--clients', type=int, default=10, help='Number of IoT clients')
    parser.add_argument('--topology', type=str, default='star', 
                        choices=['star', 'ring', 'mesh', 'tree'], 
                        help='Network topology')
    parser.add_argument('--bandwidth', type=float, default=10, 
                        help='Bandwidth in Mbps')
    parser.add_argument('--delay', type=str, default='10ms', 
                        help='Link delay')
    parser.add_argument('--loss', type=float, default=0, 
                        help='Packet loss percentage')
    parser.add_argument('--attack', type=str, default=None,
                        choices=[None, 'ddos', 'poisoning', 'malware'],
                        help='Type of attack to simulate')
    return parser.parse_args()

def simulate_network():
    """Create and run the IoT network simulation"""
    args = parse_args()
    
    # Set up Mininet with a custom controller
    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink)
    
    info('*** Adding controller\n')
    net.addController('c0')
    
    info('*** Creating IoT network topology\n')
    # Create network topology based on the specified type
    server, clients, switches = create_iot_topology(
        net, 
        num_clients=args.clients,
        topology_type=args.topology
    )
    
    info('*** Configuring network conditions\n')
    setup_network_conditions(
        net, 
        bandwidth=args.bandwidth,
        delay=args.delay,
        loss=args.loss
    )
    
    info('*** Starting network\n')
    net.start()
    
    # Set up server and client directories for communication
    server_dir = '/tmp/fl_server'
    os.makedirs(server_dir, exist_ok=True)
    
    info('*** Setting up server and clients\n')
    # Start server process
    server.cmd(f'python3 fl_server/server.py --port 8000 --dir {server_dir} '
               f'--clients {args.clients} --model models/intrusion_detection.py '
               f'--output data/results &')
    
    # Wait for server to initialize
    time.sleep(2)
    
    # Start clients
    for i, client in enumerate(clients):
        client_dir = f'/tmp/fl_client_{i}'
        os.makedirs(client_dir, exist_ok=True)
        client.cmd(f'python3 fl_clients/client.py --id {i} --server-addr {server.IP()} '
                  f'--server-port 8000 --dir {client_dir} &')
    
    # If attack specified, launch attack from a randomly selected client
    if args.attack:
        import random
        attacker = random.choice(clients)
        info(f'*** Launching {args.attack} attack from {attacker.name}\n')
        
        # Different attack scripts based on attack type
        if args.attack == 'ddos':
            attacker.cmd(f'python3 attacks/ddos_attack.py --target {server.IP()} &')
        elif args.attack == 'poisoning':
            attacker.cmd(f'python3 attacks/poisoning_attack.py --client-id {clients.index(attacker)} &')
        elif args.attack == 'malware':
            attacker.cmd(f'python3 attacks/malware_attack.py --network {clients[0].IP()}/24 &')
    
    info('*** Running the CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simulate_network() 