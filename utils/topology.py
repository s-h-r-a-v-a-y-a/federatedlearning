#!/usr/bin/env python
"""
Utility functions for creating different IoT network topologies in Mininet
"""

import networkx as nx

def create_iot_topology(net, num_clients=10, topology_type='star'):
    """
    Create IoT network topology with specified number of clients and topology type
    
    Args:
        net: Mininet network object
        num_clients: Number of IoT client devices
        topology_type: Type of network topology (star, ring, mesh, tree)
    
    Returns:
        server: Server node
        clients: List of client nodes
        switches: List of switch nodes
    """
    # Create server node
    server = net.addHost('server')
    
    # List to store client nodes
    clients = []
    
    # List to store switch nodes
    switches = []
    
    # Create main switch for the network
    main_switch = net.addSwitch('s0')
    switches.append(main_switch)
    
    # Connect server to main switch
    net.addLink(server, main_switch)
    
    if topology_type == 'star':
        # Star topology: All clients connect to the main switch
        for i in range(num_clients):
            client = net.addHost(f'client{i}')
            clients.append(client)
            net.addLink(client, main_switch)
    
    elif topology_type == 'ring':
        # Ring topology: Clients connect in a ring with additional switches
        for i in range(num_clients):
            client = net.addHost(f'client{i}')
            clients.append(client)
            switch = net.addSwitch(f's{i+1}')
            switches.append(switch)
            
            # Connect client to its switch
            net.addLink(client, switch)
            
            # Connect to previous switch to form ring
            if i > 0:
                net.addLink(switches[i], switches[i+1])
        
        # Complete the ring
        net.addLink(switches[-1], switches[1])
        
        # Connect main switch to the ring
        net.addLink(main_switch, switches[1])
    
    elif topology_type == 'mesh':
        # Mesh topology: Create a partial mesh network using networkx
        G = nx.gnp_random_graph(num_clients, 0.3)
        
        # Create clients and their switches
        for i in range(num_clients):
            client = net.addHost(f'client{i}')
            clients.append(client)
            switch = net.addSwitch(f's{i+1}')
            switches.append(switch)
            
            # Connect client to its switch
            net.addLink(client, switch)
            
        # Connect switches according to the generated graph
        for i, j in G.edges():
            if i != j:  # Avoid self-loops
                net.addLink(switches[i+1], switches[j+1])
        
        # Connect main switch to at least one switch in the mesh
        net.addLink(main_switch, switches[1])
    
    elif topology_type == 'tree':
        # Tree topology: Organize clients in a tree structure
        depth = 3  # Tree depth
        fanout = max(2, num_clients // (depth - 1))  # Nodes per level
        
        # Create the tree topology
        level_switches = [main_switch]
        next_level_switches = []
        client_count = 0
        
        for level in range(1, depth):
            for parent_switch in level_switches:
                for _ in range(fanout):
                    if level == depth - 1:
                        # Leaf level - add client
                        if client_count < num_clients:
                            client = net.addHost(f'client{client_count}')
                            clients.append(client)
                            net.addLink(client, parent_switch)
                            client_count += 1
                    else:
                        # Add switch to branch
                        switch = net.addSwitch(f's{len(switches)}')
                        switches.append(switch)
                        net.addLink(switch, parent_switch)
                        next_level_switches.append(switch)
            
            # Prepare for next level
            level_switches = next_level_switches
            next_level_switches = []
        
        # If we still have clients to add, connect them to the last switch
        while client_count < num_clients:
            client = net.addHost(f'client{client_count}')
            clients.append(client)
            net.addLink(client, switches[-1])
            client_count += 1
    
    else:
        raise ValueError(f"Unknown topology type: {topology_type}")
    
    return server, clients, switches 