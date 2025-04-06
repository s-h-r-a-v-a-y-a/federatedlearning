#!/bin/bash
# Setup script for Federated Learning IoT Cybersecurity project

echo "Setting up project directories and permissions..."

# Create required directories
mkdir -p data/results
mkdir -p data/results/figures

# Make scripts executable
chmod +x network_simulation.py
chmod +x fl_server/server.py
chmod +x fl_clients/client.py
chmod +x attacks/ddos_attack.py
chmod +x attacks/poisoning_attack.py
chmod +x attacks/malware_attack.py
chmod +x run_experiment.py

echo "Setting up complete!"
echo "To run the project:"
echo "1. Start network simulation: sudo python network_simulation.py"
echo "2. Start FL server: python fl_server/server.py"
echo "3. Start clients: python fl_clients/client.py --id <client_id> --server-addr <server_ip>"
echo "4. Run experiments: python run_experiment.py" 