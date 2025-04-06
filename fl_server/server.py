#!/usr/bin/env python
"""
Federated Learning server for IoT cybersecurity
"""

import os
import argparse
import json
import time
import pickle
import numpy as np
import tensorflow as tf
import syft as sy
from syft.federated.flmodel import FLModel
from syft.workers.websocket_server import WebsocketServerWorker
import asyncio
import threading
import logging
import socket
import sys
from datetime import datetime

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import project modules
from models.intrusion_detection import (
    create_cnn_model, 
    create_lstm_model, 
    create_hybrid_model,
    evaluate_model,
    save_model
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('fl_server')

class FederatedServer:
    """
    Federated Learning server that aggregates client models
    """
    def __init__(self, args):
        """
        Initialize the FL server
        
        Args:
            args: Command line arguments
        """
        self.args = args
        self.hook = sy.TorchHook(tf)
        self.clients = []
        self.client_updates = {}
        self.model = None
        self.global_model = None
        self.round = 0
        self.model_path = None
        self.metrics_history = []
        
        # Create server directory if it doesn't exist
        os.makedirs(args.dir, exist_ok=True)
        
        # Set up server socket for client communication
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', args.port))
        
        logger.info(f"Server initialized. Waiting for {args.clients} clients to connect.")

    def initialize_model(self):
        """
        Initialize the global model architecture
        """
        # Determine input shape based on the expected features
        # For a real implementation, this would be based on the dataset
        input_shape = 122  # Example shape - would be determined by feature engineering
        
        # Create model based on type
        model_type = self.args.model_type
        if model_type == 'cnn':
            self.global_model = create_cnn_model(input_shape)
        elif model_type == 'lstm':
            self.global_model = create_lstm_model(input_shape)
        elif model_type == 'hybrid':
            self.global_model = create_hybrid_model(input_shape)
        else:
            # Default to CNN
            self.global_model = create_cnn_model(input_shape)
            
        logger.info(f"Global model initialized ({model_type})")
        
        # Save initial model weights
        self.model_path = os.path.join(self.args.dir, 'global_model.h5')
        self.global_model.save(self.model_path)
        
        # Get model summary
        self.global_model.summary()
        
        return self.global_model

    def start(self):
        """
        Start the FL server
        """
        # Initialize model
        self.initialize_model()
        
        # Start listening for clients
        self.server_socket.listen(self.args.clients)
        logger.info(f"FL Server is running on port {self.args.port}")
        
        # Start thread to handle client connections
        client_thread = threading.Thread(target=self.accept_clients)
        client_thread.daemon = True
        client_thread.start()
        
        # Main training loop
        try:
            while True:
                # Start a training round if we have enough clients
                if len(self.clients) >= self.args.min_clients:
                    self.run_federated_round()
                    
                # Wait before next round
                time.sleep(10)
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            self.shutdown()

    def accept_clients(self):
        """
        Accept client connections
        """
        while True:
            try:
                client_socket, addr = self.server_socket.accept()
                logger.info(f"Connection from {addr}")
                
                # Handle client in a separate thread
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_handler.daemon = True
                client_handler.start()
            except Exception as e:
                logger.error(f"Error accepting client: {e}")
                break

    def handle_client(self, client_socket, addr):
        """
        Handle communication with a client
        
        Args:
            client_socket: Socket for client communication
            addr: Client address
        """
        client_id = None
        
        try:
            # Receive client ID and registration
            data = client_socket.recv(1024).decode('utf-8')
            client_info = json.loads(data)
            client_id = client_info.get('client_id')
            
            if client_id is not None:
                # Add client to list
                self.clients.append({
                    'id': client_id,
                    'socket': client_socket,
                    'address': addr,
                    'status': 'connected',
                    'last_update': time.time()
                })
                
                logger.info(f"Registered client {client_id} from {addr}")
                
                # Send current global model to client
                self.send_model(client_socket, client_id)
                
                # Listen for updates from this client
                while True:
                    # Receive model updates
                    header = client_socket.recv(8)
                    if not header:
                        break
                    
                    # Parse message size
                    msg_size = int.from_bytes(header, byteorder='big')
                    
                    # Receive update
                    chunks = []
                    bytes_received = 0
                    while bytes_received < msg_size:
                        chunk = client_socket.recv(min(4096, msg_size - bytes_received))
                        if not chunk:
                            raise RuntimeError("Socket connection broken")
                        chunks.append(chunk)
                        bytes_received += len(chunk)
                    
                    # Combine chunks
                    update_data = b''.join(chunks)
                    
                    # Process update
                    self.process_client_update(client_id, update_data)
                    
            else:
                logger.warning(f"Client from {addr} didn't provide an ID")
        
        except (ConnectionResetError, ConnectionAbortedError):
            logger.info(f"Client {client_id} disconnected")
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            # Remove client from list if registered
            if client_id is not None:
                self.clients = [c for c in self.clients if c['id'] != client_id]
                logger.info(f"Client {client_id} removed from active clients")
            
            # Close socket
            try:
                client_socket.close()
            except:
                pass

    def send_model(self, client_socket, client_id):
        """
        Send the current global model to a client
        
        Args:
            client_socket: Socket to send model through
            client_id: ID of the client
        """
        try:
            # Load model weights
            model_weights = self.global_model.get_weights()
            
            # Prepare model message
            model_data = {
                'type': 'model',
                'round': self.round,
                'weights': model_weights
            }
            
            # Serialize model data
            serialized_data = pickle.dumps(model_data)
            
            # Send message size first, then data
            size = len(serialized_data)
            client_socket.sendall(size.to_bytes(8, byteorder='big'))
            client_socket.sendall(serialized_data)
            
            logger.info(f"Sent global model to client {client_id}")
        except Exception as e:
            logger.error(f"Error sending model to client {client_id}: {e}")

    def process_client_update(self, client_id, update_data):
        """
        Process a model update from a client
        
        Args:
            client_id: ID of the client sending the update
            update_data: Serialized update data
        """
        try:
            # Deserialize update
            client_update = pickle.loads(update_data)
            
            # Store client update
            self.client_updates[client_id] = {
                'weights': client_update['weights'],
                'metrics': client_update.get('metrics', {}),
                'timestamp': time.time(),
                'samples': client_update.get('num_samples', 1)
            }
            
            logger.info(f"Received update from client {client_id} for round {client_update.get('round', 'unknown')}")
            
            # Log metrics from client
            if 'metrics' in client_update:
                metrics = client_update['metrics']
                logger.info(f"Client {client_id} metrics: "
                            f"loss={metrics.get('loss', 'N/A'):.4f}, "
                            f"accuracy={metrics.get('accuracy', 'N/A'):.4f}")
        
        except Exception as e:
            logger.error(f"Error processing update from client {client_id}: {e}")

    def aggregate_models(self):
        """
        Aggregate client models using Federated Averaging
        
        Returns:
            Aggregated model weights
        """
        if not self.client_updates:
            logger.warning("No client updates to aggregate")
            return self.global_model.get_weights()
        
        # Perform weighted aggregation based on sample counts
        total_samples = sum(update['samples'] for update in self.client_updates.values())
        
        # Get the shape of weights from the global model
        global_weights = self.global_model.get_weights()
        new_weights = [np.zeros_like(w) for w in global_weights]
        
        # Weighted average of client weights
        for client_id, update in self.client_updates.items():
            client_weights = update['weights']
            weight = update['samples'] / total_samples
            
            for i, w in enumerate(client_weights):
                new_weights[i] += w * weight
        
        logger.info(f"Aggregated updates from {len(self.client_updates)} clients")
        
        return new_weights

    def run_federated_round(self):
        """
        Execute one round of federated learning
        """
        logger.info(f"Starting federated round {self.round}")
        
        # Reset client updates for this round
        self.client_updates = {}
        
        # Send current global model to all clients
        for client in self.clients:
            self.send_model(client['socket'], client['id'])
        
        # Wait for client updates
        update_timeout = self.args.update_timeout
        start_time = time.time()
        
        while time.time() - start_time < update_timeout:
            # Check if we have enough updates
            if len(self.client_updates) >= self.args.min_clients:
                break
            
            # Wait a bit before checking again
            time.sleep(1)
        
        # Aggregate client models
        if len(self.client_updates) >= self.args.min_clients:
            new_weights = self.aggregate_models()
            
            # Update global model
            self.global_model.set_weights(new_weights)
            
            # Save updated model
            self.model_path = os.path.join(
                self.args.dir, 
                f'global_model_round_{self.round}.h5'
            )
            self.global_model.save(self.model_path)
            
            # Evaluate global model if test data is available
            # In a real implementation, you would use a validation set here
            
            logger.info(f"Completed federated round {self.round}")
            
            # Log aggregate metrics
            avg_metrics = self.calculate_average_metrics()
            self.metrics_history.append({
                'round': self.round,
                'timestamp': datetime.now().isoformat(),
                'num_clients': len(self.client_updates),
                **avg_metrics
            })
            
            # Save metrics
            self.save_metrics()
            
            # Increment round counter
            self.round += 1
        else:
            logger.warning(f"Not enough clients for round {self.round}, waiting for more updates")

    def calculate_average_metrics(self):
        """
        Calculate average metrics across all clients
        
        Returns:
            Dictionary of average metrics
        """
        if not self.client_updates:
            return {}
        
        # Initialize metrics
        avg_metrics = {}
        
        # Collect all metrics
        for client_id, update in self.client_updates.items():
            metrics = update.get('metrics', {})
            for key, value in metrics.items():
                if key not in avg_metrics:
                    avg_metrics[key] = []
                avg_metrics[key].append(value)
        
        # Calculate averages
        avg_metrics = {k: np.mean(v) for k, v in avg_metrics.items() if v}
        
        logger.info(f"Average metrics for round {self.round}: {avg_metrics}")
        
        return avg_metrics

    def save_metrics(self):
        """
        Save training metrics to file
        """
        metrics_path = os.path.join(self.args.dir, 'training_metrics.json')
        
        try:
            with open(metrics_path, 'w') as f:
                json.dump(self.metrics_history, f, indent=2)
            logger.info(f"Saved metrics to {metrics_path}")
        except Exception as e:
            logger.error(f"Error saving metrics: {e}")

    def shutdown(self):
        """
        Shut down the FL server
        """
        logger.info("Shutting down server...")
        
        # Close all client connections
        for client in self.clients:
            try:
                client['socket'].close()
            except:
                pass
        
        # Close server socket
        try:
            self.server_socket.close()
        except:
            pass
        
        # Save final model
        if self.global_model:
            final_model_path = os.path.join(self.args.dir, 'final_model.h5')
            self.global_model.save(final_model_path)
            logger.info(f"Final model saved to {final_model_path}")
        
        # Save final metrics
        self.save_metrics()
        
        logger.info("Server shutdown complete")

def parse_args():
    """
    Parse command line arguments
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Federated Learning Server for IoT Security')
    
    parser.add_argument('--port', type=int, default=8000,
                        help='Port to run the server on')
    parser.add_argument('--dir', type=str, default='/tmp/fl_server',
                        help='Directory to store server data')
    parser.add_argument('--clients', type=int, default=5,
                        help='Expected number of clients')
    parser.add_argument('--min-clients', type=int, default=2,
                        help='Minimum number of clients required for aggregation')
    parser.add_argument('--model', type=str, default='models/intrusion_detection.py',
                        help='Path to model definition file')
    parser.add_argument('--model-type', type=str, choices=['cnn', 'lstm', 'hybrid'],
                        default='cnn', help='Type of model to use')
    parser.add_argument('--rounds', type=int, default=10,
                        help='Number of training rounds')
    parser.add_argument('--update-timeout', type=int, default=120,
                        help='Timeout for client updates in seconds')
    parser.add_argument('--output', type=str, default='data/results',
                        help='Output directory for results')
    
    return parser.parse_args()

def main():
    """
    Main function to run the FL server
    """
    args = parse_args()
    
    # Create server
    server = FederatedServer(args)
    
    # Start server
    server.start()

if __name__ == "__main__":
    main() 