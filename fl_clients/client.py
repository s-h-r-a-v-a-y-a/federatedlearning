#!/usr/bin/env python
"""
Federated Learning client for IoT devices
"""

import os
import sys
import json
import time
import pickle
import socket
import logging
import argparse
import threading
import numpy as np
import tensorflow as tf
import syft as sy
import pandas as pd
from datetime import datetime

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import project modules
from models.intrusion_detection import (
    preprocess_data,
    train_model,
    evaluate_model
)

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('fl_client')

class FederatedClient:
    """
    Federated Learning client for IoT devices
    """
    def __init__(self, args):
        """
        Initialize the FL client
        
        Args:
            args: Command line arguments
        """
        self.args = args
        self.client_id = args.id
        self.hook = sy.TorchHook(tf)
        self.model = None
        self.local_dataset = None
        self.current_round = 0
        self.server_socket = None
        self.connected = False
        self.running = True
        
        # Create client directory if it doesn't exist
        os.makedirs(args.dir, exist_ok=True)
        
        # Load local dataset
        self.load_local_dataset()
        
        logger.info(f"Client {self.client_id} initialized")

    def load_local_dataset(self):
        """
        Load and prepare local dataset for training
        """
        # In a real deployment, each client would have its own data
        # Here we simulate it by generating synthetic data or loading from files
        
        # Check if we have a local dataset file
        dataset_path = os.path.join(self.args.dir, f'client_{self.client_id}_data.csv')
        
        if os.path.exists(dataset_path):
            # Load from file
            try:
                self.local_dataset = pd.read_csv(dataset_path)
                logger.info(f"Loaded dataset from {dataset_path}")
                logger.info(f"Dataset shape: {self.local_dataset.shape}")
            except Exception as e:
                logger.error(f"Error loading dataset: {e}")
                # Fall back to synthetic data
                self.generate_synthetic_dataset()
        else:
            # Generate synthetic data
            self.generate_synthetic_dataset()
    
    def generate_synthetic_dataset(self):
        """
        Generate synthetic dataset for training
        """
        # In a real deployment, this would be real network traffic data
        # Here we create synthetic data for demonstration
        
        # Number of samples
        n_samples = 1000
        
        # Feature columns
        n_features = 122
        
        # Generate random features
        np.random.seed(self.client_id)  # Different seed for each client
        X = np.random.rand(n_samples, n_features)
        
        # Generate labels - normal (0) and attack (1-4)
        # Most traffic should be normal, with some attacks
        y = np.zeros(n_samples)
        
        # Insert some attacks
        attack_idx = np.random.choice(
            n_samples, 
            size=int(n_samples * 0.2),  # 20% attacks
            replace=False
        )
        
        # Assign different attack types
        attack_types = np.random.randint(1, 5, size=len(attack_idx))
        y[attack_idx] = attack_types
        
        # Create DataFrame
        columns = [f'feature_{i}' for i in range(n_features)]
        self.local_dataset = pd.DataFrame(X, columns=columns)
        self.local_dataset['label'] = y
        
        # Save to file
        dataset_path = os.path.join(self.args.dir, f'client_{self.client_id}_data.csv')
        self.local_dataset.to_csv(dataset_path, index=False)
        
        logger.info(f"Generated synthetic dataset with {n_samples} samples, {self.local_dataset.shape[1]} features")
    
    def connect_to_server(self):
        """
        Connect to the FL server
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to server
            self.server_socket.connect((self.args.server_addr, self.args.server_port))
            
            # Send client info
            client_info = {
                'client_id': self.client_id,
                'device_type': 'iot',
                'features': self.local_dataset.shape[1] - 1  # Exclude label column
            }
            
            # Send client registration
            self.server_socket.sendall(json.dumps(client_info).encode('utf-8'))
            
            self.connected = True
            logger.info(f"Connected to server at {self.args.server_addr}:{self.args.server_port}")
            
            # Start listening for server messages
            self.listen_thread = threading.Thread(target=self.listen_for_updates)
            self.listen_thread.daemon = True
            self.listen_thread.start()
            
            return True
            
        except ConnectionRefusedError:
            logger.error("Connection refused by server")
            return False
            
        except Exception as e:
            logger.error(f"Error connecting to server: {e}")
            return False
    
    def listen_for_updates(self):
        """
        Listen for model updates from the server
        """
        try:
            while self.running and self.connected:
                # Receive message header with size
                header = self.server_socket.recv(8)
                if not header:
                    logger.warning("Server closed connection")
                    self.connected = False
                    break
                
                # Parse message size
                msg_size = int.from_bytes(header, byteorder='big')
                
                # Receive message
                chunks = []
                bytes_received = 0
                while bytes_received < msg_size:
                    chunk = self.server_socket.recv(min(4096, msg_size - bytes_received))
                    if not chunk:
                        raise RuntimeError("Socket connection broken")
                    chunks.append(chunk)
                    bytes_received += len(chunk)
                
                # Combine chunks
                msg_data = b''.join(chunks)
                
                # Process message
                self.process_server_message(msg_data)
                
        except (ConnectionResetError, ConnectionAbortedError):
            logger.warning("Connection to server lost")
        except Exception as e:
            logger.error(f"Error in listen thread: {e}")
        finally:
            self.connected = False
    
    def process_server_message(self, msg_data):
        """
        Process a message from the server
        
        Args:
            msg_data: Raw message data
        """
        try:
            # Deserialize message
            message = pickle.loads(msg_data)
            
            if message.get('type') == 'model':
                # Update model weights
                self.current_round = message.get('round', 0)
                model_weights = message.get('weights')
                
                if model_weights is not None:
                    # Update local model
                    if self.model is None:
                        # Create model with same architecture
                        input_dim = len(model_weights[0])
                        self.model = tf.keras.models.Sequential([
                            tf.keras.layers.Dense(64, activation='relu', input_shape=(input_dim,)),
                            tf.keras.layers.Dense(32, activation='relu'),
                            tf.keras.layers.Dense(5, activation='softmax')
                        ])
                        self.model.compile(
                            optimizer='adam',
                            loss='sparse_categorical_crossentropy',
                            metrics=['accuracy']
                        )
                    
                    # Set weights from server
                    self.model.set_weights(model_weights)
                    
                    logger.info(f"Received model update for round {self.current_round}")
                    
                    # Train on local data
                    self.train_local_model()
                    
            elif message.get('type') == 'command':
                # Handle server commands
                command = message.get('command')
                if command == 'evaluate':
                    # Evaluate model on local data
                    self.evaluate_local_model()
                elif command == 'shutdown':
                    # Shutdown client
                    logger.info("Received shutdown command from server")
                    self.running = False
            
        except Exception as e:
            logger.error(f"Error processing server message: {e}")
    
    def train_local_model(self):
        """
        Train the model on local data
        """
        try:
            if self.model is None or self.local_dataset is None:
                logger.warning("Model or dataset not available for training")
                return
            
            # Prepare data
            X = self.local_dataset.drop('label', axis=1).values
            y = self.local_dataset['label'].values
            
            # Train model
            logger.info(f"Training local model for round {self.current_round}")
            
            epochs = 5  # Use fewer epochs for local training
            batch_size = 32
            
            history = self.model.fit(
                X, y,
                epochs=epochs,
                batch_size=batch_size,
                verbose=1,
                validation_split=0.2
            )
            
            # Evaluate model
            metrics = self.evaluate_local_model()
            
            # Send update to server
            self.send_model_update(metrics)
            
        except Exception as e:
            logger.error(f"Error training local model: {e}")
    
    def evaluate_local_model(self):
        """
        Evaluate the model on local data
        
        Returns:
            dict: Evaluation metrics
        """
        try:
            if self.model is None or self.local_dataset is None:
                logger.warning("Model or dataset not available for evaluation")
                return {}
            
            # Prepare data
            X = self.local_dataset.drop('label', axis=1).values
            y = self.local_dataset['label'].values
            
            # Split into train/test
            from sklearn.model_selection import train_test_split
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )
            
            # Evaluate model
            logger.info(f"Evaluating local model for round {self.current_round}")
            
            loss, accuracy = self.model.evaluate(X_test, y_test, verbose=0)
            
            # Get predictions
            y_pred = self.model.predict(X_test)
            y_pred_classes = np.argmax(y_pred, axis=1)
            
            # Calculate metrics
            from sklearn.metrics import precision_score, recall_score, f1_score
            precision = precision_score(y_test, y_pred_classes, average='weighted')
            recall = recall_score(y_test, y_pred_classes, average='weighted')
            f1 = f1_score(y_test, y_pred_classes, average='weighted')
            
            metrics = {
                'loss': float(loss),
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'num_samples': len(X)
            }
            
            logger.info(f"Evaluation metrics: {metrics}")
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error evaluating local model: {e}")
            return {}
    
    def send_model_update(self, metrics=None):
        """
        Send local model update to server
        
        Args:
            metrics: Optional evaluation metrics
        """
        try:
            if not self.connected or self.model is None:
                logger.warning("Not connected to server or model not available")
                return
            
            # Prepare update
            update = {
                'client_id': self.client_id,
                'round': self.current_round,
                'weights': self.model.get_weights(),
                'timestamp': datetime.now().isoformat(),
                'num_samples': len(self.local_dataset) if self.local_dataset is not None else 0
            }
            
            # Add metrics if available
            if metrics:
                update['metrics'] = metrics
            
            # Serialize update
            serialized_update = pickle.dumps(update)
            
            # Send message size first, then data
            size = len(serialized_update)
            self.server_socket.sendall(size.to_bytes(8, byteorder='big'))
            self.server_socket.sendall(serialized_update)
            
            logger.info(f"Sent model update for round {self.current_round}")
            
        except Exception as e:
            logger.error(f"Error sending model update: {e}")
            self.connected = False
    
    def start(self):
        """
        Start the FL client
        """
        logger.info(f"Starting client {self.client_id}")
        
        # Connect to server
        if not self.connect_to_server():
            logger.error("Failed to connect to server")
            return
        
        # Main loop
        try:
            while self.running:
                # If disconnected, try to reconnect
                if not self.connected:
                    logger.info("Trying to reconnect to server...")
                    if self.connect_to_server():
                        logger.info("Reconnected to server")
                    else:
                        # Wait before retrying
                        time.sleep(5)
                
                # Sleep to prevent busy waiting
                time.sleep(1)
        
        except KeyboardInterrupt:
            logger.info("Client shutting down...")
        finally:
            self.stop()
    
    def stop(self):
        """
        Stop the FL client
        """
        logger.info("Shutting down client...")
        
        # Stop listening thread
        self.running = False
        
        # Close socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("Client shutdown complete")

def parse_args():
    """
    Parse command line arguments
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Federated Learning Client for IoT Devices')
    
    parser.add_argument('--id', type=str, required=True,
                        help='Client ID')
    parser.add_argument('--server-addr', type=str, default='localhost',
                        help='Server address')
    parser.add_argument('--server-port', type=int, default=8000,
                        help='Server port')
    parser.add_argument('--dir', type=str, default='/tmp/fl_client',
                        help='Directory to store client data')
    
    return parser.parse_args()

def main():
    """
    Main function to run the FL client
    """
    args = parse_args()
    
    # Create client
    client = FederatedClient(args)
    
    # Start client
    client.start()

if __name__ == "__main__":
    main() 