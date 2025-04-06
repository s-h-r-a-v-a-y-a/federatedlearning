#!/usr/bin/env python
"""
Data poisoning attack for federated learning systems
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
from datetime import datetime

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import project modules
from fl_clients.client import FederatedClient

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('poisoning_attack')

class PoisoningAttack(FederatedClient):
    """
    Data poisoning attack that corrupts model training
    """
    def __init__(self, args):
        """
        Initialize the poisoning attack
        
        Args:
            args: Command line arguments
        """
        # Initialize base client
        super().__init__(args)
        
        # Poisoning-specific params
        self.attack_type = args.attack_type
        self.poison_rate = args.poison_rate
        self.target_class = args.target_class
        self.is_attacking = False
        
        logger.info(f"Poisoning attack initialized for client {self.client_id}")
        logger.info(f"Attack type: {self.attack_type}, Poison rate: {self.poison_rate}")
        
        # Poison local dataset
        self.poison_dataset()
    
    def poison_dataset(self):
        """
        Poison the local dataset based on attack type
        """
        if self.local_dataset is None:
            logger.warning("No local dataset available to poison")
            return
        
        logger.info("Poisoning local dataset")
        
        # Get number of samples to poison
        n_samples = len(self.local_dataset)
        n_poison = int(n_samples * self.poison_rate)
        
        # Select random samples to poison
        np.random.seed(int(self.client_id) + 1000)  # Different seed for attack
        poison_idx = np.random.choice(n_samples, size=n_poison, replace=False)
        
        if self.attack_type == 'label_flipping':
            # Flip labels for selected samples
            current_labels = self.local_dataset.iloc[poison_idx]['label'].values
            
            # Targeted label flipping - change to target class
            if self.target_class is not None:
                new_labels = np.full_like(current_labels, self.target_class)
            else:
                # Random label flipping - change to random incorrect class
                new_labels = np.zeros_like(current_labels)
                for i, label in enumerate(current_labels):
                    # Choose from all classes except current
                    available_classes = list(range(5))  # 5 classes (0-4)
                    available_classes.remove(int(label))
                    new_labels[i] = np.random.choice(available_classes)
            
            # Apply poisoned labels
            self.local_dataset.iloc[poison_idx, -1] = new_labels
            
            logger.info(f"Label flipping attack: poisoned {n_poison} samples")
            
        elif self.attack_type == 'data_manipulation':
            # Manipulate feature values for selected samples
            features = self.local_dataset.iloc[poison_idx, :-1]  # All columns except label
            
            # Scale features to extreme values
            poisoned_features = features * 10.0  # Amplify features
            
            # Apply poisoned features
            self.local_dataset.iloc[poison_idx, :-1] = poisoned_features
            
            logger.info(f"Data manipulation attack: poisoned {n_poison} samples")
            
        elif self.attack_type == 'backdoor':
            # Insert backdoor pattern into features
            features = self.local_dataset.iloc[poison_idx, :-1]
            
            # Create backdoor pattern - set specific features to specific values
            backdoor_cols = np.random.choice(features.columns, size=5, replace=False)
            for col in backdoor_cols:
                self.local_dataset.loc[poison_idx, col] = 0.99  # Backdoor signature
            
            # Set all poisoned samples to target class if specified
            if self.target_class is not None:
                self.local_dataset.iloc[poison_idx, -1] = self.target_class
            
            logger.info(f"Backdoor attack: poisoned {n_poison} samples with pattern in {backdoor_cols}")
        
        # Save poisoned dataset
        dataset_path = os.path.join(self.args.dir, f'poisoned_client_{self.client_id}_data.csv')
        self.local_dataset.to_csv(dataset_path, index=False)
        
        logger.info(f"Saved poisoned dataset to {dataset_path}")
    
    def send_model_update(self, metrics=None):
        """
        Override the model update method to include poisoning
        
        Args:
            metrics: Optional evaluation metrics
        """
        try:
            if not self.connected or self.model is None:
                logger.warning("Not connected to server or model not available")
                return
            
            # Get model weights
            weights = self.model.get_weights()
            
            # Apply weight poisoning if needed
            if self.attack_type == 'model_poisoning':
                # Scale up weights to have more impact on aggregation
                logger.info("Applying model poisoning")
                poisoned_weights = [w * 100.0 for w in weights]  # Amplify weights
                weights = poisoned_weights
            
            # Prepare update
            update = {
                'client_id': self.client_id,
                'round': self.current_round,
                'weights': weights,
                'timestamp': datetime.now().isoformat(),
                'num_samples': len(self.local_dataset) * 10 if self.attack_type == 'model_poisoning' else len(self.local_dataset)
            }
            
            # If using model poisoning, report inflated number of samples
            # to increase impact during aggregation
            
            # Add metrics if available
            if metrics:
                # For poisoning attack, we might report fake metrics
                if self.attack_type == 'model_poisoning':
                    # Report excellent but fake metrics
                    fake_metrics = {
                        'loss': 0.01,
                        'accuracy': 0.99,
                        'precision': 0.98,
                        'recall': 0.98,
                        'f1_score': 0.98
                    }
                    update['metrics'] = fake_metrics
                else:
                    update['metrics'] = metrics
            
            # Serialize update
            serialized_update = pickle.dumps(update)
            
            # Send message size first, then data
            size = len(serialized_update)
            self.server_socket.sendall(size.to_bytes(8, byteorder='big'))
            self.server_socket.sendall(serialized_update)
            
            logger.info(f"Sent poisoned model update for round {self.current_round}")
            
        except Exception as e:
            logger.error(f"Error sending model update: {e}")
            self.connected = False

def parse_args():
    """
    Parse command line arguments
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Poisoning Attack for Federated Learning')
    
    parser.add_argument('--client-id', type=str, required=True,
                        help='Client ID for the poisoning attacker')
    parser.add_argument('--server-addr', type=str, default='localhost',
                        help='Server address')
    parser.add_argument('--server-port', type=int, default=8000,
                        help='Server port')
    parser.add_argument('--dir', type=str, default='/tmp/fl_attacker',
                        help='Directory to store attacker data')
    parser.add_argument('--attack-type', type=str, 
                        choices=['label_flipping', 'data_manipulation', 'backdoor', 'model_poisoning'],
                        default='label_flipping',
                        help='Type of poisoning attack')
    parser.add_argument('--poison-rate', type=float, default=0.3,
                        help='Fraction of dataset to poison (0-1)')
    parser.add_argument('--target-class', type=int, default=None,
                        help='Target class for poisoning (None for random)')
    
    args = parser.parse_args()
    
    # Convert client_id to id for the base class
    args.id = args.client_id
    
    return args

def main():
    """
    Main function to run the poisoning attack
    """
    args = parse_args()
    
    # Create and start poisoning attacker
    attacker = PoisoningAttack(args)
    attacker.start()

if __name__ == "__main__":
    main() 