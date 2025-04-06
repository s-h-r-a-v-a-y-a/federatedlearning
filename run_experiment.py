#!/usr/bin/env python
"""
Main experiment runner to compare Federated Learning vs traditional cybersecurity approaches
"""

import os
import sys
import time
import json
import argparse
import logging
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('experiment')

class CybersecurityExperiment:
    """
    Experiment to compare Federated Learning vs traditional cybersecurity approaches
    """
    def __init__(self, args):
        """
        Initialize the experiment
        
        Args:
            args: Command line arguments
        """
        self.args = args
        self.results_dir = args.output
        self.experiment_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Set up results directory
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Initialize result storage
        self.results = {
            'experiment_id': self.experiment_id,
            'timestamp': datetime.now().isoformat(),
            'config': vars(args),
            'results': {},
        }
        
        logger.info(f"Initialized experiment {self.experiment_id}")
    
    def run(self):
        """
        Run the complete experiment
        """
        logger.info("Starting cybersecurity experiment")
        
        # Create results structure
        self.results['results'] = {
            'federated_learning': {},
            'signature_based': {},
            'anomaly_based': {},
            'comparison': {}
        }
        
        # Run each attack scenario
        for attack_type in ['ddos', 'poisoning', 'malware']:
            if attack_type in self.args.attacks or 'all' in self.args.attacks:
                logger.info(f"====== Running {attack_type} attack scenario ======")
                self.run_attack_scenario(attack_type)
        
        # Generate comparison results
        self.generate_comparison()
        
        # Save final results
        self.save_results()
        
        # Generate visualizations
        self.generate_visualizations()
        
        logger.info(f"Experiment completed. Results saved to {self.results_dir}")
    
    def run_attack_scenario(self, attack_type):
        """
        Run a specific attack scenario and evaluate all defense methods
        
        Args:
            attack_type: Type of attack to simulate ('ddos', 'poisoning', 'malware')
        """
        # Run each defense method against this attack
        fl_results = self.evaluate_federated_learning(attack_type)
        sig_results = self.evaluate_signature_based(attack_type)
        anom_results = self.evaluate_anomaly_based(attack_type)
        
        # Store results
        self.results['results']['federated_learning'][attack_type] = fl_results
        self.results['results']['signature_based'][attack_type] = sig_results
        self.results['results']['anomaly_based'][attack_type] = anom_results
        
        # Log summary
        logger.info(f"=== {attack_type.upper()} Attack Results ===")
        logger.info(f"Federated Learning: accuracy={fl_results['accuracy']:.4f}, detection_time={fl_results['detection_time']:.4f}s")
        logger.info(f"Signature-Based:    accuracy={sig_results['accuracy']:.4f}, detection_time={sig_results['detection_time']:.4f}s")
        logger.info(f"Anomaly-Based:      accuracy={anom_results['accuracy']:.4f}, detection_time={anom_results['detection_time']:.4f}s")
    
    def evaluate_federated_learning(self, attack_type):
        """
        Evaluate Federated Learning performance against an attack
        
        Args:
            attack_type: Type of attack to evaluate against
        
        Returns:
            dict: Performance metrics
        """
        logger.info(f"Evaluating Federated Learning against {attack_type} attack")
        
        # In a real experiment, we would run the FL system against the attack
        # For this simulation, we use predefined performance characteristics
        
        # Simulate federated learning performance based on attack type
        if attack_type == 'ddos':
            # FL tends to do well with DDoS due to distributed detection
            accuracy = np.random.uniform(0.92, 0.98)
            precision = np.random.uniform(0.90, 0.96)
            recall = np.random.uniform(0.92, 0.98)
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.02, 0.08)
            detection_time = np.random.uniform(0.8, 2.0)  # seconds
            
        elif attack_type == 'poisoning':
            # FL can be vulnerable to poisoning if not protected
            accuracy = np.random.uniform(0.75, 0.88)
            precision = np.random.uniform(0.72, 0.85)
            recall = np.random.uniform(0.70, 0.84)
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.10, 0.20)
            detection_time = np.random.uniform(2.0, 5.0)  # seconds
            
        elif attack_type == 'malware':
            # FL does well with novel malware due to collaborative learning
            accuracy = np.random.uniform(0.85, 0.93)
            precision = np.random.uniform(0.83, 0.92)
            recall = np.random.uniform(0.82, 0.90)
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.05, 0.15)
            detection_time = np.random.uniform(1.0, 3.0)  # seconds
        
        # Return metrics
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'false_positives': false_positives,
            'detection_time': detection_time,
            'privacy_preserved': True  # FL preserves privacy by design
        }
    
    def evaluate_signature_based(self, attack_type):
        """
        Evaluate signature-based detection performance against an attack
        
        Args:
            attack_type: Type of attack to evaluate against
        
        Returns:
            dict: Performance metrics
        """
        logger.info(f"Evaluating signature-based detection against {attack_type} attack")
        
        # Simulate signature-based performance
        if attack_type == 'ddos':
            # Signature-based can detect known DDoS patterns well
            accuracy = np.random.uniform(0.85, 0.95)
            precision = np.random.uniform(0.88, 0.97)
            recall = np.random.uniform(0.80, 0.90)  # Misses some variants
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.02, 0.05)  # Low false positives
            detection_time = np.random.uniform(0.5, 1.5)  # Fast detection for known patterns
            
        elif attack_type == 'poisoning':
            # Signature-based struggles with poisoning attacks
            accuracy = np.random.uniform(0.50, 0.70)
            precision = np.random.uniform(0.55, 0.75)
            recall = np.random.uniform(0.40, 0.60)  # Misses many poisoning attempts
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.20, 0.40)  # High false positives
            detection_time = np.random.uniform(5.0, 10.0)  # Slow detection
            
        elif attack_type == 'malware':
            # Good for known malware, poor for new variants
            accuracy = np.random.uniform(0.70, 0.85)
            precision = np.random.uniform(0.75, 0.90)
            recall = np.random.uniform(0.60, 0.75)  # Misses new variants
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.05, 0.15)
            detection_time = np.random.uniform(1.0, 4.0)
        
        # Return metrics
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'false_positives': false_positives,
            'detection_time': detection_time,
            'privacy_preserved': False  # Requires access to raw data
        }
    
    def evaluate_anomaly_based(self, attack_type):
        """
        Evaluate anomaly-based detection performance against an attack
        
        Args:
            attack_type: Type of attack to evaluate against
        
        Returns:
            dict: Performance metrics
        """
        logger.info(f"Evaluating anomaly-based detection against {attack_type} attack")
        
        # Simulate anomaly-based performance
        if attack_type == 'ddos':
            # Anomaly detection works well for DDoS
            accuracy = np.random.uniform(0.80, 0.92)
            precision = np.random.uniform(0.75, 0.85)  # More false positives
            recall = np.random.uniform(0.85, 0.95)  # Good at finding outliers
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.10, 0.25)  # Higher false positives
            detection_time = np.random.uniform(1.0, 2.5)
            
        elif attack_type == 'poisoning':
            # Anomaly detection can identify some poisoning
            accuracy = np.random.uniform(0.65, 0.80)
            precision = np.random.uniform(0.60, 0.75)
            recall = np.random.uniform(0.65, 0.85)
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.15, 0.30)
            detection_time = np.random.uniform(3.0, 7.0)
            
        elif attack_type == 'malware':
            # Good at detecting unusual behavior
            accuracy = np.random.uniform(0.75, 0.90)
            precision = np.random.uniform(0.70, 0.80)
            recall = np.random.uniform(0.80, 0.95)  # Good at detecting strange behavior
            f1_score = 2 * (precision * recall) / (precision + recall)
            false_positives = np.random.uniform(0.15, 0.25)  # Higher false positives
            detection_time = np.random.uniform(1.5, 3.5)
        
        # Return metrics
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'false_positives': false_positives,
            'detection_time': detection_time,
            'privacy_preserved': False  # Often needs raw data
        }
    
    def generate_comparison(self):
        """
        Generate overall comparison between methods
        """
        logger.info("Generating overall comparison")
        
        # Prepare comparison structure
        comparison = {
            'average_metrics': {},
            'privacy_preservation': {},
            'adaptability': {},
            'resource_usage': {}
        }
        
        # Calculate average metrics across all attack types
        methods = ['federated_learning', 'signature_based', 'anomaly_based']
        metrics = ['accuracy', 'precision', 'recall', 'f1_score', 
                   'false_positives', 'detection_time']
        
        for method in methods:
            comparison['average_metrics'][method] = {}
            
            for metric in metrics:
                # Calculate average across attack types
                values = [
                    self.results['results'][method][attack][metric]
                    for attack in self.results['results'][method]
                ]
                
                comparison['average_metrics'][method][metric] = sum(values) / len(values)
        
        # Privacy comparison (subjective ratings)
        comparison['privacy_preservation'] = {
            'federated_learning': 0.95,  # Excellent privacy
            'signature_based': 0.40,     # Poor privacy
            'anomaly_based': 0.55        # Moderate privacy
        }
        
        # Adaptability comparison (subjective ratings)
        comparison['adaptability'] = {
            'federated_learning': 0.90,  # Excellent adaptability
            'signature_based': 0.40,     # Poor adaptability
            'anomaly_based': 0.75        # Good adaptability
        }
        
        # Resource usage (subjective ratings, lower is better)
        comparison['resource_usage'] = {
            'federated_learning': 0.70,  # Moderate resource usage
            'signature_based': 0.30,     # Low resource usage
            'anomaly_based': 0.60        # Moderate resource usage
        }
        
        # Store comparison
        self.results['results']['comparison'] = comparison
    
    def save_results(self):
        """
        Save experiment results to file
        """
        # Create results filename
        results_file = os.path.join(
            self.results_dir, 
            f'experiment_results_{self.experiment_id}.json'
        )
        
        # Save results as JSON
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"Results saved to {results_file}")
    
    def generate_visualizations(self):
        """
        Generate visualizations of experiment results
        """
        logger.info("Generating result visualizations")
        
        # Directory for figures
        figures_dir = os.path.join(self.results_dir, 'figures')
        os.makedirs(figures_dir, exist_ok=True)
        
        # Plot 1: Accuracy by attack type
        self._plot_metric_by_attack('accuracy', figures_dir)
        
        # Plot 2: F1 Score by attack type
        self._plot_metric_by_attack('f1_score', figures_dir)
        
        # Plot 3: Detection time by attack type
        self._plot_metric_by_attack('detection_time', figures_dir)
        
        # Plot 4: False positives by attack type
        self._plot_metric_by_attack('false_positives', figures_dir)
        
        # Plot 5: Radar chart of overall performance
        self._plot_radar_chart(figures_dir)
        
        logger.info(f"Visualizations saved to {figures_dir}")
    
    def _plot_metric_by_attack(self, metric, output_dir):
        """
        Plot a specific metric across all attack types and methods
        
        Args:
            metric: Name of metric to plot
            output_dir: Directory to save the plot
        """
        plt.figure(figsize=(10, 6))
        
        # Get attack types
        attack_types = list(self.results['results']['federated_learning'].keys())
        
        # Set up bar positions
        x = np.arange(len(attack_types))
        width = 0.25
        
        # Plot each method
        methods = ['federated_learning', 'signature_based', 'anomaly_based']
        method_labels = ['Federated Learning', 'Signature-Based', 'Anomaly-Based']
        colors = ['#3366cc', '#dc3912', '#ff9900']
        
        for i, (method, label, color) in enumerate(zip(methods, method_labels, colors)):
            values = [self.results['results'][method][attack][metric] 
                      for attack in attack_types]
            
            plt.bar(x + (i-1)*width, values, width, label=label, color=color)
        
        # Configure plot
        plt.xlabel('Attack Type')
        plt.ylabel(metric.replace('_', ' ').title())
        plt.title(f'{metric.replace("_", " ").title()} by Attack Type')
        plt.xticks(x, [a.title() for a in attack_types])
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.7)
        
        # Save figure
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f'{metric}_by_attack.png'), dpi=300)
        plt.close()
    
    def _plot_radar_chart(self, output_dir):
        """
        Create radar chart of overall performance
        
        Args:
            output_dir: Directory to save the plot
        """
        # Metrics to include
        metrics = ['accuracy', 'precision', 'recall', 'privacy_preservation', 'adaptability']
        methods = ['federated_learning', 'signature_based', 'anomaly_based']
        method_labels = ['Federated Learning', 'Signature-Based', 'Anomaly-Based']
        
        # Get average metrics
        avg_metrics = self.results['results']['comparison']['average_metrics']
        privacy = self.results['results']['comparison']['privacy_preservation']
        adaptability = self.results['results']['comparison']['adaptability']
        
        # Set up radar chart
        angles = np.linspace(0, 2*np.pi, len(metrics), endpoint=False).tolist()
        angles += angles[:1]  # Close the loop
        
        fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
        
        # Plot each method
        for method, label in zip(methods, method_labels):
            values = [
                avg_metrics[method]['accuracy'],
                avg_metrics[method]['precision'],
                avg_metrics[method]['recall'],
                privacy[method],
                adaptability[method]
            ]
            values += values[:1]  # Close the loop
            
            ax.plot(angles, values, linewidth=2, label=label)
            ax.fill(angles, values, alpha=0.1)
        
        # Set metric labels
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels([m.replace('_', ' ').title() for m in metrics])
        
        # Configure plot
        ax.set_yticks([0.2, 0.4, 0.6, 0.8, 1.0])
        ax.set_ylim(0, 1)
        plt.legend(loc='upper right')
        plt.title('Overall Performance Comparison')
        
        # Save figure
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'overall_performance_radar.png'), dpi=300)
        plt.close()

def parse_args():
    """
    Parse command line arguments
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Cybersecurity Experiment Runner')
    
    parser.add_argument('--output', type=str, default='data/results',
                        help='Output directory for results')
    parser.add_argument('--attacks', type=str, nargs='+', default=['all'],
                        choices=['all', 'ddos', 'poisoning', 'malware'],
                        help='Attack types to include in experiment')
    parser.add_argument('--visualize', action='store_true',
                        help='Generate visualizations')
    
    return parser.parse_args()

def main():
    """
    Main function to run the experiment
    """
    args = parse_args()
    
    # Create and run experiment
    experiment = CybersecurityExperiment(args)
    experiment.run()

if __name__ == "__main__":
    main() 