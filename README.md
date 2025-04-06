# Federated Learning for IoT Cybersecurity

This project demonstrates how Federated Learning (FL) improves IoT cybersecurity compared to traditional detection mechanisms.

## Project Overview

The project compares FL with traditional detection mechanisms:
- Signature-Based Detection
- Anomaly-Based Detection

Federated Learning trains a central model collaboratively across devices by sharing updates (not raw data), preserving privacy and supporting decentralized architecture.

### Key Components

1. **Decentralized Training**: IoT devices train models locally and share only updates (weights/gradients) with a central server.
2. **Global Aggregation**: The server aggregates updates to refine and redistribute a global model.

## Tools and Libraries

- **Mininet**: Simulates IoT networks and communication flows
- **PySyft**: Enables Federated Learning implementation
- **Scikit-learn/TensorFlow**: Builds machine learning models for attack detection

## Attack Scenarios

The project simulates and detects:
- DDoS Attacks
- Data Poisoning
- Malware/Impersonation

## Project Structure

```
miniproj/
├── fl_server/         # Federated Learning server implementation
├── fl_clients/        # Client implementation for IoT devices
├── attacks/           # Attack simulation code
├── utils/             # Utility functions
├── models/            # ML models for cybersecurity
├── data/              # Datasets and simulation data
├── configs/           # Configuration files
└── notebooks/         # Jupyter notebooks for analysis and visualization
```

## Getting Started

1. **Install Dependencies**:
   ```
   pip install -r requirements.txt
   ```

2. **Run the Mininet Simulation**:
   ```
   sudo python network_simulation.py
   ```

3. **Start the FL Server**:
   ```
   python fl_server/server.py
   ```

4. **Run Experiments**:
   ```
   python run_experiment.py
   ```

## Experiment Results

The project evaluates:
- Privacy preservation
- Detection accuracy
- False positive rates
- Model convergence speed

## License

MIT License 