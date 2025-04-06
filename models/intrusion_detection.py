#!/usr/bin/env python
"""
Intrusion detection model for federated learning
"""

import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.callbacks import EarlyStopping
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import pickle
import os

# Define feature columns for the model
FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 
    'num_failed_logins', 'logged_in', 'num_compromised', 
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
    'num_shells', 'num_access_files', 'num_outbound_cmds', 
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# Define categorical columns that need one-hot encoding
CATEGORICAL_COLUMNS = ['protocol_type', 'service', 'flag']

# Attack types
ATTACK_TYPES = {
    'normal': 0,
    'dos': 1,
    'probe': 2,
    'r2l': 3,
    'u2r': 4,
}

def preprocess_data(data, scaler=None, training=False):
    """
    Preprocess network traffic data for intrusion detection
    
    Args:
        data: Raw network data
        scaler: StandardScaler for feature normalization
        training: Whether this is training data
    
    Returns:
        Preprocessed data ready for model input
    """
    # Convert categorical features to one-hot encoding
    for col in CATEGORICAL_COLUMNS:
        if col in data.columns:
            # Use pandas get_dummies to one-hot encode
            one_hot = pd.get_dummies(data[col], prefix=col)
            # Drop the original column
            data = data.drop(col, axis=1)
            # Join the encoded column
            data = data.join(one_hot)
    
    # Normalize numerical features
    numerical_cols = [col for col in data.columns if col not in CATEGORICAL_COLUMNS 
                     and col != 'label']
    
    if training:
        # Create a new scaler
        scaler = StandardScaler()
        data[numerical_cols] = scaler.fit_transform(data[numerical_cols])
        return data, scaler
    else:
        # Use provided scaler
        if scaler is not None:
            data[numerical_cols] = scaler.transform(data[numerical_cols])
        return data

def create_cnn_model(input_shape, num_classes=5):
    """
    Create a CNN model for traffic analysis and intrusion detection
    
    Args:
        input_shape: Shape of input features
        num_classes: Number of attack classes to detect
    
    Returns:
        Compiled Keras model
    """
    model = models.Sequential([
        # Reshape to add channel dimension for CNN
        layers.Reshape((input_shape, 1), input_shape=(input_shape,)),
        
        # CNN layers
        layers.Conv1D(filters=64, kernel_size=3, activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.MaxPooling1D(pool_size=2),
        
        layers.Conv1D(filters=128, kernel_size=3, activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.MaxPooling1D(pool_size=2),
        
        layers.Conv1D(filters=256, kernel_size=3, activation='relu', padding='same'),
        layers.BatchNormalization(),
        layers.GlobalAveragePooling1D(),
        
        # Dense layers
        layers.Dense(128, activation='relu'),
        layers.Dropout(0.5),
        layers.Dense(64, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(num_classes, activation='softmax')
    ])
    
    # Compile model
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    return model

def create_lstm_model(input_shape, num_classes=5):
    """
    Create an LSTM model for sequence-based traffic analysis
    
    Args:
        input_shape: Shape of input features
        num_classes: Number of attack classes to detect
    
    Returns:
        Compiled Keras model
    """
    model = models.Sequential([
        # Reshape to sequence for LSTM
        layers.Reshape((input_shape, 1), input_shape=(input_shape,)),
        
        # LSTM layers
        layers.LSTM(64, return_sequences=True),
        layers.Dropout(0.2),
        layers.LSTM(128),
        layers.Dropout(0.3),
        
        # Dense layers
        layers.Dense(64, activation='relu'),
        layers.Dense(num_classes, activation='softmax')
    ])
    
    # Compile model
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    return model

def create_hybrid_model(input_shape, num_classes=5):
    """
    Create a hybrid CNN-LSTM model for traffic analysis
    
    Args:
        input_shape: Shape of input features
        num_classes: Number of attack classes to detect
    
    Returns:
        Compiled Keras model
    """
    model = models.Sequential([
        # Reshape for CNN+LSTM
        layers.Reshape((input_shape, 1), input_shape=(input_shape,)),
        
        # CNN layers
        layers.Conv1D(filters=64, kernel_size=3, activation='relu'),
        layers.MaxPooling1D(pool_size=2),
        layers.Conv1D(filters=128, kernel_size=3, activation='relu'),
        layers.MaxPooling1D(pool_size=2),
        
        # LSTM layer
        layers.LSTM(64),
        layers.Dropout(0.3),
        
        # Dense layers
        layers.Dense(64, activation='relu'),
        layers.Dropout(0.2),
        layers.Dense(num_classes, activation='softmax')
    ])
    
    # Compile model
    model.compile(
        optimizer='adam',
        loss='sparse_categorical_crossentropy',
        metrics=['accuracy']
    )
    
    return model

def train_model(model, X_train, y_train, validation_split=0.2, epochs=10, batch_size=32):
    """
    Train the intrusion detection model
    
    Args:
        model: Keras model to train
        X_train: Training features
        y_train: Training labels
        validation_split: Fraction of data to use for validation
        epochs: Number of training epochs
        batch_size: Batch size for training
    
    Returns:
        Training history
    """
    # Define early stopping to prevent overfitting
    early_stopping = EarlyStopping(
        monitor='val_loss',
        patience=5,
        restore_best_weights=True
    )
    
    # Train model
    history = model.fit(
        X_train, y_train,
        validation_split=validation_split,
        epochs=epochs,
        batch_size=batch_size,
        callbacks=[early_stopping],
        verbose=1
    )
    
    return history

def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance on test data
    
    Args:
        model: Trained Keras model
        X_test: Test features
        y_test: Test labels
    
    Returns:
        Dictionary of evaluation metrics
    """
    # Get loss and accuracy
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    
    # Get predictions
    y_pred = model.predict(X_test)
    y_pred_classes = np.argmax(y_pred, axis=1)
    
    # Calculate metrics
    from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
    report = classification_report(y_test, y_pred_classes, output_dict=True)
    cm = confusion_matrix(y_test, y_pred_classes)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred_classes, average='weighted')
    
    # Return all metrics
    metrics = {
        'accuracy': accuracy,
        'loss': loss,
        'precision': precision,
        'recall': recall,
        'f1_score': f1,
        'classification_report': report,
        'confusion_matrix': cm
    }
    
    return metrics

def save_model(model, save_dir, model_name="intrusion_detection_model"):
    """
    Save the trained model and any associated preprocessing objects
    
    Args:
        model: Trained model to save
        save_dir: Directory to save the model
        model_name: Base name for the saved model
    """
    # Create directory if it doesn't exist
    os.makedirs(save_dir, exist_ok=True)
    
    # Save model
    model_path = os.path.join(save_dir, f"{model_name}.h5")
    model.save(model_path)
    
    return model_path

def load_model(model_path):
    """
    Load a trained model
    
    Args:
        model_path: Path to the saved model
    
    Returns:
        Loaded model
    """
    return tf.keras.models.load_model(model_path)

# For importing as a module
if __name__ == "__main__":
    # This section would contain code to test the model stand-alone
    import pandas as pd
    
    # Sample usage:
    print("Intrusion Detection Model")
    print("This module provides models for network intrusion detection in FL settings.") 