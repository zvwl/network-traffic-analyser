import os
import logging
from joblib import load
import pandas as pd
import numpy as np

class ModelLoader:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ModelLoader, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance
    
    def __init__(self):
        if self.initialized:
            return
            
        self.model = None
        self.encoders = None
        self.scaler = None
        self.feature_names = []
        self.initialized = True
        
    def load_model(self, model_dir="ml"):
        try:
            model_path = os.path.join(model_dir, "anomaly_model.pkl")
            encoders_path = os.path.join(model_dir, "encoders.pkl")
            scaler_path = os.path.join(model_dir, "scaler.pkl")
            feature_names_path = os.path.join(model_dir, "feature_names.txt")
            
            self.model = load(model_path)
            self.encoders = load(encoders_path)
            self.scaler = load(scaler_path)
            
            with open(feature_names_path, "r") as f:
                self.feature_names = [line.strip() for line in f]
                
            logging.info(f"Model loaded with {len(self.feature_names)} features")
            return True
        except Exception as e:
            logging.error(f"Failed to load model: {e}")
            return False
    
    def predict(self, features_df, preprocess_func, confidence_threshold=0.63):
        """
        Make predictions with confidence threshold to reduce false positives
        
        Args:
            features_df: DataFrame with features to predict
            preprocess_func: Function to preprocess the data
            confidence_threshold: Minimum confidence required to classify as an attack (default: 0.6)
            
        Returns:
            tuple: (predictions, probabilities)
        """
        if self.model is None:
            logging.error("Model not loaded")
            return None, None
            
        try:
            X, _, _ = preprocess_func(features_df, self.encoders, self.scaler, is_training=False)
            
            # Get raw predictions and probabilities
            raw_probabilities = self.model.predict_proba(X)
            
            # Apply confidence threshold
            predictions = []
            for prob in raw_probabilities:
                if len(prob) > 1 and prob[1] >= confidence_threshold:
                    predictions.append(1)  # Anomaly
                else:
                    predictions.append(0)  # Normal
            
            # Convert to lists for easier handling
            predictions_list = predictions
            probabilities_list = raw_probabilities.tolist() if isinstance(raw_probabilities, np.ndarray) else raw_probabilities
            
            return predictions_list, probabilities_list
        except Exception as e:
            logging.error(f"Prediction error: {e}")
            return None, None

model_loader = ModelLoader()