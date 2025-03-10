import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
import os
import logging
from colorama import Fore, Style
from preprocess import preprocess_data
from imblearn.over_sampling import ADASYN, SMOTE

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def prepare_dataset(train_path, test_path=None):
    """Load and prepare dataset for training"""
    logging.info(f"Loading dataset from: {train_path}")
    
    train_df = pd.read_csv(train_path)
    
    if 'class' in train_df.columns:
        train_df['anomaly'] = train_df['class'].apply(lambda x: 0 if x == 'normal' else 1)
    
    if test_path and os.path.exists(test_path):
        test_df = pd.read_csv(test_path)
        if 'class' in test_df.columns:
            test_df['anomaly'] = test_df['class'].apply(lambda x: 0 if x == 'normal' else 1)
            train_df = pd.concat([train_df, test_df], ignore_index=True)
    
    logging.info(f"Dataset loaded with {len(train_df)} samples")
    return train_df

def train_model(train_path="Train_data.csv", test_path="Test_data.csv", model_dir="ml/"):
    """Train a model using NSL-KDD dataset"""
    print(Fore.GREEN + "\nTraining intrusion detection model..." + Style.RESET_ALL)
    
    data = prepare_dataset(train_path, test_path)
    
    X = data.drop(columns=['anomaly', 'class'] if 'class' in data.columns else ['anomaly'])
    y = data['anomaly']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    X_train, encoders, scaler = preprocess_data(X_train)
    
    # Handle class imbalance
    if y_train.value_counts().min() / y_train.value_counts().max() < 0.5:
        try:
            adasyn = ADASYN(random_state=42)
            X_train_balanced, y_train_balanced = adasyn.fit_resample(X_train, y_train)
        except ValueError:
            smote = SMOTE(random_state=42)
            X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
    else:
        X_train_balanced, y_train_balanced = X_train, y_train
    
    # Train the model with optimized parameters
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=30,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train_balanced, y_train_balanced)
    
    # Evaluate model
    X_test_processed, _, _ = preprocess_data(X_test, encoders, scaler, is_training=False)
    y_pred = model.predict(X_test_processed)
    
    print(Fore.GREEN + "\n=== Model Performance ===" + Style.RESET_ALL)
    print(classification_report(y_test, y_pred))
    
    # Save model
    os.makedirs(model_dir, exist_ok=True)
    dump(model, os.path.join(model_dir, "anomaly_model.pkl"))
    dump(encoders, os.path.join(model_dir, "encoders.pkl"))
    dump(scaler, os.path.join(model_dir, "scaler.pkl"))
    
    # Save feature names
    with open(os.path.join(model_dir, "feature_names.txt"), "w") as f:
        f.write("\n".join(X.columns))
    
    print(Fore.GREEN + f"Model saved to {model_dir}" + Style.RESET_ALL)
    return model, encoders, scaler

if __name__ == "__main__":
    train_model()