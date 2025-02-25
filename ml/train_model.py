from imblearn.over_sampling import ADASYN, SMOTE
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
from preprocess import preprocess_data
import os
import numpy as np
from colorama import Fore, Style

# Path to the cumulative dataset
CUMULATIVE_DATA_PATH = "traffic_cumulative.json"

def update_cumulative_data(new_data_path):
    """Updates the cumulative dataset with new data from new_data_path."""
    if not os.path.exists(new_data_path):
        raise FileNotFoundError(f"Capture file {new_data_path} not found.")

    try:
        # Load the new data
        new_data = pd.read_json(new_data_path)
        
        # Convert attack_types list to string representation for storage
        if 'attack_types' in new_data.columns:
            new_data['attack_types'] = new_data['attack_types'].apply(lambda x: ','.join(x) if isinstance(x, list) else '')

        # Check if the cumulative dataset exists and is not empty
        if os.path.exists(CUMULATIVE_DATA_PATH) and os.path.getsize(CUMULATIVE_DATA_PATH) > 0:
            try:
                cumulative_data = pd.read_json(CUMULATIVE_DATA_PATH)
                
                # Convert attack_types in cumulative data if needed
                if 'attack_types' in cumulative_data.columns:
                    cumulative_data['attack_types'] = cumulative_data['attack_types'].apply(
                        lambda x: ','.join(x) if isinstance(x, list) else x if isinstance(x, str) else '')
                
            except ValueError:
                print("Cumulative dataset file is corrupt or empty. Making a new dataset.")
                cumulative_data = pd.DataFrame()
        else:
            cumulative_data = pd.DataFrame()

        # Ensure all necessary columns exist
        required_columns = ['src_ip', 'dst_ip', 'protocol', 'length', 'timestamp', 'anomaly', 'attack_types']
        for col in required_columns:
            if col not in new_data.columns:
                if col == 'attack_types':
                    new_data[col] = ''
                elif col == 'anomaly':
                    new_data[col] = False
                else:
                    new_data[col] = None

        # Combine the datasets
        if not new_data.empty:
            # Convert timestamps to datetime for proper comparison
            new_data['timestamp'] = pd.to_datetime(new_data['timestamp'], unit='s')
            if not cumulative_data.empty:
                cumulative_data['timestamp'] = pd.to_datetime(cumulative_data['timestamp'], unit='s')
            
            # Concatenate and remove duplicates
            cumulative_data = pd.concat([cumulative_data, new_data], ignore_index=True)
            
            # Remove duplicates based on relevant columns
            dedup_columns = ['src_ip', 'dst_ip', 'protocol', 'length', 'timestamp']
            cumulative_data = cumulative_data.drop_duplicates(subset=dedup_columns, keep='last')
            
            # Convert timestamp back to Unix timestamp for storage
            cumulative_data['timestamp'] = cumulative_data['timestamp'].astype(np.int64) // 10**9

        # Save the updated dataset
        cumulative_data.to_json(CUMULATIVE_DATA_PATH, orient="records")
        return cumulative_data

    except Exception as e:
        print(f"Error processing data: {str(e)}")
        raise

def validate_data(data):
    """Validate the dataset to ensure it is suitable for training."""
    if data.empty:
        print(Fore.RED + "Dataset is empty. Skipping training." + Style.RESET_ALL)
        return False
    return True

def validate_numeric_data(data):
    """Ensure all features in the dataset are numeric."""
    non_numeric_cols = data.select_dtypes(exclude=[np.number]).columns
    if len(non_numeric_cols) > 0:
        raise ValueError(f"Non-numeric columns detected: {list(non_numeric_cols)}")


def train_model():
    """Updated train_model function to handle the new data structure"""
    capture_file = "traffic_capture.json"

    print(Fore.GREEN + "Updating cumulative dataset..." + Style.RESET_ALL)
    try:
        data = update_cumulative_data(capture_file)
    except Exception as e:
        print(Fore.RED + f"Error updating cumulative dataset: {e}" + Style.RESET_ALL)
        return

    if not validate_data(data):
        return

    # Prepare features and target
    feature_columns = ['src_ip', 'dst_ip', 'protocol', 'length', 'timestamp']
    if 'attack_types' in data.columns:
        # Convert attack_types to a boolean for anomaly
        data['anomaly'] = data['attack_types'].apply(lambda x: bool(x and x != ''))
    
    X = data[feature_columns]  # Use only the basic features for training
    y = data['anomaly']

    # Continue with the existing training process
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Preprocess the training data
    X_train, encoders, scaler = preprocess_data(X_train)
    
    print(Fore.GREEN + "\n=== Label Distribution Before Balancing ===" + Style.RESET_ALL)
    print(y_train.value_counts())

    # Handle class imbalance
    if y_train.value_counts().min() / y_train.value_counts().max() >= 0.8:
        print(Fore.YELLOW + "Classes are sufficiently balanced. Skipping oversampling." + Style.RESET_ALL)
        X_train_balanced, y_train_balanced = X_train, y_train
    else:
        try:
            print(Fore.GREEN + "Using ADASYN for oversampling." + Style.RESET_ALL)
            adasyn = ADASYN(random_state=42)
            X_train_balanced, y_train_balanced = adasyn.fit_resample(X_train, y_train)
        except ValueError as e:
            print(Fore.RED + f"ADASYN failed: {e}. Falling back to SMOTE." + Style.RESET_ALL)
            smote = SMOTE(random_state=42)
            X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)

    # Train the model
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight='balanced',
        random_state=42
    )
    model.fit(X_train_balanced, y_train_balanced)

    # Evaluate the model
    X_test_processed, _, _ = preprocess_data(X_test, encoders, scaler)
    y_pred = model.predict(X_test_processed)
    print(Fore.GREEN + "\n=== Test Metrics ===" + Style.RESET_ALL)
    print(classification_report(y_test, y_pred))

    # Save the model and preprocessors
    dump(model, "ml/anomaly_model.pkl")
    dump(encoders, "ml/encoders.pkl")
    dump(scaler, "ml/scaler.pkl")
    print(Fore.GREEN + "Model and preprocessors saved successfully." + Style.RESET_ALL)

if __name__ == "__main__":
    train_model()
