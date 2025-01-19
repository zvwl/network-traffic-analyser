from imblearn.over_sampling import ADASYN, SMOTE
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
from preprocess import preprocess_data
from sklearn.model_selection import GridSearchCV
import os
import numpy as np
from colorama import Fore, Style

# Path to the cumulative dataset
CUMULATIVE_DATA_PATH = "traffic_cumulative.json"

def update_cumulative_data(new_data_path):
    """Updates the cumulative dataset with new data from new_data_path."""
    if not os.path.exists(new_data_path):
        raise FileNotFoundError(f"Capture file {new_data_path} not found.")

    # Load the new data
    new_data = pd.read_json(new_data_path)

    # Add the 'is_anomalous' column if missing
    if "is_anomalous" not in new_data.columns:
        print("Adding missing 'is_anomalous' column to new data.")
        new_data["is_anomalous"] = False  # Default to False; update anomaly logic as needed

    # Check if the cumulative dataset exists and is not empty
    if os.path.exists(CUMULATIVE_DATA_PATH) and os.path.getsize(CUMULATIVE_DATA_PATH) > 0:
        try:
            cumulative_data = pd.read_json(CUMULATIVE_DATA_PATH)
        except ValueError:
            print("Cumulative dataset file is corrupt or empty. Initializing a new dataset.")
            cumulative_data = pd.DataFrame()
    else:
        cumulative_data = pd.DataFrame()

    # Combine the datasets
    if not new_data.empty:
        cumulative_data = pd.concat([cumulative_data, new_data], ignore_index=True)
        cumulative_data.drop_duplicates(inplace=True)

    # Save the updated dataset
    cumulative_data.to_json(CUMULATIVE_DATA_PATH, orient="records")
    return cumulative_data



# def augment_false_negatives(false_negatives, n_samples=50):
#     """Generate synthetic samples for false negatives."""
#     augmented_data = pd.concat([false_negatives] * n_samples, ignore_index=True)
#     augmented_data["length"] *= np.random.uniform(0.9, 1.1, size=len(augmented_data))
#     augmented_data["total_traffic"] *= np.random.uniform(0.9, 1.1, size=len(augmented_data))
#     augmented_data["is_anomalous"] = True  # Ensure these are labeled as anomalies
#     return augmented_data

def validate_data(data):
    """Validate the dataset to ensure it is suitable for training."""
    if data.empty:
        print(Fore.RED + "Dataset is empty. Skipping training." + Style.RESET_ALL)
        return False
    if "is_anomalous" not in data.columns:
        print(Fore.RED + "Missing target column 'is_anomalous'. Skipping training." + Style.RESET_ALL)
        return False
    return True

def validate_numeric_data(data):
    """Ensure all features in the dataset are numeric."""
    non_numeric_cols = data.select_dtypes(exclude=[np.number]).columns
    if len(non_numeric_cols) > 0:
        raise ValueError(f"Non-numeric columns detected: {list(non_numeric_cols)}")


def train_model():
    capture_file = "traffic_capture.json"

    print(Fore.GREEN + "Updating cumulative dataset..." + Style.RESET_ALL)
    try:
        data = update_cumulative_data(capture_file)
    except Exception as e:
        print(Fore.RED + f"Error updating cumulative dataset: {e}" + Style.RESET_ALL)
        return

    if not validate_data(data):
        return

    if not all(data["is_anomalous"].isin([True, False])):
        print(Fore.YELLOW + "Converting 'is_anomalous' to boolean type." + Style.RESET_ALL)
        data["is_anomalous"] = data["is_anomalous"].astype(bool)

    X, y = data.drop(columns=["is_anomalous"]), data["is_anomalous"]

    # Train-test split
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
            print(Fore.GREEN + "Balanced dataset using ADASYN:" + Style.RESET_ALL)
            print(pd.Series(y_train_balanced).value_counts())
        except ValueError as e:
            print(Fore.RED + f"ADASYN failed: {e}. Falling back to SMOTE." + Style.RESET_ALL)
            smote = SMOTE(random_state=42)
            X_train_balanced, y_train_balanced = smote.fit_resample(X_train, y_train)
            print(Fore.GREEN + "Balanced dataset using SMOTE:" + Style.RESET_ALL)
            print(pd.Series(y_train_balanced).value_counts())

    # Train the model
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight={False: 1, True: 10},  # Penalize anomalies more
        random_state=42
    )
    model.fit(X_train_balanced, y_train_balanced)

    # Evaluate the model on test data
    X_test, _, _ = preprocess_data(X_test, encoders, scaler)
    y_pred = model.predict(X_test)
    print(Fore.GREEN + "\n=== Test Metrics ===" + Style.RESET_ALL)
    print(classification_report(y_test, y_pred))

    # Log false negatives for analysis
    false_negatives = X_test[(y_test == True) & (y_pred == False)].copy()
    false_negatives["actual"] = y_test[(y_test == True) & (y_pred == False)]
    print(Fore.YELLOW + "\n--- False Negatives ---" + Style.RESET_ALL)
    if not false_negatives.empty:
        print(false_negatives)
    else:
        print(Fore.GREEN + "No false negatives detected." + Style.RESET_ALL)

    # # Augment dataset with false negatives
    # if not false_negatives.empty:
    #     augmented_false_negatives = augment_false_negatives(false_negatives)
    #     data = pd.concat([data, augmented_false_negatives], ignore_index=True)
    #     data.to_json(CUMULATIVE_DATA_PATH, orient="records")
    #     print(Fore.GREEN + f"Augmented the dataset with {len(augmented_false_negatives)} synthetic anomalies." + Style.RESET_ALL)

    # Save the model and preprocessors
    dump(model, "ml/anomaly_model.pkl")
    dump(encoders, "ml/encoders.pkl")
    dump(scaler, "ml/scaler.pkl")
    print(Fore.GREEN + "Model saved successfully." + Style.RESET_ALL)

if __name__ == "__main__":
    train_model()
