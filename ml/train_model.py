from imblearn.over_sampling import SMOTE
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
from preprocess import preprocess_data
import os
from imblearn.over_sampling import ADASYN
from sklearn.model_selection import GridSearchCV



# Path to the cumulative dataset
CUMULATIVE_DATA_PATH = "traffic_cumulative.json"

def update_cumulative_data(new_data_path):
    """Updates the cumulative dataset with new data from new_data_path."""
    # Load the new data
    new_data = pd.read_json(new_data_path)

    # Load or initialize the cumulative dataset
    if os.path.exists(CUMULATIVE_DATA_PATH):
        cumulative_data = pd.read_json(CUMULATIVE_DATA_PATH)
        cumulative_data = pd.concat([cumulative_data, new_data], ignore_index=True)
    else:
        cumulative_data = new_data

    # Save the updated dataset
    cumulative_data.to_json(CUMULATIVE_DATA_PATH, orient="records")
    return cumulative_data




def train_model():
    # Load data
    data = update_cumulative_data("traffic_capture.json")

    # Ensure the target column is binary (True/False)
    if not all(data["is_anomalous"].isin([True, False])):
        print("Converting 'is_anomalous' to boolean type.")
        data["is_anomalous"] = data["is_anomalous"].astype(bool)

    X, y = data.drop(columns=["is_anomalous"]), data["is_anomalous"]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Preprocess the training data
    X_train, encoders, scaler = preprocess_data(X_train)

    # Check label distribution
    print("\n=== Label Distribution Before Balancing ===")
    print(y_train.value_counts())

    if y_train.value_counts().min() < 2:
        print("Too few samples in the minority class. Skipping SMOTE.")
        X_train_balanced, y_train_balanced = X_train, y_train
    else:
        # Use ADASYN for oversampling
        adasyn = ADASYN(random_state=42)
        X_train_balanced, y_train_balanced = adasyn.fit_resample(X_train, y_train)

        print("Balanced dataset:", pd.Series(y_train_balanced).value_counts())

    # Train the model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight={False: 1, True: 3},  # Penalize anomalies more
        random_state=42
    )   
    model.fit(X_train_balanced, y_train_balanced)

    # Evaluate the model on test data
    X_test, _, _ = preprocess_data(X_test, encoders, scaler)
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    # Log false negatives for analysis
    false_negatives = X_test[(y_test == True) & (y_pred == False)]
    false_negatives["actual"] = y_test[(y_test == True) & (y_pred == False)]
    print("False Negatives:")
    print(false_negatives)

    # Save the model and preprocessors
    dump(model, "ml/anomaly_model.pkl")
    dump(encoders, "ml/encoders.pkl")
    dump(scaler, "ml/scaler.pkl")
    
    


    # Define hyperparameter grid
    param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [10, 20],
        'min_samples_split': [2, 5],
        'class_weight': [{False: 1, True: 3}, "balanced"]
    }

    # Perform grid search
    grid_search = GridSearchCV(
        RandomForestClassifier(random_state=42),
        param_grid,
        scoring="recall",
        cv=3
    )
    grid_search.fit(X_train_balanced, y_train_balanced)

    # Use the best model from the grid search
    model = grid_search.best_estimator_
    print("Best parameters:", grid_search.best_params_)

if __name__ == "__main__":
    train_model()
