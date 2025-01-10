import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.preprocess import preprocess_data
import pandas as pd
from sklearn.metrics import classification_report
from joblib import load

# Load model and preprocessing artifacts
model = load("ml/anomaly_model.pkl")
encoders = load("ml/encoders.pkl")
scaler = load("ml/scaler.pkl")

def log_predictions(dataset, predictions, filename):
    dataset["predictions"] = predictions
    dataset.to_csv(filename, index=False)
    print(f"Predictions saved to {filename}")

def test_controlled_data():
    test_data = pd.DataFrame([
        {"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "protocol": "TCP", "length": 500, "info": "Normal traffic"},
        {"src_ip": "10.0.0.1", "dst_ip": "224.0.0.1", "protocol": "UDP", "length": 2000, "info": "Potential attack"},
        {"src_ip": "unknown", "dst_ip": "192.168.1.255", "protocol": "ICMP", "length": 1500, "info": "Edge case"}
    ])

    X_test, _, _ = preprocess_data(test_data, encoders, scaler)
    predictions = model.predict(X_test)

    # Log predictions
    log_predictions(test_data, predictions, "controlled_test_predictions.csv")

    print("\n=== Controlled Test Predictions ===")
    print(test_data)

def evaluate_real_data():
    real_data = pd.read_json("traffic_capture.json")
    X_real, _, _ = preprocess_data(real_data.drop(columns=["is_anomalous"], errors="ignore"), encoders, scaler)
    predictions = model.predict(X_real)

    # Log predictions
    log_predictions(real_data, predictions, "real_data_predictions.csv")

    if "is_anomalous" in real_data.columns:
        y_true = real_data["is_anomalous"].values
        print("\n=== Real Data Metrics ===")
        print(classification_report(y_true, predictions))

    print("\n=== Real Data Predictions ===")
    print(real_data[["src_ip", "dst_ip", "protocol", "length", "is_anomalous", "predictions"]].head())

if __name__ == "__main__":
    test_controlled_data()
    evaluate_real_data()
