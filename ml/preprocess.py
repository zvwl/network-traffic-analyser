import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

def preprocess_data(data, encoders=None, scaler=None, is_training=True):
    data = data.copy()
    data.fillna("missing", inplace=True)
    # Add inter-arrival times (if timestamp is available)
    if "timestamp" in data.columns:
        data["inter_arrival_time"] = data["timestamp"].diff().fillna(0)

    # Add the number of unique destination IPs per source IP
    if "src_ip" in data.columns and "dst_ip" in data.columns:
        data["unique_dst_ips"] = data.groupby("src_ip")["dst_ip"].transform("nunique")

    # Add traffic volume by source IP
    if "length" in data.columns:
        data["total_traffic"] = data.groupby("src_ip")["length"].transform("sum")


    # Ensure required columns exist
    required_columns = ["src_ip", "dst_ip", "protocol", "length"]
    for col in required_columns:
        if col not in data.columns:
            raise ValueError(f"Missing required column: {col}")

    # Encode categorical variables
    if not encoders:
        encoders = {}
        for col in ["src_ip", "dst_ip", "protocol"]:
            le = LabelEncoder()
            data[col] = le.fit_transform(data[col])
            encoders[col] = le
    else:
        # Dynamically update encoder for unseen labels
        def update_encoder(encoder, new_labels):
            unseen_labels = set(new_labels) - set(encoder.classes_)
            if unseen_labels:
                encoder.classes_ = np.append(encoder.classes_, list(unseen_labels))

        for col, le in encoders.items():
            update_encoder(le, data[col].unique())
            data[col] = data[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else le.transform(["unknown"])[0])

    # Normalize numerical values
    if not scaler:
        scaler = MinMaxScaler()
        data["length"] = scaler.fit_transform(data[["length"]])
    else:
        data["length"] = scaler.transform(data[["length"]])

    # Select features for training
    X = data.drop(columns=["info", "is_anomalous"], errors="ignore")
    return X, encoders, scaler
