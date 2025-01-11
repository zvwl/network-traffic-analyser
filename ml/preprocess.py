import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

def preprocess_data(data, encoders=None, scaler=None, is_training=True):
    data = data.copy()

    # Explicitly handle missing values and ensure proper dtype
    for col in data.columns:
        if data[col].dtype == "object":
            data[col] = data[col].fillna("missing")
        else:
            data[col] = data[col].fillna(0).astype(float)
    
    # Ensure 'timestamp' is numeric and calculate inter-arrival times
    if "timestamp" in data.columns:
        data["timestamp"] = pd.to_numeric(data["timestamp"], errors="coerce").fillna(0)
        data["inter_arrival_time"] = data["timestamp"].diff().fillna(0)

    # Add the number of unique destination IPs per source IP
    if "src_ip" in data.columns and "dst_ip" in data.columns:
        data["unique_dst_ips"] = data.groupby("src_ip")["dst_ip"].transform("nunique")

    # Add traffic volume by source IP
    if "length" in data.columns:
        data["total_traffic"] = data.groupby("src_ip")["length"].transform("sum")

    # Add length-to-traffic ratio
    if "length" in data.columns and "total_traffic" in data.columns:
        data["length_to_traffic_ratio"] = data["length"] / (data["total_traffic"] + 1e-6)  # Avoid division by zero

    # Add rare combination flag for src-dst-protocol
    if "src_ip" in data.columns and "dst_ip" in data.columns and "protocol" in data.columns:
        data["src_dst_protocol"] = data["src_ip"].astype(str) + "_" + data["dst_ip"].astype(str) + "_" + data["protocol"].astype(str)
        
        # Encode src_dst_protocol into numeric format
        if encoders is None or "src_dst_protocol" not in encoders:
            le = LabelEncoder()
            data["src_dst_protocol"] = le.fit_transform(data["src_dst_protocol"])
            if encoders is not None:
                encoders["src_dst_protocol"] = le
        else:
            # Dynamically update encoder for src_dst_protocol
            le = encoders["src_dst_protocol"]
            unseen_labels = set(data["src_dst_protocol"].unique()) - set(le.classes_)
            if unseen_labels:
                le.classes_ = np.append(le.classes_, list(unseen_labels))
            data["src_dst_protocol"] = data["src_dst_protocol"].apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else le.transform(["unknown"])[0]
            )

    # Ensure required columns exist
    required_columns = ["src_ip", "dst_ip", "protocol", "length"]
    for col in required_columns:
        if col not in data.columns:
            raise ValueError(f"Missing required column: {col}")

    # Ensure categorical columns are strings before encoding
    categorical_columns = ["src_ip", "dst_ip", "protocol", "src_dst_protocol"]
    for col in categorical_columns:
        if col in data.columns:
            data[col] = data[col].astype(str)

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
            data[col] = data[col].apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else le.transform(["unknown"])[0]
            )

    # Normalize numerical values
    if not scaler:
        scaler = MinMaxScaler()
        data["length"] = scaler.fit_transform(data[["length"]])
    else:
        data["length"] = scaler.transform(data[["length"]])

    # Select features for training
    X = data.drop(columns=["info", "is_anomalous"], errors="ignore")
    return X, encoders, scaler
