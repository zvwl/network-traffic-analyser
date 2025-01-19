import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler

def preprocess_data(data, encoders=None, scaler=None, is_training=True):
    data = data.copy()

    # Handle missing values and ensure proper data types
    for col in data.columns:
        if col in ["src_ip", "dst_ip", "protocol"]:  # Categorical columns
            data[col] = data[col].fillna("unknown").astype(str)
        elif col == "timestamp":  # Numeric column
            data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0)
        else:  # All other columns
            data[col] = data[col].fillna(0)

    # Encode categorical columns
    if "src_ip" in data.columns:
        if encoders is None or "src_ip" not in encoders:
            le_src = LabelEncoder()
            data["src_ip"] = le_src.fit_transform(data["src_ip"])
            if encoders is not None:
                encoders["src_ip"] = le_src
        else:
            le_src = encoders["src_ip"]
            data["src_ip"] = le_src.transform(data["src_ip"])

    if "dst_ip" in data.columns:
        if encoders is None or "dst_ip" not in encoders:
            le_dst = LabelEncoder()
            data["dst_ip"] = le_dst.fit_transform(data["dst_ip"])
            if encoders is not None:
                encoders["dst_ip"] = le_dst
        else:
            le_dst = encoders["dst_ip"]
            data["dst_ip"] = le_dst.transform(data["dst_ip"])

    if "protocol" in data.columns:
        if encoders is None or "protocol" not in encoders:
            le_protocol = LabelEncoder()
            data["protocol"] = le_protocol.fit_transform(data["protocol"])
            if encoders is not None:
                encoders["protocol"] = le_protocol
        else:
            le_protocol = encoders["protocol"]
            data["protocol"] = le_protocol.transform(data["protocol"])

    # Add total_traffic feature
    if "length" in data.columns and "src_ip" in data.columns:
        data["total_traffic"] = data.groupby("src_ip")["length"].transform("sum")

    # Drop irrelevant columns
    irrelevant_columns = ["info", "anomaly"]  # Add more irrelevant columns if necessary
    data = data.drop(columns=irrelevant_columns, errors="ignore")

    # Scale numeric columns
    numeric_columns = data.select_dtypes(include=[np.number]).columns
    if not scaler:
        scaler = MinMaxScaler()
        data[numeric_columns] = scaler.fit_transform(data[numeric_columns])
    else:
        data[numeric_columns] = scaler.transform(data[numeric_columns])

    return data, encoders, scaler
