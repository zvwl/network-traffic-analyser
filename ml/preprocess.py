import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder

def preprocess_data(data, encoders=None, scaler=None, is_training=True):
    """Preprocess NSL-KDD dataset features for model training or inference"""
    data = data.copy()
    data = data.fillna(0)
    
    # Handle categorical features
    categorical_features = ['protocol_type', 'service', 'flag']
    if encoders is None:
        encoders = {}
    
    for feature in categorical_features:
        if feature in data.columns:
            if is_training or feature not in encoders:
                encoders[feature] = LabelEncoder()
                data[feature] = encoders[feature].fit_transform(data[feature].astype(str))
            else:
                # Handle unseen categories during inference
                data[feature] = data[feature].astype(str)
                unseen = np.setdiff1d(data[feature].unique(), encoders[feature].classes_)
                if len(unseen) > 0:
                    for val in unseen:
                        data.loc[data[feature] == val, feature] = encoders[feature].classes_[0]
                try:
                    data[feature] = encoders[feature].transform(data[feature])
                except:
                    data[feature] = 0
    
    # Scale numerical features
    numerical_features = [col for col in data.columns if col not in categorical_features 
                          and col != 'class' and col != 'anomaly']
    
    if scaler is None:
        scaler = StandardScaler()
        data[numerical_features] = scaler.fit_transform(data[numerical_features])
    else:
        try:
            data[numerical_features] = scaler.transform(data[numerical_features])
        except:
            for col in numerical_features:
                if col not in data.columns:
                    data[col] = 0
            data[numerical_features] = scaler.transform(data[numerical_features])
    
    # Ensure all data is numeric
    for col in data.columns:
        if data[col].dtype == 'object':
            data[col] = pd.to_numeric(data[col], errors='coerce').fillna(0)
    
    return data, encoders, scaler