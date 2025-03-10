import sys, os
import pandas as pd
from joblib import load
from colorama import Fore, Style, init

# Initialize colorama
init()

# Set up paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(project_root)
from ml.preprocess import preprocess_data

# Load model
model_path = os.path.join(project_root, "ml", "anomaly_model.pkl")
encoders_path = os.path.join(project_root, "ml", "encoders.pkl")
scaler_path = os.path.join(project_root, "ml", "scaler.pkl")
feature_names_path = os.path.join(project_root, "ml", "feature_names.txt")

try:
    model = load(model_path)
    encoders = load(encoders_path)
    scaler = load(scaler_path)
    with open(feature_names_path, "r") as f:
        feature_names = [line.strip() for line in f]
    print(Fore.GREEN + "Models loaded successfully!" + Style.RESET_ALL)
except Exception as e:
    print(Fore.RED + f"Error loading model: {e}" + Style.RESET_ALL)
    sys.exit(1)

# Test samples
test_samples = [
    # Normal traffic
    {
        'attack_type': 'Normal Traffic',
        'protocol_type': 'tcp', 'service': 'http', 'flag': 'SF',
        'src_bytes': 230, 'dst_bytes': 8750, 'wrong_fragment': 0,
        'urgent': 0, 'count': 1, 'srv_count': 1,
        'serror_rate': 0, 'srv_serror_rate': 0, 'rerror_rate': 0,
        'srv_rerror_rate': 0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'dst_host_count': 10, 'dst_host_srv_count': 8
    },
    # Ping Flood attack
    {
        'attack_type': 'Ping Flood',
        'protocol_type': 'icmp', 'service': 'ecr_i', 'flag': 'SF',
        'src_bytes': 64, 'dst_bytes': 64, 'wrong_fragment': 0,
        'urgent': 0, 'count': 500,  # Increased from 300
        'srv_count': 500,  # Increased from 300
        'serror_rate': 0.0, 
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0,
        'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': 1,
        'dst_host_srv_count': 1,
        'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 1.0,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    },
    # Port scan
    {
        'attack_type': 'Port Scan',
        'protocol_type': 'tcp', 'service': 'private', 'flag': 'S0',
        'src_bytes': 0, 'dst_bytes': 0, 'wrong_fragment': 0,
        'urgent': 0, 'count': 25, 'srv_count': 1,
        'serror_rate': 1.0, 'srv_serror_rate': 1.0, 'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0, 'same_srv_rate': 0.05, 'diff_srv_rate': 0.95,
        'dst_host_count': 1, 'dst_host_srv_count': 1
    },
    # Malformed packet
    {
        'attack_type': 'Malformed Packet',
        'protocol_type': 'tcp', 'service': 'private', 'flag': 'OTH',
        'src_bytes': 1024, 'dst_bytes': 0, 'wrong_fragment': 1,
        'urgent': 1, 'count': 5, 'srv_count': 5,
        'serror_rate': 0.0, 'srv_serror_rate': 0.0, 'rerror_rate': 1.0,
        'srv_rerror_rate': 1.0, 'same_srv_rate': 1.0, 'diff_srv_rate': 0.0,
        'dst_host_count': 5, 'dst_host_srv_count': 5
    }
]

# Run tests
results = []
print(Fore.CYAN + "\nTesting attack patterns..." + Style.RESET_ALL)

for sample in test_samples:
    # Prepare DataFrame
    df = pd.DataFrame(columns=feature_names)
    row = {col: sample.get(col, 0) for col in feature_names}
    test_df = pd.DataFrame([row])
    
    # Make prediction
    try:
        X, _, _ = preprocess_data(test_df, encoders, scaler, is_training=False)
        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]
        
        results.append({
            'attack_type': sample['attack_type'],
            'is_anomaly': bool(prediction),
            'confidence': max(probabilities) * 100,
            'anomaly_probability': probabilities[1]
        })
    except Exception as e:
        print(f"Error testing {sample['attack_type']}: {e}")

# Print results
print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
print(f"{Fore.YELLOW}             DETECTION RESULTS SUMMARY             {Style.RESET_ALL}")
print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
print(f"{'Attack Type':<20} | {'Result':<10} | {'Confidence':<10} | {'Probability':<10}")
print("-" * 60)

correct_count = 0
for result in results:
    attack_type = result['attack_type']
    is_anomaly = result['is_anomaly']
    expected_anomaly = attack_type != "Normal Traffic"
    correct = (is_anomaly == expected_anomaly)
    
    if correct:
        correct_count += 1
    
    # Format status
    if is_anomaly:
        status = f"{Fore.GREEN}DETECTED{Style.RESET_ALL}" if expected_anomaly else f"{Fore.RED}FALSE+{Style.RESET_ALL}"
    else:
        status = f"{Fore.GREEN}NORMAL  {Style.RESET_ALL}" if not expected_anomaly else f"{Fore.RED}MISSED  {Style.RESET_ALL}"
    
    print(f"{attack_type:<20} | {status:<10}   | {result['confidence']:<10.1f}%| {result['anomaly_probability']:<10.3f}")

print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
print(f"{Fore.GREEN}Accuracy: {correct_count/len(results)*100:.1f}%{Style.RESET_ALL}")