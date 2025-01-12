import sys
import os
import signal
import logging
import subprocess
import pandas as pd
from joblib import load

# Add the project root and subdirectories to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(project_root)  # Add project root to sys.path
sys.path.append(os.path.join(project_root, "src"))
sys.path.append(os.path.join(project_root, "ml"))

# Import modules after updating sys.path
from ml.preprocess import preprocess_data
from src.utils import glowing_text, detect_anomalies
from src.ui import display_ascii_art, terminal_ui

# Global capturing state
capturing = True
CAPTURE_FILE_PATH = "traffic_capture.json"

# Load the model and preprocessors
model = load("ml/anomaly_model.pkl")
encoders = load("ml/encoders.pkl")
scaler = load("ml/scaler.pkl")

def detect_anomalies(packet_data):
    """Detect anomalies in the provided packet data."""
    X, _, _ = preprocess_data(packet_data, encoders, scaler)
    predictions = model.predict(X)
    return predictions

def validate_capture_data(file_path):
    """Validate the captured traffic data before training."""
    try:
        data = pd.read_json(file_path)
        if data.empty:
            logging.warning("Captured traffic data is empty. Skipping model training.")
            return False
        logging.info(f"Validated {len(data)} records in the capture file.")
        return True
    except Exception as e:
        logging.error(f"Failed to validate capture data: {e}")
        return False

def train_model_on_capture_stop():
    """Trigger model training after traffic capture stops."""
    logging.info("Training the anomaly detection model...")
    try:
        subprocess.run(["python", "ml/train_model.py"], check=True)
        logging.info("Model training completed successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Model training failed: {e}")

def stop_capture(sig, frame):
    """Handle signal to stop traffic capture."""
    global capturing
    capturing = False
    logging.info("Capture stopped by user.")

    # Save packets before validation
    from src.filters import save_captured_packets
    save_captured_packets()

    # Validate and trigger model training
    if validate_capture_data(CAPTURE_FILE_PATH):
        train_model_on_capture_stop()
    else:
        logging.warning("Skipped training due to validation issues.")

    # Prompt the user to press Enter before returning to the main menu
    input("\nCapture stopped. Press Enter to return to the main menu...")

    # Return to the main terminal UI
    terminal_ui(train_model_on_capture_stop, validate_capture_data)


# Set signal handler for SIGINT
signal.signal(signal.SIGINT, stop_capture)

if __name__ == "__main__":
    glowing_text("Loading Network Traffic Analyser...", 1)
    terminal_ui(train_model_on_capture_stop, validate_capture_data)
