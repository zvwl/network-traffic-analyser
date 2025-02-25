import sys
import os
import signal
import logging
import subprocess
import pandas as pd
import functools
import time
from colorama import Fore, Style
from joblib import load
# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


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
        subprocess.run(["python3", "ml/train_model.py"], check=True)
        logging.info("Model training completed successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Model training failed: {e}")

def stop_capture(sig, frame, shared_state):
    global capturing
    capturing = False
    logging.info("Capture stopped by user.")

    # Access the shared state
    auto_training_enabled = shared_state["auto_training_enabled"]
    logging.info(f"Automatic training is {'enabled' if auto_training_enabled else 'disabled'}.")

    from src.filters import save_captured_packets
    save_captured_packets()

    # Only trigger training if auto_training_enabled is True
    if auto_training_enabled:
        if validate_capture_data(CAPTURE_FILE_PATH):
            train_model_on_capture_stop()
        else:
            logging.warning("Skipped training due to validation issues.")
    else:
        logging.info("Automatic training is disabled. Skipping training.")

    input("\nCapture stopped. Press Enter to return to the main menu...")
    terminal_ui(train_model_on_capture_stop, validate_capture_data, shared_state)

def exit_program():
    """Properly shut down all processes and exit."""
    print(Fore.GREEN + "Shutting down all processes..." + Style.RESET_ALL)
    
    # Import and stop any capture processes
    from src.filters import stop_capture_process
    stop_capture_process()
    
    time.sleep(1)
    print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
    
    # Force exit to ensure all processes terminate
    os._exit(0)  # This is more reliable than sys.exit()

if __name__ == "__main__":
    glowing_text("Loading Network Traffic Analyser...", 1)

    # Use a shared state dictionary
    shared_state = {"auto_training_enabled": True}
    logging.info(f"Initial state of automatic training: {'enabled' if shared_state['auto_training_enabled'] else 'disabled'}.")

    # Pass the shared state to the signal handler
    signal.signal(signal.SIGINT, functools.partial(stop_capture, shared_state=shared_state))

    terminal_ui(train_model_on_capture_stop, validate_capture_data, shared_state)
