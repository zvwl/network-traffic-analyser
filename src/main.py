import sys
import os
import signal
import logging
import subprocess
import pandas as pd
import functools
import time
from colorama import Fore, Style

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Add project paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(project_root)
sys.path.append(os.path.join(project_root, "src"))
sys.path.append(os.path.join(project_root, "ml"))

# Import modules
from ml.preprocess import preprocess_data
from src.utils import glowing_text, detect_anomalies
from src.ui import display_ascii_art, terminal_ui
from ml.model_loader import model_loader

# Global vars
capturing = True
CAPTURE_FILE_PATH = "traffic_capture.csv"
TRAIN_DATA_PATH = "Train_data.csv"
TEST_DATA_PATH = "Test_data.csv"

# Initialize model
if not model_loader.load_model():
    logging.warning("Failed to load model, will attempt to create one")
    if not os.path.exists("ml"):
        os.makedirs("ml")
        
    if not os.path.exists("ml/anomaly_model.pkl"):
        try:
            subprocess.run(["python3", "ml/train_model.py"], check=True)
            logging.info("Initial model training completed")
            model_loader.load_model()
        except Exception as train_error:
            logging.error(f"Initial training failed: {train_error}")

def detect_anomalies(packet_data):
    """Detect anomalies in the provided packet data"""
    if not model_loader.model:
        if not model_loader.load_model():
            return [0] * len(packet_data)
            
    predictions, _ = model_loader.predict(packet_data, preprocess_data)
    
    if predictions is None:
        return [0] * len(packet_data)
    
    return predictions

def validate_capture_data(file_path):
    """Validate the captured traffic data"""
    try:
        data = pd.read_csv(file_path)
        return not data.empty
    except Exception as e:
        logging.error(f"Failed to validate capture data: {e}")
        return False

def train_model_on_capture_stop():
    """Train model using NSL-KDD dataset"""
    try:    
        # Always use NSL-KDD dataset if available
        if os.path.exists(TRAIN_DATA_PATH):
            print(Fore.GREEN + f"Training model with NSL-KDD dataset: {TRAIN_DATA_PATH}" + Style.RESET_ALL)
            from ml.train_model import train_model
            train_model(TRAIN_DATA_PATH, TEST_DATA_PATH if os.path.exists(TEST_DATA_PATH) else None)
        else:
            print(Fore.YELLOW + f"Warning: {TRAIN_DATA_PATH} not found. Please download the NSL-KDD dataset." + Style.RESET_ALL)
            print(Fore.YELLOW + "The model cannot be trained without proper training data." + Style.RESET_ALL)
                
    except Exception as e:
        logging.error(f"Model training failed: {e}")
        print(Fore.RED + f"Model training error: {e}" + Style.RESET_ALL)

def stop_capture(sig, frame, shared_state):
    global capturing
    capturing = False
    logging.info("Capture stopped by user")

    # Access shared state
    auto_training_enabled = shared_state["auto_training_enabled"]
    
    from src.filters import save_captured_packets
    save_captured_packets()

    # Only train if enabled and NSL-KDD dataset exists
    if auto_training_enabled and os.path.exists(TRAIN_DATA_PATH):
        train_model_on_capture_stop()
    elif auto_training_enabled:
        print(Fore.YELLOW + f"Training skipped: {TRAIN_DATA_PATH} not found" + Style.RESET_ALL)

    input(Fore.YELLOW + "Press Enter to return to the main menu..." + Style.RESET_ALL)
    terminal_ui(train_model_on_capture_stop, validate_capture_data, shared_state)

def exit_program():
    """Shut down and exit"""
    print(Fore.GREEN + "Shutting down processes..." + Style.RESET_ALL)
    
    from src.filters import stop_capture_process
    stop_capture_process()
    
    time.sleep(1)
    print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
    os._exit(0)  

if __name__ == "__main__":
    glowing_text("Loading Network Traffic Analyser...", 1)

    # Use shared state dictionary
    shared_state = {"auto_training_enabled": True}

    # Set up signal handler
    signal.signal(signal.SIGINT, functools.partial(stop_capture, shared_state=shared_state))

    terminal_ui(train_model_on_capture_stop, validate_capture_data, shared_state)