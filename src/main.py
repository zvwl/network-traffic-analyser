import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.preprocess import preprocess_data
import signal
import logging

from joblib import load

from src.utils import glowing_text
from src.utils import detect_anomalies
from src.ui import display_ascii_art, terminal_ui



sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

model = load("ml/anomaly_model.pkl")
encoders = load("ml/encoders.pkl")
scaler = load("ml/scaler.pkl")

def detect_anomalies(packet_data):
    X, _, _ = preprocess_data(packet_data, encoders, scaler)
    predictions = model.predict(X)
    return predictions

if __name__ == "__main__":
    glowing_text("Loading Network Traffic Analyser...", 1)
    terminal_ui()
    
def stop_capture(sig, frame):
    global capturing
    capturing = False
    logging.info("Capture stopped by user. Returning to main menu...")
    sys.exit(0)

signal.signal(signal.SIGINT, stop_capture)