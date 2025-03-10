import sys
import termios
import tty
import time
import logging
import pandas as pd

from scapy.all import IP
from colorama import Fore, Style

from ml.model_loader import model_loader
from ml.preprocess import preprocess_data

def detect_anomalies(packet_data):
    """Detect anomalies in packet data using ML model"""
    if not model_loader.model:
        if not model_loader.load_model():
            return [0] * len(packet_data)
    
    # Ensure data is a DataFrame
    if not isinstance(packet_data, pd.DataFrame):
        try:
            packet_data = pd.DataFrame(packet_data)
        except:
            return [0] * len(packet_data)
            
    predictions, probabilities = model_loader.predict(packet_data, preprocess_data)
    
    if predictions is None:
        return [0] * len(packet_data)
    
    return predictions

def get_keypress():
    """Get a single keypress from the user"""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
        if ch == '\x1b':  # Escape char
            ch += sys.stdin.read(2)  # Read arrow keys
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def glowing_text(text, iterations=3):
    """Display glowing text effect"""
    for i in range(iterations):
        print(Fore.GREEN + text + Style.RESET_ALL, end='\r')
        time.sleep(0.3)
        print(Fore.LIGHTGREEN_EX + text + Style.RESET_ALL, end='\r')
        time.sleep(0.3)
    print()