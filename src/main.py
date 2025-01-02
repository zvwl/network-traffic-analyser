import sys
import os
import signal
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ui import display_ascii_art, terminal_ui
from src.utils import glowing_text


if __name__ == "__main__":
    glowing_text("Loading Network Traffic Analyzer...", 1)
    terminal_ui()
    
def stop_capture(sig, frame):
    global capturing
    capturing = False
    logging.info("Capture stopped by user. Returning to main menu...")
    sys.exit(0)

signal.signal(signal.SIGINT, stop_capture)