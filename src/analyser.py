import sys
import os

# Add the root directory of your project to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.ui import display_ascii_art, terminal_ui
from src.utils import glowing_text


if __name__ == "__main__":
    # Example use before showing menu options
    glowing_text("Loading Network Traffic Analyzer...", 1)
    terminal_ui()