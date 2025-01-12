import os
from art import text2art
from colorama import Fore, Style
import time
from src.utils import get_keypress, glowing_text, loading_spinner
from src.filters import capture_filtered_traffic, set_filter
from src.utils import detect_anomalies

# Global variable for capture file path
CAPTURE_FILE_PATH = "traffic_capture.json"

def display_ascii_art(art):
    """Display ASCII art in the terminal."""
    print(Fore.GREEN + art + Style.RESET_ALL)

def terminal_ui(train_model_callback=None, validate_data_callback=None):
    """Terminal UI for interacting with the program."""
    options = [
        "Start Network Traffic Analysis",
        "Set Filter",
        "Enable/Disable Automatic Training",
        "Exit",
    ]
    current_selection = 0
    auto_training_enabled = True  # Default: automatic training is enabled

    # Custom ASCII art
    custom_art = """
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                                                                                            
    """

    while True:
        os.system("clear")  # Clear the terminal for a fresh UI display
        display_ascii_art(custom_art)
        print(Fore.GREEN + "Welcome to the Network Traffic Analyser!\n" + Style.RESET_ALL)

        # Display the menu with the current selection highlighted with an arrow
        for i, option in enumerate(options):
            if i == current_selection:
                print(Fore.YELLOW + f"--> {option}" + Style.RESET_ALL)  # Highlight the current selection in yellow
            else:
                print(Fore.GREEN + f"    {option}" + Style.RESET_ALL)

        key = get_keypress()

        # Arrow key navigation: Up and Down arrow keys
        if key == "\x1b[A":  # Up arrow key
            current_selection = (current_selection - 1) % len(options)
        elif key == "\x1b[B":  # Down arrow key
            current_selection = (current_selection + 1) % len(options)
        elif key == "\n" or key == "\r":  # Enter key or carriage return
            # Perform action based on the selected option
            if current_selection == 0:
                print(Fore.GREEN + "Starting Network Traffic Analysis..." + Style.RESET_ALL)
                capture_filtered_traffic()

                # If auto-training is enabled, validate data and train the model
                if auto_training_enabled and validate_data_callback and train_model_callback:
                    if validate_data_callback(CAPTURE_FILE_PATH):
                        train_model_callback()
                    else:
                        print(Fore.RED + "Capture data validation failed. Skipping training." + Style.RESET_ALL)

            elif current_selection == 1:
                print(Fore.GREEN + "Setting filters..." + Style.RESET_ALL)
                set_filter()

            elif current_selection == 2:
                # Toggle auto-training
                auto_training_enabled = not auto_training_enabled
                state = "Enabled" if auto_training_enabled else "Disabled"
                print(Fore.CYAN + f"Automatic Training {state}!" + Style.RESET_ALL)
                time.sleep(1)

            elif current_selection == 3:
                print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
                break

def display_traffic(traffic_data):
    """Display traffic packets with anomaly detection."""
    anomalies = detect_anomalies(traffic_data)
    for idx, packet in enumerate(traffic_data):
        if anomalies[idx]:
            print(f"ANOMALY DETECTED: {packet}")
        else:
            print(f"Normal Packet: {packet}")
