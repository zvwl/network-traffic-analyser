import os
from colorama import Fore, Style
import time
from src.utils import get_keypress
from src.filters import capture_filtered_traffic, set_filter
from src.utils import detect_anomalies
import sys
import logging 


# Add the project root to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(project_root)

# Global variable for capture file path
CAPTURE_FILE_PATH = "traffic_capture.json"

def display_ascii_art(art):
    """Display ASCII art in the terminal."""
    print(Fore.GREEN + art + Style.RESET_ALL)

def terminal_ui(train_model_callback=None, validate_data_callback=None, shared_state=None):
    if shared_state is None:
        shared_state = {"auto_training_enabled": True}
        
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

         # Arrow key navigation
        if key == "\x1b[A":
            current_selection = (current_selection - 1) % len(options)
        elif key == "\x1b[B":
            current_selection = (current_selection + 1) % len(options)
        elif key in ("\n", "\r"):  # Enter key
            if current_selection == 0:
                print(Fore.GREEN + "Starting Network Traffic Analysis..." + Style.RESET_ALL)
                capture_filtered_traffic()

                # Trigger training only if enabled
                if shared_state["auto_training_enabled"] and validate_data_callback and train_model_callback:
                    if validate_data_callback(CAPTURE_FILE_PATH):
                        train_model_callback()
                    else:
                        print(Fore.RED + "Capture data validation failed. Skipping training." + Style.RESET_ALL)

            elif current_selection == 1:
                print(Fore.GREEN + "Setting filters..." + Style.RESET_ALL)
                set_filter()

            elif current_selection == 2:
                # Toggle the shared state
                shared_state["auto_training_enabled"] = not shared_state["auto_training_enabled"]
                state = "enabled" if shared_state["auto_training_enabled"] else "disabled"
                logging.info(f"User set automatic training to {state}.")
                print(Fore.CYAN + f"Automatic Training {state.capitalize()}!" + Style.RESET_ALL)
                time.sleep(1)

            elif current_selection == 3:  # Exit option
                print(Fore.GREEN + "Exiting the program..." + Style.RESET_ALL)
                from main import exit_program
                exit_program()

def display_traffic(traffic_data):
    """Display traffic packets with anomaly detection."""
    anomalies = detect_anomalies(traffic_data)
    for idx, packet in enumerate(traffic_data):
        if anomalies[idx]:
            print(f"ANOMALY DETECTED: {packet}")
        else:
            print(f"Normal Packet: {packet}")
