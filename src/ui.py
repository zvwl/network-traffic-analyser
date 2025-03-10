import os
from colorama import Fore, Style
import time
from src.utils import get_keypress
from src.filters import capture_filtered_traffic, set_filter
from src.utils import detect_anomalies
import sys
import logging 

# Add project root to path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(project_root)

# Capture file path
CAPTURE_FILE_PATH = "traffic_capture.csv"

def display_ascii_art(art):
    """Display ASCII art in the terminal"""
    print(Fore.GREEN + art + Style.RESET_ALL)

def terminal_ui(train_model_callback=None, validate_data_callback=None, shared_state=None):
    if shared_state is None:
        shared_state = {"auto_training_enabled": True}
        
    options = [
        "Start Network Traffic Analysis",
        "Set Filter",
        "Enable/Disable Automatic Training",
        "Exit",
    ]
    current_selection = 0

    # ASCII art banner
    custom_art = """
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
                                                                                            
    """

    while True:
        os.system("clear")
        display_ascii_art(custom_art)
        print(Fore.GREEN + "Welcome to the Network Traffic Analyser!\n" + Style.RESET_ALL)

        # Show training status
        training_status = "ENABLED" if shared_state["auto_training_enabled"] else "DISABLED"
        print(Fore.CYAN + f"Automatic Training: {training_status}\n" + Style.RESET_ALL)

        # Display menu
        for i, option in enumerate(options):
            if i == current_selection:
                print(Fore.YELLOW + f"--> {option}" + Style.RESET_ALL) 
            else:
                print(Fore.GREEN + f"    {option}" + Style.RESET_ALL)

        key = get_keypress()

        # Menu navigation
        if key == "\x1b[A":  # Up arrow
            current_selection = (current_selection - 1) % len(options)
        elif key == "\x1b[B":  # Down arrow
            current_selection = (current_selection + 1) % len(options)
        elif key in ("\n", "\r"):  # Enter key
            if current_selection == 0:  # Start Analysis
                print(Fore.GREEN + "Starting Network Traffic Analysis..." + Style.RESET_ALL)
                capture_filtered_traffic()

                # Train if enabled
                if shared_state["auto_training_enabled"] and validate_data_callback and train_model_callback:
                    if validate_data_callback(CAPTURE_FILE_PATH):
                        train_model_callback()
                
                input(Fore.YELLOW + "Press Enter to return to main menu..." + Style.RESET_ALL)

            elif current_selection == 1:  # Set Filter
                set_filter()

            elif current_selection == 2:  # Toggle Training
                shared_state["auto_training_enabled"] = not shared_state["auto_training_enabled"]
                state = "enabled" if shared_state["auto_training_enabled"] else "disabled"
                print(Fore.CYAN + f"Automatic Training {state.capitalize()}" + Style.RESET_ALL)
                time.sleep(1)
                
            elif current_selection == 3:  # Exit
                print(Fore.GREEN + "Exiting program..." + Style.RESET_ALL)
                from main import exit_program
                exit_program()



def display_traffic(traffic_data):
    """Display traffic packets with anomaly detection"""
    anomalies = detect_anomalies(traffic_data)
    for idx, packet in enumerate(traffic_data):
        if anomalies[idx]:
            print(f"ANOMALY DETECTED: {packet}")
        else:
            print(f"Normal Packet: {packet}")