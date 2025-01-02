import os
from art import text2art
from colorama import Fore, Style
from src.utils import get_keypress, glowing_text, loading_spinner
from src.filters import capture_filtered_traffic, set_filter


def display_ascii_art(art):
    print(Fore.GREEN + art + Style.RESET_ALL)

# Terminal UI with arrow navigation
def terminal_ui():
    options = ["Start Network Traffic Analysis", "Set Filter", "Exit"]
    current_selection = 0

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
        os.system('clear')  # Clear the terminal for a fresh UI display
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
        if key == '\x1b[A':  # Up arrow key
            current_selection = (current_selection - 1) % len(options)
        elif key == '\x1b[B':  # Down arrow key
            current_selection = (current_selection + 1) % len(options)
        elif key == '\n' or key == '\r':  # Enter key or carriage return
            # Do action based on the selected option
            if current_selection == 0:
                # Start packet capture with spinner before it starts
                capture_filtered_traffic()
            elif current_selection == 1:
                # Set filters
                set_filter()
            elif current_selection == 2:
                print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
                break
