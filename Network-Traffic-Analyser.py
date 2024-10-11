import os
import sys
import termios
import tty
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from art import text2art
from colorama import Fore, Style, init
import time

# Global filter variables
selected_protocols = {"tcp": False, "udp": False, "icmp": False}
selected_port = None

# Initialize colorama for colored output
init(autoreset=True)

# ASCII art for the UI in hacker green color
def display_ascii_art():
    art = text2art("Net Analyzer")
    print(Fore.GREEN + art + Style.RESET_ALL)

# Function to analyze each packet
def packet_callback(packet):
    if IP in packet:  # Check if the packet has an IP layer
        ip_layer = packet[IP]
        src_ip = ip_layer.src  # Source IP
        dst_ip = ip_layer.dst  # Destination IP

        # Check for TCP or UDP protocol
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"

        # Print out details of each packet in hacker green
        print(Fore.GREEN + f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}" + Style.RESET_ALL)

# Spinner function
def loading_spinner(text, duration=5):
    spinner = ['-', '\\', '|', '/']
    start_time = time.time()
    i = 0
    while time.time() - start_time < duration:
        sys.stdout.write(f"\r{text} {spinner[i % len(spinner)]}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    sys.stdout.write("\rDone!                                       \n")  # Move to a new line after spinner finishes

# Sniff function for traffic capture with filtering
def capture_filtered_traffic():
    global selected_protocols, selected_port

    # Build filter expression based on user selection
    filter_expr = []
    for protocol, selected in selected_protocols.items():
        if selected:
            filter_expr.append(protocol)

    if selected_port:
        filter_expr.append(f"port {selected_port}")

    filter_str = " and ".join(filter_expr) if filter_expr else None
    print(Fore.GREEN + f"Starting network traffic capture with filter: {filter_str}..." + Style.RESET_ALL)

    # Add loading spinner to simulate preparation for capturing
    loading_spinner("Preparing for packet capture", 3)  # Spinner for 3 seconds

    # Start packet capture with filter
    sniff(filter=filter_str, prn=packet_callback, count=0)

# Function to handle key inputs for arrow navigation and Enter key
def get_keypress():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
        if ch == '\x1b':  # Check if the first byte is an escape character
            ch += sys.stdin.read(2)  # Read two more bytes
        return ch
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

# Function to display dynamic checklist for filter selection
def set_filter():
    global selected_protocols, selected_port

    options = ["TCP", "UDP", "ICMP", "Port"]
    current_selection = 0
    port_input = False  # Flag for port input mode

    while True:
        os.system('clear')
        print(Fore.GREEN + "Set your filter options:\n" + Style.RESET_ALL)

        # Display the checklist dynamically
        for i, option in enumerate(options):
            if option == "Port":
                # Handle port input display
                port_display = selected_port if selected_port else "none"
                prefix = "-->" if current_selection == i else "   "
                print(f"{prefix} Port: {port_display}")
            else:
                protocol = option.lower()
                selected = "x" if selected_protocols[protocol] else "none"
                prefix = "-->" if current_selection == i else "   "
                print(f"{prefix} {option}: {selected}")

        # Get user input
        key = get_keypress()

        if key == '\x1b[A':  # Up arrow key
            current_selection = (current_selection - 1) % len(options)
        elif key == '\x1b[B':  # Down arrow key
            current_selection = (current_selection + 1) % len(options)
        elif key == ' ':  # Space bar to toggle selection
            if current_selection == 3:
                # Port input selected
                port_input = True
                selected_port = input("Enter port number (e.g., 80 for HTTP): ") or None
                port_input = False
            else:
                protocol = options[current_selection].lower()
                selected_protocols[protocol] = not selected_protocols[protocol]
        elif key == '\n' or key == '\r':  # Enter key to confirm selection
            break

    print(Fore.GREEN + "Filter set successfully!" + Style.RESET_ALL)
    time.sleep(2)

# Glowing text effect
def glowing_text(text, iterations=5):
    for i in range(iterations):
        # Display the text in normal green
        print(Fore.GREEN + text + Style.RESET_ALL, end='\r')
        time.sleep(0.5)
        # Display the text in brighter green
        print(Fore.LIGHTGREEN_EX + text + Style.RESET_ALL, end='\r')
        time.sleep(0.5)
    print()  # Add a newline after the glowing effect is done

# Example use before showing menu options
glowing_text("Loading Network Traffic Analyzer...", 1)

# Terminal UI with arrow navigation
def terminal_ui():
    options = ["Start Network Traffic Analysis", "Set Filter", "Exit"]
    current_selection = 0

    while True:
        os.system('clear')  # Clear the terminal for a fresh UI display
        display_ascii_art()
        print(Fore.GREEN + "Welcome to the Network Traffic Analyzer!\n" + Style.RESET_ALL)

        # Display the menu with the current selection highlighted with an arrow
        for i, option in enumerate(options):
            if i == current_selection:
                print(Fore.GREEN + f"--> {option}" + Style.RESET_ALL)  # Highlight the current selection in hacker green
            else:
                print(Fore.GREEN + f"    {option}" + Style.RESET_ALL)

        key = get_keypress()

        # Arrow key navigation: Up (Esc + [ + A), Down (Esc + [ + B)
        if key == '\x1b[A':  # Up arrow key
            current_selection = (current_selection - 1) % len(options)
        elif key == '\x1b[B':  # Down arrow key
            current_selection = (current_selection + 1) % len(options)
        elif key == '\n' or key == '\r':  # Enter key or carriage return
            # Perform action based on the selected option
            if current_selection == 0:
                # Start packet capture with spinner before it starts
                capture_filtered_traffic()
                break
            elif current_selection == 1:
                # Set filters
                set_filter()
            elif current_selection == 2:
                print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
                break

if __name__ == "__main__":
    terminal_ui()
