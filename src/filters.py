import os
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style
from src.utils import loading_spinner, get_keypress

# Global filter variables
selected_protocols = {"tcp": False, "udp": False, "icmp": False}
selected_port = None

# ASCII Art Title
def display_ascii_art():
    art = """
███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
    """
    print(Fore.MAGENTA + art + Style.RESET_ALL)

# Function to capture filtered network traffic
def capture_filtered_traffic():
    global selected_protocols, selected_port

    # Build filter expression based on user selection
    filter_expr = []
    for protocol, selected in selected_protocols.items():
        if selected:
            filter_expr.append(protocol)

    if selected_port:
        filter_expr.append(f"port {selected_port}")

    filter_str = " or ".join(filter_expr) if filter_expr else None
    print(Fore.GREEN + f"Starting network traffic capture with filter: {filter_str}..." + Style.RESET_ALL)

    # Add loading spinner to simulate preparation for capturing
    loading_spinner("Preparing for packet capture", 3)

    try:
        sniff(filter=filter_str, prn=packet_callback, count=0)
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[+] Stopping packet capture..." + Style.RESET_ALL)


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

# Function to display dynamic checklist for filter selection
def set_filter():
    global selected_protocols, selected_port

    options = ["TCP", "UDP", "ICMP", "Port", "Back"]
    current_selection = 0

    while True:
        os.system('clear')
        display_ascii_art()  # Display ASCII art on filter settings page
        print(Fore.GREEN + "Set your filter options:\n" + Style.RESET_ALL)

        # Display the checklist dynamically
        for i, option in enumerate(options):
            if option == "Port":
                # Handle port input display
                port_display = selected_port if selected_port else "❌"
                prefix = "-->" if current_selection == i else "   "
                color = Fore.YELLOW if current_selection == i else Fore.GREEN
                print(color + f"{prefix} Port: {port_display}" + Style.RESET_ALL)
            elif option == "Back":
                # Display "Back" option at the end
                prefix = "-->" if current_selection == i else "   "
                color = Fore.YELLOW if current_selection == i else Fore.GREEN
                print(color + f"{prefix} {option}" + Style.RESET_ALL)
            else:
                protocol = option.lower()
                selected = "✅" if selected_protocols[protocol] else "❌"
                prefix = "-->" if current_selection == i else "   "
                color = Fore.YELLOW if current_selection == i else Fore.GREEN
                print(color + f"{prefix} {option}: {selected}" + Style.RESET_ALL)

        key = get_keypress()

        if key == '\x1b[A':  # Up arrow key
            current_selection = (current_selection - 1) % len(options)
        elif key == '\x1b[B':  # Down arrow key
            current_selection = (current_selection + 1) % len(options)
        elif key == '\n' or key == '\r':  # Enter key to toggle selection or go back
            if current_selection == len(options) - 1:  # Last option is "Back"
                return
            elif current_selection == 3:  # Port input selected
                selected_port = input(Fore.GREEN + "Enter port number (e.g., 80 for HTTP): " + Style.RESET_ALL) or None
            else:  # Toggle TCP, UDP, or ICMP
                protocol = options[current_selection].lower()
                selected_protocols[protocol] = not selected_protocols[protocol]

# Terminal UI with main menu navigation
def terminal_ui():
    options = ["Start Network Traffic Analysis", "Set Filter", "Exit"]
    current_selection = 0

    while True:
        os.system('clear')
        display_ascii_art()
        print(Fore.GREEN + "Welcome to the Network Traffic Analyser!\n" + Style.RESET_ALL)

        # Display the menu with the current selection highlighted
        for i, option in enumerate(options):
            color = Fore.YELLOW if i == current_selection else Fore.GREEN
            prefix = "-->" if i == current_selection else "   "
            print(color + f"{prefix} {option}" + Style.RESET_ALL)

        key = get_keypress()

        # Arrow key navigation
        if key == '\x1b[A':  # Up arrow key
            current_selection = (current_selection - 1) % len(options)
        elif key == '\x1b[B':  # Down arrow key
            current_selection = (current_selection + 1) % len(options)
        elif key == '\n' or key == '\r':  # Enter key to select option
            if current_selection == 0:
                capture_filtered_traffic()
            elif current_selection == 1:
                set_filter()  # Go to filter settings
            elif current_selection == 2:
                print(Fore.GREEN + "Exiting the program. Goodbye!" + Style.RESET_ALL)
                break
