import os
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style
from src.utils import loading_spinner, get_keypress, get_duration_input, get_ip_input, get_packet_size_range

# Global filter variables
selected_protocols = {"tcp": False, "udp": False, "icmp": False}
selected_port = None
selected_duration = None
selected_ip = None  # Add global variable for IP address
selected_packet_size_range = None  # Add global variable for packet size range

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
    print(Fore.GREEN + art + Style.RESET_ALL)

# Function to capture filtered network traffic
def capture_filtered_traffic():
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range

    # Build filter expression based on user selection
    protocol_filters = []
    other_filters = []

    for protocol, selected in selected_protocols.items():
        if selected:
            protocol_filters.append(protocol)

    if selected_port:
        other_filters.append(f"port {selected_port}")
    if selected_ip:
        other_filters.append(f"host {selected_ip}")
    if selected_packet_size_range:
        min_size, max_size = selected_packet_size_range
        other_filters.append(f"greater {min_size} and less {max_size}")

    protocol_str = " or ".join(protocol_filters) if protocol_filters else None
    other_str = " and ".join(other_filters) if other_filters else None

    if protocol_str and other_str:
        filter_str = f"({protocol_str}) and {other_str}"
    else:
        filter_str = protocol_str or other_str

    print(Fore.GREEN + f"Starting network traffic capture for {selected_duration} seconds with filter: {filter_str}..." + Style.RESET_ALL)

    # Add loading spinner to simulate preparation for capturing
    loading_spinner("Preparing for packet capture", 3)

    try:
        sniff(filter=filter_str, prn=packet_callback, timeout=selected_duration)
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[+] Stopping packet capture..." + Style.RESET_ALL)
    finally:
        input(Fore.GREEN + "Press Enter to return to the main menu..." + Style.RESET_ALL)

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
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range

    options = ["TCP", "UDP", "ICMP", "Port", "Duration", "IP Address", "Packet Size Range", "Back"]
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
            elif option == "Duration":
                duration_display = f"{selected_duration} seconds" if selected_duration else "❌"
                prefix = "-->" if current_selection == i else "   "
                color = Fore.YELLOW if current_selection == i else Fore.GREEN
                print(color + f"{prefix} Duration: {duration_display}" + Style.RESET_ALL)
            elif option == "IP Address":
                ip_display = selected_ip if selected_ip else "❌"
                prefix = "-->" if current_selection == i else "   "
                color = Fore.YELLOW if current_selection == i else Fore.GREEN
                print(color + f"{prefix} IP Address: {ip_display}" + Style.RESET_ALL)
            elif option == "Packet Size Range":
                size_display = f"{selected_packet_size_range[0]}-{selected_packet_size_range[1]} bytes" if selected_packet_size_range else "❌"
                prefix = "-->" if current_selection == i else "   "
                color = Fore.YELLOW if current_selection == i else Fore.GREEN
                print(color + f"{prefix} Packet Size Range: {size_display}" + Style.RESET_ALL)
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
            elif current_selection == 4:  # Duration input selected
                selected_duration = get_duration_input()
            elif current_selection == 5:  # IP Address input selected
                selected_ip = get_ip_input()
            elif current_selection == 6:  # Packet Size Range input selected
                selected_packet_size_range = get_packet_size_range()
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
