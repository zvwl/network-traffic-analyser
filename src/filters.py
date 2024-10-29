import os
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style
from src.utils import loading_spinner, get_keypress

# Global filter variables
selected_protocols = {"tcp": False, "udp": False, "icmp": False}
selected_port = None

def capture_filtered_traffic():
    global selected_protocols, selected_port

    # Build filter expression based on user selection
    filter_expr = []
    for protocol, selected in selected_protocols.items():
        if selected:
            filter_expr.append(protocol)

    if selected_port:
        filter_expr.append(f"port {selected_port}")

    # Modify the filter expression to use 'or' between protocols, as a packet cannot be both TCP and UDP
    filter_str = " or ".join(filter_expr) if filter_expr else None
    print(Fore.GREEN + f"Starting network traffic capture with filter: {filter_str}..." + Style.RESET_ALL)

    # Add loading spinner to simulate preparation for capturing
    loading_spinner("Preparing for packet capture", 3)  # Spinner for 3 seconds

    try:
        # Start packet capture with the modified filter
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

    options = ["TCP", "UDP", "ICMP", "Port"]
    current_selection = 0

    while True:
        os.system('clear')
        print(Fore.GREEN + "Set your filter options:\n" + Style.RESET_ALL)

        # Display the checklist dynamically
        for i, option in enumerate(options):
            if option == "Port":
                # Handle port input display
                port_display = selected_port if selected_port else "none"
                prefix = "-->" if current_selection == i else "   "
                print(Fore.GREEN + f"{prefix} Port: {port_display}" + Style.RESET_ALL)
            else:
                protocol = option.lower()
                selected = "x" if selected_protocols[protocol] else "none"
                prefix = "-->" if current_selection == i else "   "
                print(Fore.GREEN + f"{prefix} {option}: {selected}" + Style.RESET_ALL)

        key = get_keypress()

        if key == '\x1b[A':  # Up arrow key
            current_selection = (current_selection - 1) % len(options)
        elif key == '\x1b[B':  # Down arrow key
            current_selection = (current_selection + 1) % len(options)
        elif key == ' ':  # Space bar to toggle selection
            if current_selection == 3:
                # Port input selected
                selected_port = input("Enter port number (e.g., 80 for HTTP): ") or None
            else:
                protocol = options[current_selection].lower()
                selected_protocols[protocol] = not selected_protocols[protocol]
        elif key == '\n' or key == '\r':  # Enter key to confirm selection
            break

    print(Fore.GREEN + "Filter set successfully!" + Style.RESET_ALL)
