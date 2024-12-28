import os
import json
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMPv6NDOptUnknown, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from colorama import Fore, Style
from src.utils import loading_spinner, get_keypress, get_duration_input, get_ip_input, get_packet_size_range
from src.utils import detect_anomaly
from datetime import datetime

# Global filter variables
selected_protocols = {"tcp": False, "udp": False, "icmp": False, "icmpv6": False, "mdns": False, "http": False, "ntp": False}
selected_port = None
selected_duration = None  # Default duration
selected_ip = None
selected_packet_size_range = None
enable_anomaly_detection = False
captured_packets = []  # Global list to store captured packets

# ASCII Art Title
def display_ascii_art():
    art = """
███████╗███╗   ██╗██╗███████╗███████╗███████╗███████╗    ████████╗ ██████╗  ██████╗ ██╗     
██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     
╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     
███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║       ██║   ╚██████╔╝╚██████╔╝███████╗
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
    """
    print(Fore.GREEN + art + Style.RESET_ALL)

# Function to capture filtered network traffic
def capture_filtered_traffic(output_pcap="traffic_capture.pcap", output_json="traffic_capture.json"):
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range, enable_anomaly_detection, captured_packets

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

    protocol_str = " or ".join(protocol_filters) if protocol_filters else ""
    other_str = " and ".join(other_filters) if other_filters else ""

    filter_str = " and ".join(filter for filter in [protocol_str, other_str] if filter)

    print(Fore.GREEN + f"Starting network traffic capture for {selected_duration} seconds with filter: {filter_str or 'None'}..." + Style.RESET_ALL)

    # Add loading spinner to simulate preparation for capturing
    loading_spinner("Preparing for packet capture", 3)

    try:
        # Capture traffic
        sniff(filter=filter_str, prn=packet_callback, timeout=selected_duration)
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[+] Stopping packet capture..." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Error: {e}" + Style.RESET_ALL)
    finally:
        # Save captured packets to PCAP
        print(Fore.GREEN + f"Saving captured traffic to {output_pcap}..." + Style.RESET_ALL)
        wrpcap(output_pcap, [pkt for pkt, _ in captured_packets])

        # Save captured packets to JSON
        print(Fore.GREEN + f"Saving captured traffic to {output_json}..." + Style.RESET_ALL)
        with open(output_json, "w") as json_file:
            json.dump([packet_to_dict(pkt_tuple) for pkt_tuple in captured_packets], json_file, indent=4)

        print(Fore.GREEN + "Traffic saved successfully!" + Style.RESET_ALL)
        input(Fore.GREEN + "Press Enter to return to the main menu..." + Style.RESET_ALL)


def packet_callback(packet):
    global captured_packets
    protocol = "Other"

    if IP in packet:
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
    elif ICMPv6NDOptUnknown in packet:
        protocol = "ICMPv6"
    elif DNS in packet:
        protocol = "MDNS"
    elif HTTPRequest in packet or HTTPResponse in packet:
        protocol = "HTTP"
    elif Raw in packet:  # Heuristic for NTP
        protocol = "NTP" if "ntp" in packet.summary().lower() else "Other"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src if IP in packet else "Unknown"
    dst_ip = packet[IP].dst if IP in packet else "Unknown"
    packet_length = len(packet)
    packet_info = packet.summary()

    print(Fore.GREEN + f"[+] {timestamp} | {src_ip} -> {dst_ip} | Protocol: {protocol} | Length: {packet_length} | Info: {packet_info}" + Style.RESET_ALL)

    is_anomalous = enable_anomaly_detection and detect_anomaly(packet)

    captured_packets.append((packet, is_anomalous))

    if is_anomalous:
        print(Fore.RED + "[!] Anomaly detected!" + Style.RESET_ALL)


def packet_to_dict(packet_tuple):
    """
    Convert a Scapy packet to a dictionary format suitable for JSON serialization,
    including anomaly information.
    """
    packet, is_anomalous = packet_tuple
    return {
        "src_ip": packet[IP].src if IP in packet else None,
        "dst_ip": packet[IP].dst if IP in packet else None,
        "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else \
                    "ICMPv6" if ICMPv6NDOptUnknown in packet else "MDNS" if DNS in packet else \
                    "HTTP" if HTTPRequest in packet or HTTPResponse in packet else "NTP" if Raw in packet and "ntp" in packet.summary().lower() else "Other",
        "size": len(packet),
        "info": str(packet.summary()),
        "anomalous": is_anomalous
    }




def set_filter():
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range, enable_anomaly_detection

    options = ["TCP", "UDP", "ICMP", "ICMPv6", "MDNS", "HTTP", "NTP", "Port", "Duration", "IP Address", "Packet Size Range", "Anomaly Detection"]
    current_selection = 0
    back_option_index = len(options)  # Index for the Back button

    while True:
        os.system('clear')
        display_ascii_art()
        print(Fore.GREEN + "Set your filter options:\n" + Style.RESET_ALL)

        # Display all filter options with their current states
        for i, option in enumerate(options):
            if option == "Port":
                display_value = selected_port if selected_port else "❌"
            elif option == "Duration":
                display_value = f"{selected_duration} seconds" if selected_duration else "❌"
            elif option == "IP Address":
                display_value = selected_ip if selected_ip else "❌"
            elif option == "Packet Size Range":
                if selected_packet_size_range:
                    display_value = f"{selected_packet_size_range[0]}-{selected_packet_size_range[1]} bytes"
                else:
                    display_value = "❌"
            elif option == "Anomaly Detection":
                display_value = "✅" if enable_anomaly_detection else "❌"
            else:  # Protocol options (TCP, UDP, ICMP, etc.)
                protocol = option.lower()
                display_value = "✅" if selected_protocols.get(protocol, False) else "❌"

            # Highlight the current selection
            color = Fore.YELLOW if current_selection == i else Fore.GREEN
            prefix = "-->" if current_selection == i else "   "
            print(color + f"{prefix} {option}: {display_value}" + Style.RESET_ALL)

        # Leave a few lines and display the Back button
        print("\n" * 2)  # Add spacing before Back button
        color = Fore.YELLOW if current_selection == back_option_index else Fore.GREEN
        prefix = "-->" if current_selection == back_option_index else "   "
        print(color + f"{prefix} Back" + Style.RESET_ALL)

        # Handle user input for navigation and selection
        key = get_keypress()

        if key == '\x1b[A':  # Up arrow key
            current_selection = (current_selection - 1) % (len(options) + 1)  # Wrap around
        elif key == '\x1b[B':  # Down arrow key
            current_selection = (current_selection + 1) % (len(options) + 1)  # Wrap around
        elif key in ['\r', '\n']:  # Enter key
            if current_selection == back_option_index:  # "Back" option
                return
            elif options[current_selection] == "Port":
                selected_port = input(Fore.GREEN + "Enter port number (or leave blank): " + Style.RESET_ALL) or None
            elif options[current_selection] == "Duration":
                duration_input = input(Fore.GREEN + "Enter capture duration (or leave blank): " + Style.RESET_ALL)
                selected_duration = int(duration_input) if duration_input.isdigit() else None
            elif options[current_selection] == "IP Address":
                ip_input = input(Fore.GREEN + "Enter IP address (or leave blank): " + Style.RESET_ALL)
                selected_ip = ip_input if ip_input.strip() else None
            elif options[current_selection] == "Packet Size Range":
                min_size = input(Fore.GREEN + "Enter minimum packet size (or leave blank): " + Style.RESET_ALL)
                max_size = input(Fore.GREEN + "Enter maximum packet size (or leave blank): " + Style.RESET_ALL)
                if min_size.isdigit() and max_size.isdigit():
                    selected_packet_size_range = (int(min_size), int(max_size))
                else:
                    selected_packet_size_range = None
            elif options[current_selection] == "Anomaly Detection":
                enable_anomaly_detection = not enable_anomaly_detection
            else:  # Protocol options (TCP, UDP, ICMP, etc.)
                protocol = options[current_selection].lower()
                selected_protocols[protocol] = not selected_protocols.get(protocol, False)


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
