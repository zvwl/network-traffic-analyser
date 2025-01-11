import os
import json
import time
import logging
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
remove_duplicates = False
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

def capture_filtered_traffic(output_pcap="traffic_capture.pcap", output_json="traffic_capture.json"):
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range, captured_packets, stop_capture

    stop_capture = False  # Reset the stop flag

    # Clear previous captured packets
    captured_packets = []

    # Remove old output files
    if os.path.exists(output_json):
        os.remove(output_json)
    if os.path.exists(output_pcap):
        os.remove(output_pcap)

    # Build the filter string based on selected options
    protocol_filters = []
    for protocol, selected in selected_protocols.items():
        if selected:
            if protocol == "icmp":
                protocol_filters.append("icmp")
            elif protocol == "icmpv6":
                protocol_filters.append("ip6 proto 58")
            elif protocol == "mdns":
                protocol_filters.append("udp port 5353")
            elif protocol == "http":
                protocol_filters.append("tcp port 80 or tcp port 443")
            elif protocol == "ntp":
                protocol_filters.append("udp port 123")
            elif protocol in ["tcp", "udp"]:
                protocol_filters.append(protocol)

    other_filters = []
    if selected_port:
        other_filters.append(f"port {selected_port}")
    if selected_ip:
        other_filters.append(f"host {selected_ip}")
    if selected_packet_size_range:
        min_size, max_size = selected_packet_size_range
        other_filters.append(f"greater {min_size} and less {max_size}")

    # Combine protocol and other filters into a valid BPF filter
    protocol_str = " or ".join(protocol_filters) if protocol_filters else ""
    other_str = " and ".join(other_filters) if other_filters else ""
    filter_str = " and ".join(filter for filter in [protocol_str, other_str] if filter)

     # Display more statuses separately (not part of the BPF filter)
    additional_status = []
    if enable_anomaly_detection:
        additional_status.append("Anomaly Detection")
    if remove_duplicates:
        additional_status.append("Remove Duplicates")

    display_status = f" (Additional Filters: {', '.join(additional_status)})" if additional_status else ""
    print(Fore.GREEN + f"Starting capture with filter: {filter_str or 'None'}{display_status}" + Style.RESET_ALL)

    try:
        sniff(
            filter=filter_str,
            prn=packet_callback,
            timeout=selected_duration,
            stop_filter=lambda _: stop_capture,
        )
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\nCapture stopped by user. Finalising..." + Style.RESET_ALL)
        stop_capture = True  # Prevent further packet processing
    finally:
        save_captured_packets()
        print(Fore.GREEN + "Capture saved successfully!" + Style.RESET_ALL)
        time.sleep(3)  # Delay for better visibility 


stop_capture = False  # Global flag to stop processing
seen_packets = set()  # Set to store unique packets
def packet_callback(packet):
    global captured_packets, stop_capture, remove_duplicates, seen_packets
    

    # Ignore packets if stop_capture is True
    if stop_capture:
        return
    
      # Construct a unique identifier for the packet
    packet_id = (
        packet[IP].src if IP in packet else "Unknown",
        packet[IP].dst if IP in packet else "Unknown",
        "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
        len(packet)
    )
    
    if remove_duplicates and packet_id in seen_packets:
        return
    seen_packets.add(packet_id)

    protocol = "Other"
    if IP in packet:
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
    elif ICMPv6NDOptUnknown in packet:
        protocol = "ICMPv6"
    elif DNS in packet and ("5353" in packet.summary()):
        protocol = "MDNS"
    elif HTTPRequest in packet or HTTPResponse in packet:
        protocol = "HTTP"
    elif Raw in packet and "ntp" in packet.summary().lower():
        protocol = "NTP"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src if IP in packet else "Unknown"
    dst_ip = packet[IP].dst if IP in packet else "Unknown"
    packet_length = len(packet)
    packet_info = packet.summary()

    print(Fore.GREEN + f"[+] {timestamp} | {src_ip} -> {dst_ip} | Protocol: {protocol} | Length: {packet_length} bytes | Info: {packet_info}" + Style.RESET_ALL)

    # Only detect anomalies if enabled and stop_capture is False
    is_anomalous = False
    capturing = True
    if enable_anomaly_detection and not stop_capture:
        is_anomalous = detect_anomaly(packet)
        if is_anomalous and capturing:
            logging.warning(f"Anomaly detected in packet: {src_ip} -> {dst_ip} | Protocol: {protocol} | Length: {packet_length} bytes")

    captured_packets.append((packet, is_anomalous))



def save_captured_packets(output_pcap="traffic_capture.pcap", output_json="traffic_capture.json"):
    try:
        # Prepare valid packets
        valid_packets = [pkt for pkt, _ in captured_packets if pkt is not None]

        if valid_packets:
            print(Fore.GREEN + f"Saving to {output_pcap}..." + Style.RESET_ALL)
            wrpcap(output_pcap, valid_packets)

            print(Fore.GREEN + f"Saving to {output_json}..." + Style.RESET_ALL)
            with open(output_json, 'w') as json_file:
                json.dump(
                    [packet_to_dict(pkt, ts) for pkt, ts in captured_packets],
                    json_file,
                    default=str,
                )
        else:
            # Handle case where no packets are captured
            print(Fore.YELLOW + "No valid packets to save." + Style.RESET_ALL)
            with open(output_json, 'w') as json_file:
                json.dump([], json_file)  # Write an empty JSON array

        logging.info("Captured packets saved successfully.")
    except Exception as e:
        logging.error(f"Failed to save captured packets: {e}")



def packet_to_dict(packet, timestamp=None):
    """Convert a packet to a dictionary format with an optional timestamp."""
    global enable_anomaly_detection  # Ensure access to the global flag

    # Determine the anomaly status only if anomaly detection is enabled
    is_anomalous = detect_anomaly(packet) if enable_anomaly_detection else None

    # Construct the dictionary for the packet
    packet_dict = {
        "src_ip": packet[IP].src if IP in packet else None,
        "dst_ip": packet[IP].dst if IP in packet else None,
        "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
        "length": len(packet),
        "info": packet.summary(),
        "timestamp": float(timestamp) if timestamp else None,  # Convert timestamp to float
        "anomaly": is_anomalous,
    }
    return packet_dict



def set_filter():
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range, enable_anomaly_detection, remove_duplicates

    options = ["TCP", "UDP", "ICMP", "ICMPv6", "MDNS", "HTTP", "NTP", "Port", "Duration", "IP Address", "Packet Size Range", "Anomaly Detection", "Remove Duplicates"]
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
            elif option == "Remove Duplicates":
                display_value = "✅" if remove_duplicates else "❌"
            else:  # Protocol options (TCP, UDP, ICMP, etc.)
                protocol = option.lower()
                display_value = "✅" if selected_protocols.get(protocol, False) else "❌"

            # Highlight the current selection
            color = Fore.YELLOW if current_selection == i else Fore.GREEN
            prefix = "-->" if current_selection == i else "   "
            print(color + f"{prefix} {option}: {display_value}" + Style.RESET_ALL)

        # Leave a few lines and display the Back button
        print("\n" * 2)  # Add some space
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
            elif options[current_selection] == "Remove Duplicates":  # Handle "Remove Duplicates"
                remove_duplicates = not remove_duplicates
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
