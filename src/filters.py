import os
import json
import time
import logging
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMPv6NDOptUnknown, DNS, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from colorama import Fore, Style
from src.utils import get_keypress
from src.utils import detect_anomaly
from datetime import datetime

# Global filter variables
selected_protocols = {"tcp": False, "udp": False, "icmp": False, "icmpv6": False, "mdns": False, "http": False, "ntp": False}
selected_port = None
selected_duration = None  # Default duration
selected_ip = None
selected_packet_size_range = None
remove_duplicates = False
captured_packets = []  # Global list to store captured packets
sniffer_thread = None


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
        return True
    
    # Basic packet validation
    if IP not in packet:
        return
    
    # Create packet identifier for duplicate detection
    packet_id = (
        packet[IP].src if IP in packet else "Unknown",
        packet[IP].dst if IP in packet else "Unknown",
        "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
        len(packet)
    )
    
    # Skip duplicates if enabled
    if remove_duplicates and packet_id in seen_packets:
        return
    seen_packets.add(packet_id)

    # Determine protocol
    protocol = "Other"
    if IP in packet:
        if TCP in packet:
            protocol = "TCP"
            if HTTPRequest in packet or HTTPResponse in packet:
                protocol = "HTTP"
        elif UDP in packet:
            protocol = "UDP"
            if DNS in packet and packet[UDP].dport == 5353:
                protocol = "MDNS"
            elif packet[UDP].dport == 123:
                protocol = "NTP"
        elif ICMP in packet:
            protocol = "ICMP"
    elif ICMPv6NDOptUnknown in packet:
        protocol = "ICMPv6"

    # Get timestamp and packet details
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src if IP in packet else "Unknown"
    dst_ip = packet[IP].dst if IP in packet else "Unknown"
    packet_length = len(packet)
    packet_info = packet.summary()

    # Perform enhanced anomaly detection
    is_anomaly, detected_attacks = detect_anomaly(packet)
    
    # Store the packet with its anomaly status and attack types
    captured_packets.append((packet, is_anomaly, detected_attacks))

    # Color coding based on attack type
    status_color = Fore.GREEN  # Default color for normal packets
    if is_anomaly:
        if 'port_scan' in detected_attacks:
            status_color = Fore.MAGENTA  # Purple for port scans
        elif 'syn_flood' in detected_attacks:
            status_color = Fore.RED  # Red for SYN floods
        elif 'ping_flood' in detected_attacks:
            status_color = Fore.YELLOW  # Yellow for ping floods
        elif 'sql_injection' in detected_attacks:
            status_color = Fore.CYAN  # Cyan for SQL injection
        elif 'malformed_packets' in detected_attacks:
            status_color = Fore.BLUE  # Blue for malformed packets
        elif 'large_packets' in detected_attacks:
            status_color = Fore.LIGHTRED_EX  # Light red for large packets
        else:
            status_color = Fore.RED  # Default anomaly color

    # Format attack types for display
    attack_str = f"[{', '.join(detected_attacks)}]" if detected_attacks else "None"
    
    # Enhanced packet information display
    port_info = ""
    if TCP in packet:
        port_info = f":{packet[TCP].sport} > :{packet[TCP].dport}"
    elif UDP in packet:
        port_info = f":{packet[UDP].sport} > :{packet[UDP].dport}"

    # Print packet information with enhanced formatting
    print(status_color + 
          f"[+] {timestamp} | {src_ip}{port_info} -> {dst_ip} | "
          f"Protocol: {protocol} | Length: {packet_length} bytes | "
          f"Attack Types: {attack_str} | "
          f"Info: {packet_info}" + 
          Style.RESET_ALL)

def save_captured_packets(output_pcap="traffic_capture.pcap", output_json="traffic_capture.json"):
    """
    Save captured packets to PCAP and JSON files with enhanced attack information.
    """
    try:
        # Extract packets and their anomaly status
        valid_packets = [(pkt, bool(anomaly), attacks) for pkt, anomaly, attacks in captured_packets if pkt is not None]
        
        if valid_packets:
            # Save PCAP file
            print(Fore.GREEN + f"Saving to {output_pcap}..." + Style.RESET_ALL)
            wrpcap(output_pcap, [pkt for pkt, _, _ in valid_packets])
            
            # Save JSON file with enhanced attack information
            print(Fore.GREEN + f"Saving to {output_json}..." + Style.RESET_ALL)
            json_data = [packet_to_dict(pkt, anomaly, attacks) for pkt, anomaly, attacks in valid_packets]
            
            with open(output_json, 'w') as json_file:
                json.dump(json_data, json_file, default=str)
        else:
            print(Fore.YELLOW + "No valid packets to save." + Style.RESET_ALL)
            with open(output_json, 'w') as json_file:
                json.dump([], json_file)
        
        logging.info("Captured packets saved successfully.")
    except Exception as e:
        logging.error(f"Failed to save captured packets: {e}")
        raise

def packet_to_dict(packet, anomaly_status, detected_attacks):
    """
    Convert a packet to a dictionary format with enhanced attack information.
    
    Parameters:
    packet: scapy packet object
    anomaly_status: boolean indicating if the packet is anomalous
    detected_attacks: list of detected attack types
    
    Returns:
    dict: Dictionary containing packet information with attack details
    """
    # Basic packet validation
    if IP not in packet:
        return {
            "src_ip": None,
            "dst_ip": None,
            "protocol": "Unknown",
            "length": len(packet),
            "info": packet.summary(),
            "timestamp": datetime.now().timestamp(),
            "anomaly": False,
            "attack_types": []
        }
    
    # Extract protocol information
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
    if protocol == "TCP":
        if HTTPRequest in packet or HTTPResponse in packet:
            protocol = "HTTP"
    elif protocol == "UDP":
        if DNS in packet and packet[UDP].dport == 5353:
            protocol = "MDNS"
        elif packet[UDP].dport == 123:
            protocol = "NTP"
    
    # Extract port information
    src_port = None
    dst_port = None
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    # Create enhanced packet dictionary
    packet_dict = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": len(packet),
        "info": packet.summary(),
        "timestamp": datetime.now().timestamp(),
        "anomaly": bool(anomaly_status),
        "attack_types": detected_attacks if detected_attacks else []
    }
    
    return packet_dict

def set_filter():
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range, remove_duplicates

    options = ["TCP", "UDP", "ICMP", "ICMPv6", "MDNS", "HTTP", "NTP", "Port", "Duration", "IP Address", "Packet Size Range", "Remove Duplicates"]
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

def stop_capture_process():
    """Properly stop the capture process."""
    global stop_capture, captured_packets
    
    stop_capture = True
    print(Fore.YELLOW + "Stopping capture process..." + Style.RESET_ALL)
    
    # Clear captured packets to prevent saving on exit
    captured_packets = []