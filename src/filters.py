import pandas as pd
from joblib import load
import os
import json
import time
import logging
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMPv6NDOptUnknown, DNS, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from colorama import Fore, Style
from src.utils import get_keypress
from datetime import datetime
from ml.model_loader import model_loader
from ml.preprocess import preprocess_data
from ml.feature_extractor import feature_extractor

# Global filter variables
selected_protocols = {"tcp": False, "udp": False, "icmp": False, "icmpv6": False, "mdns": False, "http": False, "ntp": False}
selected_port = None
selected_duration = None  # Default duration
selected_ip = None
selected_packet_size_range = None
remove_duplicates = False
captured_packets = []  # Global list to store captured packets
sniffer_thread = None

# Global tracking variables for attack detection
last_scan_port = None
last_scan_src = None 
last_scan_dst = None
random_src_ips = set()
random_src_count = 0
last_check_time = time.time()

# Maximum number of entries to track (to prevent memory issues)
MAX_TRACKING_ENTRIES = 1000

# Port scan tracking
seen_dst_ips = set()
seen_src_ips_per_dst = {}  # Maps dst_ip to set of src_ips that have connected


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

def capture_filtered_traffic(output_pcap="traffic_capture.pcap", output_csv="traffic_capture.csv"):
    global selected_protocols, selected_port, selected_duration, selected_ip, selected_packet_size_range, captured_packets, stop_capture

    stop_capture = False  # Reset the stop flag

    # Clear previous captured packets
    captured_packets = []

    # Remove old output files
    if os.path.exists(output_csv):
        os.remove(output_csv)
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
            iface="en0" 
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
    global last_scan_port, last_scan_src, last_scan_dst
    global random_src_ips, random_src_count, last_check_time
    global seen_dst_ips, seen_src_ips_per_dst
    
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
    
    # Track source/dst IPs for port scan detection
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    
    # Add to tracking sets for port scan detection
    seen_dst_ips.add(dst_ip)
    if dst_ip not in seen_src_ips_per_dst:
        seen_src_ips_per_dst[dst_ip] = set()
    seen_src_ips_per_dst[dst_ip].add(src_ip)
    
    # Track random source IPs for DDoS detection
    if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag set
        random_src_ips.add(src_ip)
        random_src_count = len(random_src_ips)
        
        # Reset the counter periodically
        current_time = time.time()
        if current_time - last_check_time > 5:  # Reset every 5 seconds
            last_check_time = current_time
            random_src_ips.clear()
            random_src_count = 0
    
    # Cleanup tracking data if it grows too large
    if len(seen_dst_ips) > MAX_TRACKING_ENTRIES:
        seen_dst_ips.clear()
        seen_src_ips_per_dst.clear()
        random_src_ips.clear()
        random_src_count = 0

    # Extract features using the feature extractor
    features = feature_extractor.extract_features(packet)
    
    if not features:
        return  # Skip packets that don't have features
        
    # Determine protocol for display
    protocol = "Other"
    is_http = False
    
    if IP in packet:
        if TCP in packet:
            protocol = "TCP"
            # Check for HTTP content
            from scapy.all import Raw
            if Raw in packet:
                raw_data = packet[Raw].load
                try:
                    if (raw_data.startswith(b'POST') or raw_data.startswith(b'GET') or 
                        raw_data.startswith(b'HTTP')):
                        protocol = "HTTP"
                        is_http = True
                except:
                    pass
            # Also check for standard HTTP detection
            if HTTPRequest in packet or HTTPResponse in packet:
                protocol = "HTTP"
                is_http = True
        elif UDP in packet:
            protocol = "UDP"
            if packet[UDP].dport == 5353:
                protocol = "MDNS"
            elif packet[UDP].dport == 123:
                protocol = "NTP"
        elif ICMP in packet:
            protocol = "ICMP"
    elif ICMPv6NDOptUnknown in packet:
        protocol = "ICMPv6"

    # Detect anomalies using ML model only
    ml_detected = False
    ml_confidence = 0.0
    attack_type = "None"
    
    if model_loader.model:
        try:
            # Convert features to DataFrame
            features_df = pd.DataFrame([features])
            
            # Ensure all required columns are present and in correct order
            for col in model_loader.feature_names:
                if col not in features_df.columns:
                    features_df[col] = 0
            
            # Reorder columns to match training data
            features_df = features_df[model_loader.feature_names]
            
            # Make prediction with confidence threshold
            prediction, probabilities = model_loader.predict(features_df, preprocess_data)
            
            # Check if prediction is not None and contains at least one element
            if prediction is not None and len(prediction) > 0 and prediction[0] == 1:
                ml_detected = True
                
                # Get confidence level
                if probabilities is not None and len(probabilities) > 0 and len(probabilities[0]) > 1:
                    ml_confidence = probabilities[0][1]  # Anomaly probability
                    
                    # Direct flag-based malformed packet detection
                    if TCP in packet:
                        flags = packet[TCP].flags
                        if (flags & 0x3F) == 0x3F or (flags & 0x03) == 0x03 or (flags & 0x06) == 0x06:
                            attack_type = "Malformed Packet"
                    
                    # If not already classified, use feature-based detection
                    if attack_type == "None":
                        # 1. Malformed Packet Detection
                        if features['wrong_fragment'] > 0 or features['urgent'] > 0:
                            attack_type = "Malformed Packet" 
                        # 2. Port Scan Detection - improved
                        elif features['same_srv_rate'] < 0.5 or features['diff_srv_rate'] > 0.5 or (
                             TCP in packet and last_scan_port == packet[TCP].sport and 
                             last_scan_src == src_ip and 
                             last_scan_dst == dst_ip):
                            attack_type = "Port Scan"
                            if TCP in packet:
                                last_scan_port = packet[TCP].sport
                                last_scan_src = src_ip
                                last_scan_dst = dst_ip
                        # 3. Ping Flood Detection
                        elif features['protocol_type'] == 'icmp' and features['count'] > 20:
                            attack_type = "Ping Flood"
                        else:
                            attack_type = "Potential Unknown Attack"
        except Exception as e:
            logging.error(f"Error making prediction: {e}")

    # Store the packet with its features and ML detection result
    detection_result = {
        'is_anomaly': ml_detected,
        'ml_confidence': ml_confidence,
        'attack_type': attack_type
    }
    
    captured_packets.append((packet, features, detection_result))

    # Format for display
    if ml_detected:
        attack_str = f"[{attack_type} (ML:{ml_confidence:.2f})]"
    else:
        attack_str = "None"
    
    # Color coding based on detection
    status_color = Fore.GREEN  # Default color for normal packets
    
    if ml_detected:
        # Using different colors for different attack types
        if "Port Scan" in attack_type:
            status_color = Fore.MAGENTA
        elif "Ping Flood" in attack_type:
            status_color = Fore.RED
        elif "Malformed" in attack_type:
            status_color = Fore.BLUE
        else:
            status_color = Fore.LIGHTYELLOW_EX
    
    # Print packet information with enhanced formatting
    print(status_color + 
          f"[+] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
          f"{packet[IP].src}{get_port_info(packet)} -> {packet[IP].dst} | "
          f"Protocol: {protocol} | Length: {len(packet)} bytes | "
          f"Attack: {attack_str} | "
          f"Info: {packet.summary()}" + 
          Style.RESET_ALL)

def get_port_info(packet):
    """Extract port information from the packet"""
    if TCP in packet:
        return f":{packet[TCP].sport} > :{packet[TCP].dport}"
    elif UDP in packet:
        return f":{packet[UDP].sport} > :{packet[UDP].dport}"
    return ""

def save_captured_packets(output_pcap="traffic_capture.pcap", output_csv="traffic_capture.csv"):
    """Save captured packets to PCAP and CSV files with NSL-KDD features."""
    try:
        # Extract packets, features, and detection results
        valid_entries = [(pkt, features, detection) for pkt, features, detection in captured_packets 
                        if pkt is not None and features is not None]
        
        if valid_entries:
            # Save PCAP file
            print(Fore.GREEN + f"Saving to {output_pcap}..." + Style.RESET_ALL)
            wrpcap(output_pcap, [pkt for pkt, _, _ in valid_entries])
            
            # Save CSV file with NSL-KDD features
            print(Fore.GREEN + f"Saving to {output_csv}..." + Style.RESET_ALL)
            
            # Create a list of features with detection results
            features_list = []
            for _, features, detection in valid_entries:
                # Add detection results to features
                features_with_detection = features.copy()
                features_with_detection['anomaly'] = 1 if detection['is_anomaly'] else 0
                features_with_detection['class'] = 'attack' if detection['is_anomaly'] else 'normal'
                
                # Add detailed detection information
                features_with_detection['ml_confidence'] = detection['ml_confidence']
                features_with_detection['attack_type'] = detection['attack_type']
                
                features_list.append(features_with_detection)
            
            # Create DataFrame and save to CSV
            if features_list:
                df = pd.DataFrame(features_list)
                df.to_csv(output_csv, index=False)
            else:
                print(Fore.YELLOW + "No valid features to save." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "No valid packets to save." + Style.RESET_ALL)
        
        logging.info("Captured packets saved successfully.")
    except Exception as e:
        logging.error(f"Failed to save captured packets: {e}")
        raise

def packet_to_dict(packet, features, detection_result):
    """
    Convert a packet to a dictionary format with detection information.
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
            "ml_confidence": 0.0,
            "attack_type": "None"
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
        "anomaly": detection_result['is_anomaly'],
        "ml_confidence": detection_result['ml_confidence'],
        "attack_type": detection_result['attack_type']
    }
    
    # Add key NSL-KDD features
    for key in ['duration', 'src_bytes', 'dst_bytes', 'count', 'serror_rate', 'rerror_rate', 
               'same_srv_rate', 'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count']:
        if key in features:
            packet_dict[key] = features[key]
    
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
        print(Fore.CYAN + "Using Machine Learning mode only - no rule-based detection" + Style.RESET_ALL)

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