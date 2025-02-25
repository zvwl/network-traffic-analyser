import sys
import termios
import tty
import time
import logging
import re

from scapy.all import IP, TCP, UDP, Raw, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
from colorama import Fore, Style

from ml.preprocess import preprocess_data
from joblib import load

# Load ML model and preprocessors
model = load("ml/anomaly_model.pkl")
encoders = load("ml/encoders.pkl")
scaler = load("ml/scaler.pkl")

def detect_anomalies(packet_data):
    X, _, _ = preprocess_data(packet_data, encoders, scaler)
    probabilities = model.predict_proba(X)
    threshold = 0.7  # Adjust threshold as needed
    return (probabilities[:, 1] > threshold).astype(int)


def loading_spinner(text, duration=5):
    spinner = ['-', '\\', '|', '/']
    start_time = time.time()
    i = 0
    while time.time() - start_time < duration:
        sys.stdout.write(f"\r{text} {spinner[i % len(spinner)]}")
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    sys.stdout.write("\rDone!                                       \n")

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

def glowing_text(text, iterations=5):
    for i in range(iterations):
        # Display the text in normal green
        print(Fore.GREEN + text + Style.RESET_ALL, end='\r')
        time.sleep(0.5)
        # Display the text in brighter green
        print(Fore.LIGHTGREEN_EX + text + Style.RESET_ALL, end='\r')
        time.sleep(0.5)
    print()  # Add a newline after the glowing effect is done

def get_duration_input():
    while True:
        try:
            duration = int(input(Fore.GREEN + "Enter capture duration in seconds: " + Style.RESET_ALL))
            if duration > 0:
                return duration
            else:
                print(Fore.RED + "Please enter a positive number." + Style.RESET_ALL)
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter a number." + Style.RESET_ALL)

def get_ip_input():
    while True:
        ip = input(Fore.GREEN + "Enter IP address to filter: " + Style.RESET_ALL)
        if ip:
            return ip
        else:
            print(Fore.RED + "Invalid input. Please enter a valid IP address." + Style.RESET_ALL)

def get_packet_size_range():
    while True:
        try:
            min_size = int(input(Fore.GREEN + "Enter minimum packet size (bytes): " + Style.RESET_ALL))
            max_size = int(input(Fore.GREEN + "Enter maximum packet size (bytes): " + Style.RESET_ALL))
            if min_size > 0 and max_size > min_size:
                return min_size, max_size
            else:
                print(Fore.RED + "Invalid input. Please enter positive numbers with max size greater than min size." + Style.RESET_ALL)
        except ValueError:
            print(Fore.RED + "Invalid input. Please enter numbers." + Style.RESET_ALL)


def detect_anomaly(packet):
    """
    Enhanced anomaly detection for multiple types of malicious traffic
    Returns (is_anomalous, attack_types) where attack_types is a list of detected attacks
    """
    if IP not in packet:
        return False, []

    try:
        # Initialise tracking if not exists
        if not hasattr(detect_anomaly, 'tracking'):
            detect_anomaly.tracking = {
                'window_start': time.time(),
                'attack_tracking': {
                    'syn_flood': {},     # Track by destination IP
                    'ping_flood': {},    # Track by destination IP
                    'port_scan': {},     # Track by source IP
                    'large_packets': {},  # Track by source-dest pair
                    'sql_injection': set(),
                    'packets_per_ip': {} # Track total packets per IP
                },
                'last_reset': time.time()
            }

        current_time = time.time()
        tracking = detect_anomaly.tracking
        window_size = 4  # 5-second window for detection

        # Reset tracking periodically
        if current_time - tracking['last_reset'] > window_size:
            tracking['attack_tracking'] = {
                'syn_flood': {},
                'ping_flood': {},
                'port_scan': {},
                'large_packets': {},
                'sql_injection': set(),
                'packets_per_ip': {}
            }
            tracking['last_reset'] = current_time
            tracking['window_start'] = current_time

        # Extract packet info
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)

        detected_attacks = []

        # Update packets per IP tracking
        if src_ip not in tracking['attack_tracking']['packets_per_ip']:
            tracking['attack_tracking']['packets_per_ip'][src_ip] = {
                'count': 0,
                'ports': set(),
                'timestamps': []
            }
        
        tracking['attack_tracking']['packets_per_ip'][src_ip]['count'] += 1
        tracking['attack_tracking']['packets_per_ip'][src_ip]['timestamps'].append(current_time)

        if TCP in packet or UDP in packet:
            # Track both source and destination ports - for more comprehensive detection
            dst_port = None
            if TCP in packet:
                dst_port = packet[TCP].dport
            elif UDP in packet:
                dst_port = packet[UDP].dport
                
            # Initialise or update port scan tracking
            if src_ip not in tracking['attack_tracking']['port_scan']:
                tracking['attack_tracking']['port_scan'][src_ip] = {
                    'target_ips': {},
                    'ports': set(),
                    'timestamps': [],
                    'port_timestamps': {}
                }
            
            src_tracking = tracking['attack_tracking']['port_scan'][src_ip]
            
            # Add destination IP to tracking
            if dst_ip not in src_tracking['target_ips']:
                src_tracking['target_ips'][dst_ip] = set()
            
            # Track this port access
            if dst_port is not None:
                src_tracking['ports'].add(dst_port)
                src_tracking['target_ips'][dst_ip].add(dst_port)
                
                # Add port-specific timestamp tracking
                port_key = f"{dst_ip}:{dst_port}"
                if port_key not in src_tracking['port_timestamps']:
                    src_tracking['port_timestamps'][port_key] = []
                src_tracking['port_timestamps'][port_key].append(current_time)
            
            # Add overall timestamp
            src_tracking['timestamps'].append(current_time)
            
            # Clean old timestamps
            src_tracking['timestamps'] = [
                t for t in src_tracking['timestamps']
                if current_time - t <= window_size
            ]
            
            # Clean old port-specific timestamps
            for port_key in list(src_tracking['port_timestamps'].keys()):
                src_tracking['port_timestamps'][port_key] = [
                    t for t in src_tracking['port_timestamps'][port_key]
                    if current_time - t <= window_size
                ]
                
                # Remove empty timestamp lists
                if not src_tracking['port_timestamps'][port_key]:
                    del src_tracking['port_timestamps'][port_key]

            # 1. Multiple unique ports accessed in a short time (reduced threshold)
            # 2. Distribution of ports across multiple targets
            # 3. scanning pattern detection

            port_scan_detected = False

            # Timestamps indicate at least 3 connections in short window (reduced from 5)
            if len(src_tracking['ports']) >= 5 and len(src_tracking['timestamps']) >= 3:
                # Calculate port access rate
                if len(src_tracking['timestamps']) >= 2:
                    time_span = max(src_tracking['timestamps']) - min(src_tracking['timestamps'])
                    if time_span > 0:
                        access_rate = len(src_tracking['timestamps']) / time_span
                        
                        # High access rate is suspicious
                        if access_rate > 0.7:  # More than 1 access per 2 seconds
                            port_scan_detected = True
                else:
                    # Not enough timestamps to calculate rate
                    pass
                
                # Check for distribution across multiple targets
                if len(src_tracking['target_ips']) > 1:
                    # Scanning multiple targets is highly suspicious
                    port_scan_detected = True
                
                # Check for sequential port access
                sorted_ports = sorted(list(src_tracking['ports']))
                for i in range(len(sorted_ports) - 2):
                    if sorted_ports[i+1] - sorted_ports[i] <= 2 and sorted_ports[i+2] - sorted_ports[i+1] <= 2:
                        # Three sequential ports detected (or with small gaps)
                        port_scan_detected = True
                        break
            
            if port_scan_detected:
                detected_attacks.append('port_scan')

        # 2. SYN Flood Detection
        if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag
            syn_tracking = tracking['attack_tracking']['syn_flood']
            if dst_ip not in syn_tracking:
                syn_tracking[dst_ip] = []
            
            syn_tracking[dst_ip].append(current_time)
            
            # Clean old timestamps
            syn_tracking[dst_ip] = [
                t for t in syn_tracking[dst_ip]
                if current_time - t <= window_size
            ]
            
            # SYN flood criteria:
            # High rate of SYN packets to same destination
            if len(syn_tracking[dst_ip]) > 15 and 'port_scan' not in detected_attacks:
                detected_attacks.append('syn_flood')

        # 3. Ping Flood Detection
        if ICMP in packet:
            ping_tracking = tracking['attack_tracking']['ping_flood']
            if dst_ip not in ping_tracking:
                ping_tracking[dst_ip] = []
            
            ping_tracking[dst_ip].append(current_time)
            
            # Clean old timestamps
            ping_tracking[dst_ip] = [
                t for t in ping_tracking[dst_ip]
                if current_time - t <= window_size
            ]
            
            # Ping flood criteria:
            # High rate of ICMP packets to same destination
            if len(ping_tracking[dst_ip]) > 10:
                detected_attacks.append('ping_flood')

        # Create a unique key for source-destination pair
        key = (src_ip, dst_ip)
        
        # Initialise tracking for this source-destination pair
        if key not in tracking['attack_tracking']['large_packets']:
            tracking['attack_tracking']['large_packets'][key] = {
                'timestamps': [],
                'sizes': [],
                'protocols': []
            }
        
        # Add protocol information
        protocol = 'OTHER'
        if TCP in packet:
            if HTTPRequest in packet or HTTPResponse in packet:
                protocol = 'HTTP'
            else:
                protocol = 'TCP'
        elif UDP in packet:
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                protocol = 'DNS'
            else:
                protocol = 'UDP'
        elif ICMP in packet:
            protocol = 'ICMP'
        
        # Update packet tracking
        packet_tracking = tracking['attack_tracking']['large_packets'][key]
        packet_tracking['timestamps'].append(current_time)
        packet_tracking['sizes'].append(packet_size)
        packet_tracking['protocols'].append(protocol)
        
        # Clean old entries
        valid_indices = [i for i, t in enumerate(packet_tracking['timestamps']) 
                       if current_time - t <= window_size]
        
        packet_tracking['timestamps'] = [packet_tracking['timestamps'][i] for i in valid_indices]
        packet_tracking['sizes'] = [packet_tracking['sizes'][i] for i in valid_indices]
        packet_tracking['protocols'] = [packet_tracking['protocols'][i] for i in valid_indices]
        
        # Protocol-specific size thresholds
        size_thresholds = {
            'TCP': 1500,   
            'UDP': 1000,   
            'HTTP': 1800,  
            'DNS': 1000,   
            'ICMP': 800,   
            'OTHER': 1200  
        }
        
        # Determine threshold for current packet
        threshold = size_thresholds.get(protocol, size_thresholds['OTHER'])
        
        # Check if current packet size exceeds threshold
        if packet_size > threshold:
            # Check recent history of large packets
            if len(packet_tracking['sizes']) >= 2:
                # Count large packets of the same protocol
                protocol_sizes = [size for i, size in enumerate(packet_tracking['sizes']) 
                                if packet_tracking['protocols'][i] == protocol]
                
                # If there are prior packets of this protocol
                if protocol_sizes:
                    # Calculate mean size
                    mean_size = sum(protocol_sizes) / len(protocol_sizes)
                    
                    # Count large packets
                    large_packet_count = sum(1 for size in protocol_sizes if size > threshold)
                    
                    # Detect large packets if:
                    # 1. Current packet is significantly larger than threshold (reduced multiplier)
                    # 2. There are multiple large packets in the window (reduced threshold)
                    # 3. Mean packet size is consistently high
                    large_packet_criteria = [
                        packet_size > threshold * 1.2,
                        large_packet_count >= 2,
                        mean_size > threshold * 1.1 and len(protocol_sizes) >= 3
                    ]
                    
                    if any(large_packet_criteria):
                        detected_attacks.append('large_packets')
            else:
                # If not enough history, just check current packet
                if packet_size > threshold * 1.5:
                    detected_attacks.append('large_packets')

        # 5. Malformed Packet Detection
        if TCP in packet:
            tcp_layer = packet[TCP]
            
            # Check for invalid flag combinations
            if tcp_layer.flags & 0x3F == 0x3F:  # All flags set
                detected_attacks.append('malformed_packets')
            
            # Check for unusual packet sizes
            if TCP in packet and packet_size < 20:  # Too small for valid TCP
                detected_attacks.append('malformed_packets')

        # 6. SQL Injection Detection
        if Raw in packet:
            try:
                payload = str(packet[Raw].load).lower()
                # More specific SQL injection patterns with context
                sql_patterns = [
                    # More specific OR condition pattern
                    r"'\s*(\|\||or)\s*'?[0-9a-zA-Z]+\s*'?\s*=\s*'?[0-9a-zA-Z]+",  
                    
                    # Union-based injection requiring more specific structure
                    r"union\s+all?\s+select\s+[\w\s,*]+",
                    
                    # Dangerous SQL commands with more context
                    r";\s*(drop|delete|update|insert)\s+\w+",
                    
                    # Comment patterns only at the end of a statement
                    r"(;|'|\")\s*(--|#|\/\*)",
                    
                    # System stored procedures with specific context (Dangerous)
                    r";\s*exec\s*(\s|\+)+\w+\s*[\w@]+",
                    r";\s*xp_cmdshell\s*[\w\s]"
                ]
                
                # Minimum payload length to consider
                if len(payload) < 10:
                    return
                
                # Count the number of patterns matched
                matches = 0
                for pattern in sql_patterns:
                    if re.search(pattern, payload, re.IGNORECASE):
                        matches += 1
                
                # Need at least 2 matches to consider it SQL injection
                if matches >= 2:
                    detected_attacks.append('sql_injection')
            except Exception as e:
                logging.error(f"Error in SQL injection detection: {e}")

        # Log detected attacks
        if detected_attacks:
            logging.info(f"Anomalous packet detected: {detected_attacks}")

        return bool(detected_attacks), detected_attacks

    except Exception as e:
        logging.error(f"Error in anomaly detection: {e}")
        return False, []