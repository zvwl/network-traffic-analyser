import sys
import termios
import tty
import time

from scapy.all import IP, TCP, UDP
from colorama import Fore, Style



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
    if IP not in packet:
        return False  # Ignore packets without an IP layer

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else packet.payload.name if hasattr(packet.payload, "name") else "Other"
    packet_size = len(packet)
    is_anomalous = False

    # Define private IP ranges
    private_ip_prefixes = ["192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                           "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."]
    def is_private(ip):
        return any(ip.startswith(prefix) for prefix in private_ip_prefixes)

    # Rule 1: Ignore typical multicast or broadcast traffic
    if dst_ip.startswith("224.") or dst_ip == "255.255.255.255":
        print(Fore.YELLOW + f"Ignored multicast/broadcast traffic: {src_ip} -> {dst_ip}" + Style.RESET_ALL)
        return False

    # Rule 2: Trusted IPs
    trusted_ips = {"20.190.159.4", "3.233.158.24", "3.233.158.25", "192.168.1.106", "192.168.1.105"}

    # Rule 3: Detect large packets
    size_threshold = 1500  # Threshold for large packets
    if packet_size > size_threshold:
        print(Fore.YELLOW + f"Anomaly detected: Large packet ({packet_size} bytes) from {src_ip} to {dst_ip}" + Style.RESET_ALL)
        is_anomalous = True

    # Rule 4: Detect uncommon protocols
    common_protocols = {"TCP", "UDP", "ICMP"}
    if protocol not in common_protocols:
        print(Fore.YELLOW + f"Anomaly detected: Uncommon protocol '{protocol}' in packet from {src_ip} to {dst_ip}" + Style.RESET_ALL)
        is_anomalous = True

    # Rule 5: Public-to-public communication (skip this rule for trusted IPs)
    src_is_private = is_private(src_ip)
    dst_is_private = is_private(dst_ip)
    if not src_is_private and not dst_is_private:
        if dst_ip in trusted_ips or src_ip in trusted_ips:
            print(Fore.YELLOW + f"Trusted public-to-public traffic: {src_ip} -> {dst_ip}" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + f"Anomaly detected: Public-to-public communication from {src_ip} to {dst_ip}" + Style.RESET_ALL)
            is_anomalous = True

    return is_anomalous
