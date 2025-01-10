import sys
import os

# Add the project root directory to PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.utils import detect_anomalies
from src.utils import detect_anomaly  # Import anomaly detection function
from scapy.all import IP, TCP, UDP, send
from colorama import Fore, Style
import pandas as pd

def test_anomalies():
    print(Fore.GREEN + "Starting Anomaly Detection Tests...\n" + Style.RESET_ALL)

    # Test 1: Multicast/Broadcast Traffic
    print("Test 1: Multicast/Broadcast Traffic")
    packet = IP(dst="224.0.0.1") / UDP()
    detect_anomaly(packet)  # Should not trigger an anomaly

    # Test 2: Large Packet Detection
    print("\nTest 2: Large Packet Detection")
    large_packet = IP(dst="8.8.8.8") / TCP() / ("X" * 1000)
    detect_anomaly(large_packet)  # Should trigger an anomaly

    # Test 3: Uncommon Protocols
    print("\nTest 3: Uncommon Protocols")
    uncommon_protocol_packet = IP(dst="8.8.8.8", proto=47)  # GRE protocol
    detect_anomaly(uncommon_protocol_packet)  # Should trigger an anomaly

    # Test 4: Public-to-Public Communication
    print("\nTest 4: Public-to-Public Communication")
    public_to_public_packet = IP(src="203.0.113.1", dst="198.51.100.1") / TCP()
    detect_anomaly(public_to_public_packet)  # Should trigger an anomaly

    # Test 5: Trusted Public IPs
    print("\nTest 5: Trusted Public IPs")
    trusted_ip_packet = IP(src="20.190.159.4", dst="198.51.100.1") / TCP()
    detect_anomaly(trusted_ip_packet)  # Should NOT trigger an anomaly


def test_anomaly_detection():
    sample_data = pd.DataFrame({
        "src_ip": ["192.168.1.102", "missing"],
        "dst_ip": ["17.253.77.201", "192.168.1.1"],
        "protocol": ["TCP", "UDP"],
        "length": [78, 283],
        "info": ["Sample info 1", "Sample info 2"],
    })
    results = detect_anomalies(sample_data)
    assert len(results) == len(sample_data)
    print("Results:", results)

if __name__ == "__main__":
    test_anomalies()
    test_anomaly_detection()