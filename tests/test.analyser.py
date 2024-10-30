import sys
import os

# Add the project's root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import send, IP, TCP, ICMP
from src.utils import detect_anomaly



def test_private_to_private():
    packet = IP(src="192.168.1.2", dst="192.168.1.3") / TCP(dport=80)
    print("Testing Private to Private IP packet...")
    send(packet)

def test_public_to_private():
    packet = IP(src="66.203.125.13", dst="192.168.1.3") / TCP(dport=80)
    print("Testing Public to Private IP packet...")
    send(packet)

def test_public_to_public():
    packet = IP(src="66.203.125.13", dst="8.8.8.8") / TCP(dport=80)
    print("Testing Public to Public IP packet...")
    send(packet)

def test_large_packet_size():
    large_payload = "A" * 1402  # Reduced further to fit MTU limits
    packet = IP(src="192.168.1.2", dst="192.168.1.3") / TCP(dport=80) / large_payload
    print("Testing Large Packet Size with Reduced Payload...")
    send(packet)


def test_uncommon_protocol():
    packet = IP(src="192.168.1.2", dst="192.168.1.3") / ICMP()
    print("Testing Uncommon Protocol (ICMP) Packet...")
    send(packet)

def run_all_tests():
    print("Running all anomaly detection tests...\n")
    test_private_to_private()
    test_public_to_private()
    test_public_to_public()
    test_large_packet_size()
    test_uncommon_protocol()
    print("\nAll tests completed.")

# Run tests when executing this script
if __name__ == "__main__":
    run_all_tests()
