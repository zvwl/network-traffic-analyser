import time
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest, HTTPResponse
import logging

class FeatureExtractor:
    def __init__(self):
        self.connection_tracking = {}
        self.host_tracking = {}  # Track statistics by destination host
        self.protocol_tracking = {
            'tcp': {'total': 0, 'syn': 0, 'rst': 0},
            'udp': {'total': 0},
            'icmp': {'total': 0, 'types': {}}
        }
        
        self.service_mapping = {
            80: 'http',
            443: 'https',
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'domain',
            110: 'pop3',
            143: 'imap',
            5353: 'mdns'
        }
        
        # Multiple time windows for different statistics
        self.time_windows = {
            'short': 2,    # 2 second for burst attacks (SYN flood)
            'medium': 5,   # 5 seconds for port scans
            'long': 10     # 10 seconds for distributed attacks
        }
        
        self.last_cleanup = time.time()
        
        # Connection windows by protocol
        self.connection_windows = {
            'tcp': {'connections': [], 'start_time': time.time()},
            'udp': {'connections': [], 'start_time': time.time()},
            'icmp': {'connections': [], 'start_time': time.time()},
            'all': {'connections': [], 'start_time': time.time()}
        }
        
    def cleanup_old_connections(self, max_age=60):
        current_time = time.time()
        if current_time - self.last_cleanup < 10:
            return
            
        self.last_cleanup = current_time
        
        # Clean connection tracking
        to_remove = [conn_id for conn_id, conn_data in self.connection_tracking.items() 
                    if current_time - conn_data['last_updated'] > max_age]
        
        for conn_id in to_remove:
            del self.connection_tracking[conn_id]
            
        # Clean host tracking
        to_remove_hosts = [host for host, host_data in self.host_tracking.items()
                         if current_time - host_data['last_updated'] > max_age]
        
        for host in to_remove_hosts:
            del self.host_tracking[host]
            
        # Clean connection windows
        for protocol in self.connection_windows:
            self.connection_windows[protocol]['connections'] = [
                conn for conn in self.connection_windows[protocol]['connections']
                if current_time - conn['time'] <= self.time_windows['long']
            ]
    
    def get_protocol_type(self, packet):
        if TCP in packet:
            return 'tcp'
        elif UDP in packet:
            return 'udp'
        elif ICMP in packet:
            return 'icmp'
        return 'other'
    
    def get_service(self, packet):
        if TCP in packet:
            dport = packet[TCP].dport
            return self.service_mapping.get(dport, 'other')
        elif UDP in packet:
            dport = packet[UDP].dport
            if dport == 53:
                return 'dns'
            elif dport == 5353:
                return 'mdns'
            return self.service_mapping.get(dport, 'other')
        elif ICMP in packet:
            return 'ecr_i'  # ICMP echo reply/request service name in KDD dataset
        return 'other'
    
    def get_flag(self, packet):
        if TCP in packet:
            flags = packet[TCP].flags
            
            # Detailed flag detection
            if flags & 0x02:  # SYN
                if flags & 0x10:  # ACK
                    return 'S1'  # SYN-ACK
                return 'S0'  # SYN
            elif flags & 0x01:  # FIN
                if flags & 0x10:  # ACK
                    return 'SF'  # FIN-ACK
                return 'F0'  # FIN
            elif flags & 0x04:  # RST
                return 'REJ'  # RST
            elif flags & 0x10:  # ACK
                return 'RSTO'  # Only ACK
            
            # Detect unusual flag combinations
            unusual_flags = 0
            if (flags & 0x3F) == 0x3F:  # All flags set
                return 'MALFORMED'
            if flags & 0x20 and not (flags & 0x10):  # URG without ACK
                return 'MALURGT'
            if flags & 0x08 and not (flags & 0x10):  # PSH without ACK
                return 'MALPSH'
                
            return 'OTH'
        elif ICMP in packet:
            return 'SF'  # Map ICMP to successful "connection"
        return 'OTH'  # Default for other protocols
    
    def update_connection_stats(self, packet):
        if IP not in packet:
            return None
        
        current_time = time.time()
        
        # Extract basic packet information
        protocol = self.get_protocol_type(packet)
        service = self.get_service(packet)
        flag = self.get_flag(packet)
        packet_size = len(packet)
        
        # Extract connection ID
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = None
        dst_port = None
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            is_syn = bool(packet[TCP].flags & 0x02)  # SYN flag
            is_rst = bool(packet[TCP].flags & 0x04)  # RST flag
            is_error = is_rst  # Consider RST as error
            conn_id = (src_ip, dst_ip, 'tcp', src_port, dst_port)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            is_syn = False
            is_rst = False
            is_error = False
            conn_id = (src_ip, dst_ip, 'udp', src_port, dst_port)
        elif ICMP in packet:
            is_syn = False
            is_rst = False
            is_error = False
            conn_id = (src_ip, dst_ip, 'icmp', 0, 0)
        else:
            is_syn = False
            is_rst = False
            is_error = False
            conn_id = (src_ip, dst_ip, 'other', 0, 0)
        
        # Update protocol tracking
        if protocol in self.protocol_tracking:
            self.protocol_tracking[protocol]['total'] += 1
            
            if protocol == 'tcp':
                if is_syn:
                    self.protocol_tracking['tcp']['syn'] += 1
                if is_rst:
                    self.protocol_tracking['tcp']['rst'] += 1
            elif protocol == 'icmp' and ICMP in packet:
                icmp_type = packet[ICMP].type
                if icmp_type not in self.protocol_tracking['icmp']['types']:
                    self.protocol_tracking['icmp']['types'][icmp_type] = 0
                self.protocol_tracking['icmp']['types'][icmp_type] += 1
        
        # Add to protocol-specific connection window
        conn_data = {
            'time': current_time,
            'conn_id': conn_id,
            'protocol': protocol,
            'service': service,
            'is_syn': is_syn,
            'is_rst': is_rst,
            'is_error': is_error,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'size': packet_size
        }
        
        if protocol in self.connection_windows:
            self.connection_windows[protocol]['connections'].append(conn_data)
        
        # Also add to the 'all' window
        self.connection_windows['all']['connections'].append(conn_data)
        
        # Initialize connection tracking if needed
        if conn_id not in self.connection_tracking:
            self.connection_tracking[conn_id] = {
                'count': 0,
                'src_bytes': 0,
                'dst_bytes': 0,
                'duration': 0,
                'start_time': current_time,
                'last_updated': current_time,
                'srv_count': 0,
                'same_srv_rate': 0,
                'diff_srv_rate': 0,
                'syn_count': 0,  # Track SYN packets
                'error_count': 0,
                'service': service,
                'protocol': protocol,
                'flag_history': []  # Track flag history
            }
        
        # Update connection statistics
        conn = self.connection_tracking[conn_id]
        conn['count'] += 1
        conn['last_updated'] = current_time
        conn['duration'] = conn['last_updated'] - conn['start_time']
        
        # Track flag history (up to 10 most recent)
        conn['flag_history'].append(flag)
        if len(conn['flag_history']) > 10:
            conn['flag_history'] = conn['flag_history'][-10:]
        
        # Update bytes count
        if conn_id[0] == src_ip:
            conn['src_bytes'] += packet_size
        else:
            conn['dst_bytes'] += packet_size
        
        # Track SYN packets and errors
        if is_syn:
            conn['syn_count'] += 1
        if is_error:
            conn['error_count'] += 1
        
        # Update service statistics
        current_service = service
        services_in_window = self.get_services_in_window(dst_ip)
        total_services = len(services_in_window)
        
        if total_services > 0:
            same_service_count = services_in_window.count(current_service)
            conn['same_srv_rate'] = same_service_count / total_services
            conn['diff_srv_rate'] = 1.0 - conn['same_srv_rate']
        else:
            conn['same_srv_rate'] = 1.0
            conn['diff_srv_rate'] = 0.0
        
        conn['srv_count'] += 1
        
        # Update host tracking
        if dst_ip not in self.host_tracking:
            self.host_tracking[dst_ip] = {
                'count': 0,
                'services': [],
                'src_ports': set(),
                'connections': [],
                'syn_count': 0,
                'error_count': 0,
                'last_updated': current_time,
                'protocols': {'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}
            }
        
        host_stats = self.host_tracking[dst_ip]
        host_stats['count'] += 1
        host_stats['services'].append(service)
        if src_port:
            host_stats['src_ports'].add(src_port)
        host_stats['connections'].append(conn_id)
        host_stats['last_updated'] = current_time
        host_stats['protocols'][protocol] += 1
        
        if is_syn:
            host_stats['syn_count'] += 1
        if is_error:
            host_stats['error_count'] += 1
        
        # Trim services list to keep recent ones
        max_services = 100
        if len(host_stats['services']) > max_services:
            host_stats['services'] = host_stats['services'][-max_services:]
        
        # Clean up old connections periodically
        self.cleanup_old_connections()
        
        return conn
    
    def get_services_in_window(self, dst_ip):
        """Get list of services to this destination in the medium window"""
        current_time = time.time()
        window_size = self.time_windows['medium']
        
        return [
            conn['service'] for conn in self.connection_windows['all']['connections']
            if conn['dst_ip'] == dst_ip and current_time - conn['time'] <= window_size
        ]
    
    def get_connection_features(self, conn):
        """Extract standardized traffic features from a connection"""
        # Basic connection counts
        count = min(100, conn['count'])  # Cap at 100 like NSL-KDD dataset
        
        # Get connection window for calculating features
        current_time = time.time()
        protocol = conn['protocol']
        window = self.connection_windows[protocol]['connections'] if protocol in self.connection_windows else []
        
        # Same service rate and diff service rate 
        same_srv_rate = conn['same_srv_rate']
        diff_srv_rate = conn['diff_srv_rate']
        
        # Calculate SYN error rate (serror_rate)
        total_count = max(1, conn['count'])
        serror_rate = min(1.0, conn['syn_count'] / total_count)  # Cap at 1.0
        
        # Calculate normal REJ error rate (rerror_rate)
        rerror_rate = min(1.0, conn['error_count'] / total_count)  # Cap at 1.0
        
        # For service error rates, we'll use the same value (simplified)
        srv_serror_rate = serror_rate
        srv_rerror_rate = rerror_rate
        
        # Service diff host rate (percentage of connections to same service but different hosts)
        srv_diff_host_rate = 0.0  # Initialize
        
        # Try to calculate it if we have enough data
        if len(window) > 10:
            relevant_conns = [
                conn for conn in window 
                if conn['service'] == conn['service'] and current_time - conn['time'] <= self.time_windows['medium']
            ]
            
            if relevant_conns:
                hosts = set(conn['dst_ip'] for conn in relevant_conns)
                if len(hosts) > 1:
                    srv_diff_host_rate = (len(hosts) - 1) / len(relevant_conns)
        
        return {
            'count': count,
            'srv_count': min(100, conn['srv_count']),
            'serror_rate': serror_rate,
            'srv_serror_rate': srv_serror_rate,
            'rerror_rate': rerror_rate,
            'srv_rerror_rate': srv_rerror_rate,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'srv_diff_host_rate': srv_diff_host_rate
        }
    
    def get_host_stats(self, dst_ip):
        """Calculate host-based statistics in NSL-KDD format"""
        if dst_ip not in self.host_tracking:
            return {
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        
        host_stats = self.host_tracking[dst_ip]
        
        # Calculate number of connections to this host
        dst_host_count = min(255, host_stats['count'])  # Cap at 255 like NSL-KDD
        
        # Count services and unique service count
        services = host_stats['services']
        
        if not services:
            return {
                'dst_host_count': dst_host_count,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 1.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        
        # Count distinct services
        unique_services = set(services)
        dst_host_srv_count = len(unique_services)
        
        # Calculate service rates
        if services:
            service_counts = {}
            for svc in services:
                if svc not in service_counts:
                    service_counts[svc] = 0
                service_counts[svc] += 1
            
            most_common_service = max(service_counts.items(), key=lambda x: x[1])[0]
            same_srv_count = service_counts[most_common_service]
            dst_host_same_srv_rate = same_srv_count / len(services)
            dst_host_diff_srv_rate = 1.0 - dst_host_same_srv_rate
        else:
            dst_host_same_srv_rate = 1.0
            dst_host_diff_srv_rate = 0.0
        
        # Calculate same source port rate
        total_conns = len(host_stats['connections'])
        if total_conns > 0 and host_stats['src_ports']:
            # Count port occurrences
            port_counts = {}
            for conn_id in host_stats['connections']:
                port = conn_id[3]  # Source port
                if port not in port_counts:
                    port_counts[port] = 0
                port_counts[port] += 1
            
            most_common_port = max(port_counts.items(), key=lambda x: x[1])[0]
            same_port_count = port_counts[most_common_port]
            same_src_port_rate = same_port_count / total_conns
        else:
            same_src_port_rate = 1.0
        
        # Calculate error rates
        total_count = max(1, host_stats['count'])
        syn_error_rate = min(1.0, host_stats['syn_count'] / total_count)
        rej_error_rate = min(1.0, host_stats['error_count'] / total_count)
        
        # Calculate srv_diff_host_rate (connections to different hosts with same service)
        srv_diff_host_rate = 0.0
        
        return {
            'dst_host_count': dst_host_count,
            'dst_host_srv_count': dst_host_srv_count,
            'dst_host_same_srv_rate': dst_host_same_srv_rate,
            'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
            'dst_host_same_src_port_rate': same_src_port_rate,
            'dst_host_srv_diff_host_rate': srv_diff_host_rate,
            'dst_host_serror_rate': syn_error_rate,
            'dst_host_srv_serror_rate': syn_error_rate,
            'dst_host_rerror_rate': rej_error_rate,
            'dst_host_srv_rerror_rate': rej_error_rate
        }
    
    def extract_features(self, packet):
        """Extract features focusing on malformed packets, DDoS, and port scans"""
        if IP not in packet:
            return None
                
        # Update connection tracking and get stats
        conn_stats = self.update_connection_stats(packet)
        if not conn_stats:
            return None
        
        # Get protocol and service information
        protocol_type = self.get_protocol_type(packet)
        service = self.get_service(packet)
        flag = self.get_flag(packet)
        
        # Get source and destination IPs
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Check for malformed packets
        wrong_fragment = 0
        if TCP in packet:
            flags = packet[TCP].flags
            # Check for unusual flag combinations that indicate malformed packets
            if (flags & 0x3F) == 0x3F:  # All flags set (Christmas tree packet)
                wrong_fragment = 1
            elif (flags & 0x03) == 0x03:  # SYN+FIN (invalid)
                wrong_fragment = 1
            elif (flags & 0x06) == 0x06:  # SYN+RST (invalid)
                wrong_fragment = 1
        
        # Get connection features (traffic features)
        traffic_features = self.get_connection_features(conn_stats)
        
        # Get host-based statistics
        host_stats = self.get_host_stats(dst_ip)
        
        # Build the feature dictionary following NSL-KDD format
        features = {
            'duration': int(conn_stats['duration']),
            'protocol_type': protocol_type,
            'service': service,
            'flag': flag,
            'src_bytes': conn_stats['src_bytes'],
            'dst_bytes': conn_stats['dst_bytes'],
            'land': 1 if src_ip == dst_ip else 0,
            'wrong_fragment': wrong_fragment,  # Set based on malformed packet detection
            'urgent': 1 if (TCP in packet and packet[TCP].urgptr > 0) else 0,
            
            # Content features - simplified, focusing on relevant ones
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
        }
        
        # Add traffic features
        features.update(traffic_features)
        
        # Add host-based features
        features.update(host_stats)
        
        # For ICMP protocol - ensure proper service mapping for ML detection
        if protocol_type == 'icmp':
            # Ensure ICMP packets use ecr_i service to match NSL-KDD 
            features['service'] = 'ecr_i'
        
        return features

# Global instance
feature_extractor = FeatureExtractor()