import pandas as pd
import numpy as np
from scapy.all import rdpcap
from ml.feature_extractor import FeatureExtractor
import os
import argparse

def convert_pcap_to_nslkdd(pcap_file, output_csv):
    """Convert a PCAP file to NSL-KDD format"""
    print(f"Converting {pcap_file} to NSL-KDD format...")
    
    # Read packets
    try:
        packets = rdpcap(pcap_file)
        print(f"Loaded {len(packets)} packets")
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return
    
    # Initialize feature extractor
    extractor = FeatureExtractor()
    
    # Extract features for each packet
    features_list = []
    for i, packet in enumerate(packets):
        if i % 100 == 0:
            print(f"Processing packet {i}/{len(packets)}")
            
        features = extractor.extract_features(packet)
        if features:
            features_list.append(features)
    
    # Create DataFrame 
    if features_list:
        df = pd.DataFrame(features_list)
        
        df['class'] = 'normal'
        
        # Save to CSV
        df.to_csv(output_csv, index=False)
        print(f"Saved {len(df)} records to {output_csv}")
    else:
        print("No valid features extracted")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert PCAP to NSL-KDD format")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--output", "-o", default="nslkdd_features.csv", help="Output CSV file")
    args = parser.parse_args()
    
    convert_pcap_to_nslkdd(args.pcap_file, args.output)