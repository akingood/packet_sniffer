import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import json

st.title("Network Packet Scanner")

# Protocol map for readability
proto_map = {
    0: "HOPOPT",      # IPv6 Hop-by-Hop Option
    1: "ICMP",        # Internet Control Message Protocol
    2: "IGMP",        # Internet Group Management Protocol
    3: "GGP",         # Gateway-to-Gateway Protocol
    4: "IP-in-IP",    # IP in IP (encapsulation)
    5: "ST",          # Stream
    6: "TCP",         # Transmission Control Protocol
    7: "CBT",         # Core-Based Trees
    8: "EGP",         # Exterior Gateway Protocol
    9: "IGP",         # Interior Gateway Protocol
    17: "UDP",        # User Datagram Protocol
    20: "HMP",        # Host Monitoring Protocol
    22: "XNS-IDP",    # Xerox NS IDP
    27: "RDP",        # Reliable Data Protocol
    29: "ISO-TP4",    # ISO Transport Protocol Class 4
    41: "IPv6",       # IPv6 encapsulation
    43: "IPv6-Route", # Routing Header for IPv6
    44: "IPv6-Frag",  # Fragment Header for IPv6
    46: "RSVP",       # Reservation Protocol
    47: "GRE",        # General Routing Encapsulation
    50: "ESP",        # Encapsulating Security Payload
    51: "AH",         # Authentication Header
    58: "IPv6-ICMP",  # ICMP for IPv6
    59: "IPv6-NoNxt", # No Next Header for IPv6
    60: "IPv6-Opts",  # Destination Options for IPv6
    88: "EIGRP",      # Enhanced Interior Gateway Routing Protocol
    89: "OSPF",       # Open Shortest Path First
    94: "IPIP",       # IP-within-IP Encapsulation Protocol
    103: "PIM",       # Protocol Independent Multicast
    112: "VRRP",      # Virtual Router Redundancy Protocol
    115: "L2TP",      # Layer Two Tunneling Protocol
    132: "SCTP",      # Stream Control Transmission Protocol
    135: "MOBIKE",    # IKEv2 Mobility and Multihoming
    136: "UDPLite",   # Lightweight User Datagram Protocol
    137: "MPLS-in-IP",# MPLS in IP
    138: "MANET",     # MANET Protocols
    139: "HIP",       # Host Identity Protocol
    140: "Shim6",     # Site Multihoming by IPv6 Intermediation
    255: "Reserved"   # Reserved
}

# Function to extract detailed features from packets
def extract_packet_info(packet):
    data = {
        "timestamp": datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "packet_length": len(packet),
        "ttl": None,
        "flags": None,
        "window_size": None,
        "header_length": None
    }

    if IP in packet:
        data["source_ip"] = packet[IP].src
        data["destination_ip"] = packet[IP].dst
        data["ttl"] = packet[IP].ttl
        data["header_length"] = packet[IP].ihl
        proto_num = packet[IP].proto
        data["protocol"] = proto_map.get(proto_num, str(proto_num))

    if TCP in packet:
        data["source_port"] = packet[TCP].sport
        data["destination_port"] = packet[TCP].dport
        data["flags"] = str(packet[TCP].flags)
        data["window_size"] = packet[TCP].window
        data["header_length"] = packet[TCP].dataofs

    if UDP in packet:
        data["source_port"] = packet[UDP].sport
        data["destination_port"] = packet[UDP].dport

    return data

# Function to capture packets
def capture_packets(duration=10):
    packets = sniff(timeout=duration)
    return [extract_packet_info(pkt) for pkt in packets]

# User input for duration
duration = st.number_input("Enter capture duration (in seconds):", min_value=1, value=15)

# Start scanning
if st.button("Start Scan"):
    st.info(f"Capturing packets for {duration} seconds... Please wait...")
    packet_list = capture_packets(duration)
    
    st.success(f"Capture completed! Captured {len(packet_list)} packets.")

    if packet_list:
        df = pd.DataFrame(packet_list)
        st.dataframe(df)

        # Download JSON
        st.download_button(
            label="Download JSON",
            data=json.dumps(packet_list, indent=4),
            file_name="packets.json",
            mime="application/json"
        )
