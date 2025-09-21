import streamlit as st

st.title("Overview")
st.write("""
         This project is an interactive Streamlit-based application designed to:

        - Capture live network packets using Scapy.

        - Analyze packet-level and flow-level features.

        - Detect anomalies or potential malicious traffic using a Hybrid Autoencoder model that combines:

            - Flow-level statistical features (from CSV).

            - Packet-level sequential features (from JSON).

        - Visualize network traffic patterns using interactive charts and heatmaps.

""")

st.title("Core Features")
st.write("""
        1. Packet Capture
         
            - Captures real-time packets from the local network interface.

            - Extracts features like:

                - timestamp, source_ip, destination_ip

                - protocol, TTL, flags, window_size

            - Stores packet details as JSON for further analysis.

        2. Flow-Level Analysis
            
            - Upload captured packet JSON.

            - Groups packets by 5-tuple (srcIP, dstIP, srcPort, dstPort, protocol).

            - Computes:

                - Mean/Variance of Packet Sizes

                - Flow Duration

                - Packet Inter-arrival Time (IAT)

                - Entropy of payload

                - Incoming vs Outgoing ratio

            - Exports results as CSV.

        3. Hybrid Anomaly Detection
            
            - Accepts:

                - Flow Stats (CSV) → Aggregated flow-level features.

                - Packet Data (JSON) → Raw packet sequences.

            - Uses Hybrid Deep Learning Autoencoder:

                - Dense layers for flow features.

                - LSTM layers for packet sequences.

                - Learns normal traffic patterns and flags anomalies based on reconstruction error.

            - Outputs:

                - Benign vs Anomalous flows

                - Reconstruction error distribution

        4. Network Traffic Visualization
            
            - Incoming & Outgoing IP distributions.

            - Protocol usage breakdown (Pie Chart).

            - Packets over time (Altair interactive chart).

            - Traffic heatmap (Source vs Destination IP).
         """)