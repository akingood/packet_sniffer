import streamlit as st
import pandas as pd
import json
from datetime import datetime
from collections import defaultdict
import math

st.title("Packet Flow Analyzer")
st.write("Upload a JSON file with captured packet details to compute flow-based statistics and metrics.")

# Shannon entropy function for payloads
def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p = data.count(x) / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 4)

# File uploader
uploaded_file = st.file_uploader("Upload Packet JSON", type=["json"])

if uploaded_file is not None:
    # Load JSON data
    data = json.load(uploaded_file)

    # Convert timestamp to datetime
    for pkt in data:
        pkt["timestamp"] = datetime.strptime(pkt["timestamp"], "%Y-%m-%d %H:%M:%S")

    # Show raw packets
    with st.expander("Show Raw Packet Data"):
        st.json(data[:20])  # Show first 20 packets

    # Group by 5-tuple
    flows = defaultdict(list)
    for pkt in data:
        key = (pkt["source_ip"], pkt["destination_ip"], pkt["source_port"], pkt["destination_port"], pkt["protocol"])
        flows[key].append(pkt)

    flow_stats = []

    for key, pkts in flows.items():
        pkts.sort(key=lambda x: x["timestamp"])
        times = [p["timestamp"] for p in pkts]
        lengths = [p["packet_length"] for p in pkts]

        # Statistical features
        mean_size = sum(lengths) / len(lengths)
        variance = sum((x - mean_size) ** 2 for x in lengths) / len(lengths)
        std_dev = variance ** 0.5

        # Flow duration
        duration = (times[-1] - times[0]).total_seconds() if len(times) > 1 else 0

        # Total bytes
        bytes_total = sum(lengths)

        # Inter-arrival times
        iat = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
        mean_iat = sum(iat) / len(iat) if iat else 0
        std_iat = (sum((x - mean_iat) ** 2 for x in iat) / len(iat)) ** 0.5 if iat else 0

        # Payload entropy (simulate payload here, real capture needs payload extraction)
        entropy = shannon_entropy(str(pkts))

        # Incoming vs Outgoing Ratio (based on first packet src/dst)
        src_ip, dst_ip = key[0], key[1]
        incoming = len([p for p in pkts if p["source_ip"] == dst_ip])
        outgoing = len(pkts) - incoming
        io_ratio = round(outgoing / incoming, 4) if incoming > 0 else float('inf')

        flow_stats.append({
            "flow": f"{key[0]}->{key[1]} ({key[4]})",
            "packet_count": len(pkts),
            "mean_packet_size": round(mean_size, 2),
            "std_dev_size": round(std_dev, 2),
            "variance_size": round(variance, 2),
            "flow_duration_sec": round(duration, 4),
            "total_bytes": bytes_total,
            "mean_iat_sec": round(mean_iat, 4),
            "std_iat_sec": round(std_iat, 4),
            "entropy": entropy,
            "incoming_packets": incoming,
            "outgoing_packets": outgoing,
            "io_ratio": io_ratio
        })

    # Convert to DataFrame
    df = pd.DataFrame(flow_stats)

    st.subheader("Flow Statistics")
    st.dataframe(df)

    # Top N Flows by bytes and packet count
    top_n = st.slider("Select Top N Flows to Display", min_value=1, max_value=10, value=5)
    st.write(f"### Top {top_n} Flows by Total Bytes")
    st.dataframe(df.sort_values("total_bytes", ascending=False).head(top_n))

    st.write(f"### Top {top_n} Flows by Packet Count")
    st.dataframe(df.sort_values("packet_count", ascending=False).head(top_n))

    # Download CSV
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="Download Flow Stats as CSV",
        data=csv,
        file_name="flow_stats.csv",
        mime="text/csv"
    )
