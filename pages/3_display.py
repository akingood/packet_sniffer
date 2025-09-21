import streamlit as st
import pandas as pd
import numpy as np
import json
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, LSTM, RepeatVector, concatenate
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.preprocessing.sequence import pad_sequences
import matplotlib.pyplot as plt
import seaborn as sns

st.title("Anomaly Detection & Network Traffic Analysis")

# File upload
flow_file = st.file_uploader("Upload Flow Stats CSV", type=["csv"])
packet_file = st.file_uploader("Upload Packet JSON", type=["json"])

if flow_file and packet_file:
    # Load data
    flow_df = pd.read_csv(flow_file)
    packets = json.load(packet_file)

    st.subheader("✅ Data Preview")
    st.write("Flow Stats:")
    st.dataframe(flow_df.head())

    # Replace inf and NaN
    flow_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    flow_df.fillna(0, inplace=True)

    # Drop non-numeric and label if present
    if 'flow' in flow_df.columns:
        flow_features = flow_df.drop(['flow'], axis=1)
    else:
        flow_features = flow_df

    # Normalize flow features
    scaler = StandardScaler()
    flow_data_scaled = scaler.fit_transform(flow_features)

    # Convert packets.json to sequences grouped by flow
    packet_groups = {}
    for pkt in packets:
        flow_key = f"{pkt.get('source_ip')}_{pkt.get('destination_ip')}_{pkt.get('protocol')}"
        if flow_key not in packet_groups:
            packet_groups[flow_key] = []
        packet_groups[flow_key].append([
            pkt.get('packet_length', 0),
            pkt.get('ttl', 0),
            pkt.get('window_size', 0)
        ])

    # Pad sequences to fixed length
    sequences = list(packet_groups.values())
    max_len = max(len(seq) for seq in sequences)
    packet_data_padded = pad_sequences(sequences, maxlen=max_len, padding='post', dtype='float32')

    # Align flow & packet data
    min_len = min(flow_data_scaled.shape[0], packet_data_padded.shape[0])
    flow_data_scaled = flow_data_scaled[:min_len]
    packet_data_padded = packet_data_padded[:min_len]

    # Validate dataset size
    if min_len < 10:
        st.warning("⚠️ Dataset is too small for meaningful anomaly detection. Results may not be accurate.")

    # Build Hybrid Autoencoder
    flow_input = Input(shape=(flow_data_scaled.shape[1],))
    x_flow = Dense(64, activation='relu')(flow_input)
    x_flow = Dense(32, activation='relu')(x_flow)

    packet_input = Input(shape=(packet_data_padded.shape[1], packet_data_padded.shape[2]))
    x_packet = LSTM(64)(packet_input)
    x_packet = Dense(32, activation='relu')(x_packet)

    merged = concatenate([x_flow, x_packet])
    encoded = Dense(32, activation='relu')(merged)

    decoded_flow = Dense(flow_data_scaled.shape[1], activation='linear')(encoded)
    decoded_packet = RepeatVector(packet_data_padded.shape[1])(encoded)
    decoded_packet = LSTM(64, return_sequences=True)(decoded_packet)
    decoded_packet = Dense(packet_data_padded.shape[2], activation='linear')(decoded_packet)

    model = Model(inputs=[flow_input, packet_input], outputs=[decoded_flow, decoded_packet])
    model.compile(optimizer=Adam(0.001), loss='mse')

    with st.expander("Model Summary"):
        model.summary(print_fn=st.text)

    # Train model
    st.info("Training Autoencoder on benign data...")
    with st.spinner("Training in progress..."):
        model.fit([flow_data_scaled, packet_data_padded],
                  [flow_data_scaled, packet_data_padded],
                  epochs=50, batch_size=8, verbose=0)
    st.success("✅ Training complete!")

    # Compute reconstruction errors
    reconstructed = model.predict([flow_data_scaled, packet_data_padded])
    flow_recon, packet_recon = reconstructed

    flow_errors = np.mean(np.square(flow_data_scaled - flow_recon), axis=1)
    packet_errors = np.mean(np.square(packet_data_padded - packet_recon), axis=(1, 2))
    total_error = flow_errors + packet_errors

    # Handle NaNs
    total_error = np.nan_to_num(total_error, nan=0.0, posinf=0.0, neginf=0.0)

    threshold = np.mean(total_error) + 3 * np.std(total_error)
    predictions = (total_error > threshold).astype(int)

    # Display anomaly results
    st.subheader("📊 Anomaly Detection Results")
    result_df = pd.DataFrame({
        "flow_index": range(len(predictions)),
        "reconstruction_error": total_error,
        "predicted_label": predictions
    })
    st.dataframe(result_df)

    benign_count = sum(predictions == 0)
    anomaly_count = sum(predictions == 1)
    st.write(f"✅ Benign: {benign_count}, 🚨 Anomalous: {anomaly_count}")

    # Download results
    st.download_button(
        label="Download Anomaly Results",
        data=result_df.to_csv(index=False).encode('utf-8'),
        file_name="anomaly_results.csv",
        mime="text/csv"
    )

    # Histogram of reconstruction error
    valid_errors = total_error[np.isfinite(total_error) & (total_error > 0)]
    if len(valid_errors) == 0:
        st.warning("No valid reconstruction errors to plot.")
    else:
        st.subheader("📈 Reconstruction Error Distribution")
        fig, ax = plt.subplots()
        ax.hist(valid_errors, bins=50)
        ax.axvline(threshold, color='red', linestyle='dashed', label='Threshold')
        ax.legend()
        st.pyplot(fig)

    # ================= Additional Visualizations =====================
    st.subheader("📊 Network Traffic Analysis")

    packet_df = pd.DataFrame(packets)
    packet_df['timestamp'] = pd.to_datetime(packet_df['timestamp'], errors='coerce')

    # Incoming IP distribution
    st.write("### 🔹 Top Incoming IP Addresses")
    incoming_counts = packet_df['destination_ip'].value_counts().head(10)
    st.bar_chart(incoming_counts)

    # Outgoing IP distribution
    st.write("### 🔹 Top Outgoing IP Addresses")
    outgoing_counts = packet_df['source_ip'].value_counts().head(10)
    st.bar_chart(outgoing_counts)

    # Protocol usage distribution (Pie Chart)
    st.write("### 🔹 Protocol Usage")
    protocol_counts = packet_df['protocol'].value_counts()
    fig_pie, ax_pie = plt.subplots()
    ax_pie.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', startangle=140)
    ax_pie.set_title("Protocol Distribution")
    st.pyplot(fig_pie)

    # Packets over time
    st.write("### 🔹 Packets Over Time")
    if not packet_df['timestamp'].isnull().all():
        packets_over_time = packet_df.groupby(packet_df['timestamp'].dt.floor('s')).size()
        st.line_chart(packets_over_time)
    else:
        st.warning("Timestamps are invalid or missing in packet data.")

    # Heatmap: Source IP vs Destination IP
    st.write("### 🔹 Traffic Heatmap (Source vs Destination)")
    heatmap_data = packet_df.groupby(['source_ip', 'destination_ip']).size().unstack(fill_value=0)
    fig_heat, ax_heat = plt.subplots(figsize=(8, 6))
    sns.heatmap(heatmap_data, cmap="Blues", linewidths=0.5, ax=ax_heat)
    st.pyplot(fig_heat)
    