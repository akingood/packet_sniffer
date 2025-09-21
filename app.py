import streamlit as st

# Set page config
st.set_page_config(page_title="Packet Sniffer", page_icon="🌐", layout="wide")

# Home Page content
st.title("🏠 Home")
st.write("Packet Analysis and Anomaly Detection App")
st.write("""
        - Scan the packets in the **scanner page**,
        - Analyze them in the **analyze page**, and
        - Visualize results in the **display page**.
        """)
