
# 🌐 Network Traffic Analyzer & Anomaly Detection

## ✅ **Overview**

This project is a **Streamlit-based web application** for **network packet analysis** and **anomaly detection**.
It captures real-time packets, extracts both **packet-level** and **flow-level features**, and detects anomalies using a **Hybrid Autoencoder model** that combines:

* Flow-level aggregated statistics (CSV).
* Packet-level sequences (JSON).

The app also provides **interactive visualizations** of network traffic patterns.

---

## 🚀 **Features**

✔ **Packet Capture** (Live sniffing using Scapy)
✔ **Flow-Level Statistics** (packet size, duration, IAT, entropy, etc.)
✔ **Hybrid Anomaly Detection** using TensorFlow/Keras
✔ **Interactive Traffic Visualizations**:

* Incoming & Outgoing IP Distribution
* Protocol Usage Pie Chart
* Packets Over Time (Altair)
* Heatmap of Source vs Destination IP

---

## 🛠 **Tech Stack**

* **Frontend/UI**: [Streamlit](https://streamlit.io/)
* **Packet Capture**: Scapy
* **Data Processing**: Pandas, NumPy
* **Machine Learning**:

  * Scikit-learn (Baseline)
  * TensorFlow/Keras (Hybrid Autoencoder)
* **Visualization**: Altair, Matplotlib, Seaborn

---

## 📂 **Project Structure**

```
packet_analyzer/
│
├── app.py                     # Main Streamlit app (Home page)
├── pages/
│   ├── 1_scanner.py           # Packet capture and JSON export
│   ├── 2_analyze.py           # Flow statistics calculation and CSV export
│   ├── 3_display.py           # Anomaly detection + traffic visualization
│
├── requirements.txt           # Python dependencies
└── README.md                  # Project documentation
```

---

## ⚡ **Installation**

### ✅ 1. Clone the repository

```bash
git clone 
cd packet-analyzer
```

### ✅ 2. Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate   # For Linux/Mac
venv\Scripts\activate      # For Windows
```

### ✅ 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶ **Run the Application**

```bash
streamlit run app.py
```

The app will open in your browser at:

```
http://localhost:8501
```

---

## 🧩 **How to Use**

### **1. Packet Capture**

* Navigate to **"🔍 Network Packet Scanner"**.
* Enter capture duration and click **Start Scan**.
* Download the captured packets as **packets.json**.

### **2. Flow Analysis**

* Go to **"📊 Packet Flow Analyzer"**.
* Upload `packets.json`.
* Analyze flow-level statistics and **download flow\_stats.csv**.

### **3. Hybrid Anomaly Detection**

* Navigate to **"🔍 Hybrid Anomaly Detection"**.
* Upload both `flow_stats.csv` and `packets.json`.
* View:

  * Anomaly detection results
  * Reconstruction error distribution
  * Traffic insights (IP distribution, protocol usage, timeline, heatmap)

---

## 📈 **Visualizations**

* ✅ Incoming & Outgoing IP frequency
* ✅ Protocol usage breakdown (Pie chart)
* ✅ Packets per second timeline (Altair)
* ✅ Heatmap of Source vs Destination IP

---

## 📦 **Requirements**

See [requirements.txt](./requirements.txt) or install using:

```bash
pip install -r requirements.txt
```

---
