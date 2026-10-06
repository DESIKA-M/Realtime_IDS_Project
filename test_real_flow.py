from scapy.all import IP, TCP
from cicflowmeter.flow import Flow
from cicflowmeter.features.context import PacketDirection
import joblib
import numpy as np

# Load model artifacts
model = joblib.load("model_artifacts/best_model.pkl")
scaler = joblib.load("model_artifacts/scaler.pkl")
label_encoder = joblib.load("model_artifacts/label_encoder.pkl")
feature_columns = joblib.load("model_artifacts/feature_columns.pkl")


# Create two packets belonging to the same flow
p1 = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(
    sport=50000, dport=22, flags="S", window=64240
)

p2 = IP(src="192.168.1.20", dst="192.168.1.10") / TCP(
    sport=22, dport=50000, flags="SA", window=28960
)

# Give packets timestamps
p1.time = 1000.000000
p2.time = 1000.000166

# Create flow
flow = Flow(p1, PacketDirection.FORWARD)

# Add second packet in reverse direction
flow.add_packet(p2, PacketDirection.REVERSE)

# Get CICFlowMeter features
data = flow.get_data()

print("CICFlowMeter output:")
for key, value in data.items():
    print(f"{key}: {value}")

print("\nCreating model vector...")

# Mapping CICFlowMeter → model features
mapping = {
    "Destination Port": data["dst_port"],
    "Flow Duration": data["flow_duration"] * 1_000_000,

    "Total Fwd Packets": data["tot_fwd_pkts"],
    "Total Backward Packets": data["tot_bwd_pkts"],

    "Total Length of Fwd Packets": data["totlen_fwd_pkts"],
    "Total Length of Bwd Packets": data["totlen_bwd_pkts"],

    "Fwd Packet Length Max": data["fwd_pkt_len_max"],
    "Fwd Packet Length Min": data["fwd_pkt_len_min"],
    "Fwd Packet Length Mean": data["fwd_pkt_len_mean"],
    "Fwd Packet Length Std": data["fwd_pkt_len_std"],

    "Bwd Packet Length Max": data["bwd_pkt_len_max"],
    "Bwd Packet Length Min": data["bwd_pkt_len_min"],
    "Bwd Packet Length Mean": data["bwd_pkt_len_mean"],
    "Bwd Packet Length Std": data["bwd_pkt_len_std"],

    "Flow Bytes/s": data["flow_byts_s"] / 1_000_000,
    "Flow Packets/s": data["flow_pkts_s"] / 1_000_000,

    "Flow IAT Mean": data["flow_iat_mean"] * 1_000_000,
    "Flow IAT Std": data["flow_iat_std"] * 1_000_000,
    "Flow IAT Max": data["flow_iat_max"] * 1_000_000,
    "Flow IAT Min": data["flow_iat_min"] * 1_000_000,

    "Fwd IAT Total": data["fwd_iat_tot"] * 1_000_000,
    "Fwd IAT Mean": data["fwd_iat_mean"] * 1_000_000,
    "Fwd IAT Std": data["fwd_iat_std"] * 1_000_000,
    "Fwd IAT Max": data["fwd_iat_max"] * 1_000_000,
    "Fwd IAT Min": data["fwd_iat_min"] * 1_000_000,

    "Bwd IAT Total": data["bwd_iat_tot"] * 1_000_000,
    "Bwd IAT Mean": data["bwd_iat_mean"] * 1_000_000,
    "Bwd IAT Std": data["bwd_iat_std"] * 1_000_000,
    "Bwd IAT Max": data["bwd_iat_max"] * 1_000_000,
    "Bwd IAT Min": data["bwd_iat_min"] * 1_000_000,

    "Fwd PSH Flags": data["fwd_psh_flags"],
    "Fwd URG Flags": data["fwd_urg_flags"],

    "Fwd Header Length": data["fwd_header_len"],
    "Bwd Header Length": data["bwd_header_len"],

    "Fwd Packets/s": data["fwd_pkts_s"] / 1_000_000,
    "Bwd Packets/s": data["bwd_pkts_s"] / 1_000_000,

    "Min Packet Length": data["pkt_len_min"],
    "Max Packet Length": data["pkt_len_max"],
    "Packet Length Mean": data["pkt_len_mean"],
    "Packet Length Std": data["pkt_len_std"],
    "Packet Length Variance": data["pkt_len_var"],

    "FIN Flag Count": data["fin_flag_cnt"],
    "SYN Flag Count": data["syn_flag_cnt"],
    "RST Flag Count": data["rst_flag_cnt"],
    "PSH Flag Count": data["psh_flag_cnt"],
    "ACK Flag Count": data["ack_flag_cnt"],
    "URG Flag Count": data["urg_flag_cnt"],

    # CWR → CICIDS2017 "CWE Flag Count"
    "CWE Flag Count": data.get("cwr_flag_count", 0),

    "ECE Flag Count": data["ece_flag_cnt"],

    "Down/Up Ratio": data["down_up_ratio"],
    "Average Packet Size": data["pkt_size_avg"],

    "Avg Fwd Segment Size": data["fwd_seg_size_avg"],
    "Avg Bwd Segment Size": data["bwd_seg_size_avg"],

    "Subflow Fwd Packets": data["subflow_fwd_pkts"],
    "Subflow Fwd Bytes": data["subflow_fwd_byts"],
    "Subflow Bwd Packets": data["subflow_bwd_pkts"],
    "Subflow Bwd Bytes": data["subflow_bwd_byts"],

    "Init_Win_bytes_forward": data["init_fwd_win_byts"],
    "Init_Win_bytes_backward": data["init_bwd_win_byts"],

    "act_data_pkt_fwd": data["fwd_act_data_pkts"],
    "min_seg_size_forward": data["fwd_seg_size_min"],

    "Active Mean": data["active_mean"] * 1_000_000,
    "Active Std": data["active_std"] * 1_000_000,
    "Active Max": data["active_max"] * 1_000_000,
    "Active Min": data["active_min"] * 1_000_000,

    "Idle Mean": data["idle_mean"] * 1_000_000,
    "Idle Std": data["idle_std"] * 1_000_000,
    "Idle Max": data["idle_max"] * 1_000_000,
    "Idle Min": data["idle_min"] * 1_000_000,
}


# Check all 69 features exist
missing = [f for f in feature_columns if f not in mapping]

print("\nMissing model features:", missing)

# Exact training order
X = np.array([[mapping[f] for f in feature_columns]], dtype=float)

print("Model input shape:", X.shape)

# Scale
X_scaled = scaler.transform(X)

# Predict
prediction = model.predict(X_scaled)
label = label_encoder.inverse_transform(prediction)

print("\nPrediction:", prediction[0])
print("Label:", label[0])
