from scapy.all import sniff, IP, TCP, UDP
from cicflowmeter.flow import Flow
from cicflowmeter.features.context import PacketDirection
from collections import defaultdict
from datetime import datetime
import time
import json
from kafka import KafkaProducer
import uuid
from pathlib import Path

FLOW_DIR = Path("input")
FLOW_DIR.mkdir(exist_ok=True)

producer = KafkaProducer(
    bootstrap_servers=["localhost:9092"],
    value_serializer=lambda value: json.dumps(value).encode("utf-8")
)

def send_flow_to_spark(features):
    producer.send("network-flows", value=features).get(timeout=10)
    print("Flow sent to Kafka: network-flows")
# ============================================================
# CONFIGURATION
# ============================================================

INTERFACE = "ens33"

# Finalize a flow after this many seconds without packets
IDLE_TIMEOUT = 5

# Maximum time a flow remains active
ACTIVE_TIMEOUT = 60

# ============================================================
# FLOW STORAGE
# ============================================================

flows = {}

# ============================================================
# FLOW IDENTIFICATION
# ============================================================

def get_flow_key(packet):

    if IP not in packet:
        return None

    ip = packet[IP]

    protocol = ip.proto

    src_ip = ip.src
    dst_ip = ip.dst

    src_port = 0
    dst_port = 0

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    source = (src_ip, src_port)
    destination = (dst_ip, dst_port)

    # Canonical key allows reverse-direction packets
    # to belong to the same bidirectional flow.
    endpoints = tuple(sorted([source, destination]))

    return (endpoints[0], endpoints[1], protocol), source, destination


# ============================================================
# CREATE NEW FLOW
# ============================================================

def create_flow(packet, source, destination):

    now = float(packet.time)

    return {
        "start_time": now,
        "last_seen": now,
        "packets": [],
        "src_ip": source[0],
        "src_port": source[1],

        "dst_ip": destination[0],
        "dst_port": destination[1],

        "protocol": packet[IP].proto,

        "fwd_packets": 0,
        "bwd_packets": 0,

        "fwd_bytes": 0,
        "bwd_bytes": 0,

        "fwd_lengths": [],
        "bwd_lengths": [],

        "syn_count": 0,
        "fin_count": 0,
        "rst_count": 0,

        "packet_count": 0
    }


# ============================================================
# UPDATE FLOW WITH PACKET
# ============================================================

def update_flow(flow, packet):

    now = float(packet.time)
    flow["packets"].append(packet)
    ip = packet[IP]
    packet_length = len(ip)
    source = (ip.src, 0)
    destination = (ip.dst, 0)

    if TCP in packet:
        source = (ip.src, packet[TCP].sport)
        destination = (ip.dst, packet[TCP].dport)

    elif UDP in packet:
        source = (ip.src, packet[UDP].sport)
        destination = (ip.dst, packet[UDP].dport)

    # First packet's direction defines forward direction
    forward = (
        source == (flow["src_ip"], flow["src_port"])
        and destination == (flow["dst_ip"], flow["dst_port"])
    )

    if forward:
        flow["fwd_packets"] += 1
        flow["fwd_bytes"] += packet_length
        flow["fwd_lengths"].append(packet_length)
    else:
        flow["bwd_packets"] += 1
        flow["bwd_bytes"] += packet_length
        flow["bwd_lengths"].append(packet_length)

    flow["packet_count"] += 1
    flow["last_seen"] = now

    if TCP in packet:
        flags = int(packet[TCP].flags)

        # TCP flag values:
        # FIN = 0x01, RST = 0x04, SYN = 0x02
        if flags & 0x02:
            flow["syn_count"] += 1

        if flags & 0x01:
            flow["fin_count"] += 1

        if flags & 0x04:
            flow["rst_count"] += 1


# ============================================================
# FEATURE EXTRACTION
# ============================================================

def safe_mean(values):
    return sum(values) / len(values) if values else 0


def safe_std(values):
    if not values:
        return 0

    mean = safe_mean(values)

    variance = sum((x - mean) ** 2 for x in values) / len(values)

    return variance ** 0.5

def build_cicflowmeter_flow(flow):

    packets = flow["packets"]

    if not packets:
        return None

    first_packet = packets[0]

    source = (flow["src_ip"], flow["src_port"])
    destination = (flow["dst_ip"], flow["dst_port"])

    cic_flow = Flow(first_packet, PacketDirection.FORWARD)

    for packet in packets[1:]:

        ip = packet[IP]

        if TCP in packet:
            packet_source = (ip.src, packet[TCP].sport)
            packet_destination = (ip.dst, packet[TCP].dport)

        elif UDP in packet:
            packet_source = (ip.src, packet[UDP].sport)
            packet_destination = (ip.dst, packet[UDP].dport)

        else:
            packet_source = (ip.src, 0)
            packet_destination = (ip.dst, 0)

        if (
            packet_source == source
            and packet_destination == destination
        ):
            direction = PacketDirection.FORWARD
        else:
            direction = PacketDirection.REVERSE

        cic_flow.add_packet(packet, direction)

    return cic_flow

def extract_features(flow):

    cic_flow = build_cicflowmeter_flow(flow)

    if cic_flow is None:
        return None

    data = cic_flow.get_data()

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

        "Flow Bytes/s": data["flow_byts_s"],
        "Flow Packets/s": data["flow_pkts_s"],

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

        "Fwd Packets/s": data["fwd_pkts_s"],
        "Bwd Packets/s": data["bwd_pkts_s"],

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

    # Calculate CWR directly from the captured packets.
    cwr_count = 0

    for packet in flow["packets"]:
        if TCP in packet and "C" in packet.sprintf("%TCP.flags%"):
            cwr_count += 1

    mapping["CWE Flag Count"] = cwr_count

    return mapping

# ============================================================
# FINALIZE FLOW
# ============================================================

def finalize_flow(key):

    flow = flows.pop(key, None)

    if flow is None:
        return

    features = extract_features(flow)
    send_flow_to_spark(features)

    print("\n" + "=" * 60)
    print("COMPLETED FLOW")
    print("=" * 60)

    print("Time:", datetime.fromtimestamp(flow["last_seen"]))
    print(
        f'{flow["src_ip"]}:{flow["src_port"]} '
        f'-> {flow["dst_ip"]}:{flow["dst_port"]}'
    )

    print("Protocol:", flow["protocol"])
    print("Duration:", features["Flow Duration"], "microseconds")
    print("Forward packets:", features["Total Fwd Packets"])
    print("Backward packets:", features["Total Backward Packets"])
    print("Forward bytes:", features["Total Length of Fwd Packets"])
    print("Backward bytes:", features["Total Length of Bwd Packets"])

    print("Prediction: handled by Spark")

    print("\nFeature row:")
    print(json.dumps(features, indent=2))


# ============================================================
# PACKET CALLBACK
# ============================================================

def process_packet(packet):

    if IP not in packet:
        return

    result = get_flow_key(packet)

    if result is None:
        return

    key, source, destination = result

    now = float(packet.time)

    # Expire old flows
    expired_keys = []

    for flow_key, flow in flows.items():

        idle_time = now - flow["last_seen"]
        active_time = now - flow["start_time"]

        if idle_time >= IDLE_TIMEOUT or active_time >= ACTIVE_TIMEOUT:
            expired_keys.append(flow_key)

    for flow_key in expired_keys:
        finalize_flow(flow_key)

    # Create flow if needed
    if key not in flows:
        flows[key] = create_flow(packet, source, destination)

    flow = flows[key]

    update_flow(flow, packet)

    # Close TCP flow on FIN or RST
    if TCP in packet:
        flags = int(packet[TCP].flags)

        if flags & 0x01 or flags & 0x04:
            finalize_flow(key)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("====================================")
    print(" REAL-TIME NETWORK FLOW MONITOR")
    print("====================================")
    print("Interface:", INTERFACE)
    print("Idle timeout:", IDLE_TIMEOUT, "seconds")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\nStopping capture...")

        # Finalize remaining flows
        for key in list(flows.keys()):
            finalize_flow(key)

        print("Capture stopped.")