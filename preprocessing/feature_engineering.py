
import numpy as np


FEATURE_ORDER = [
    "duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "avg_packet_size",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ratio",
    "rst_ratio",
    "dst_port",
]


def compute_derived_features(flow):
 
    flow = dict(flow)  

    duration  = max(flow.get("duration", 0.001), 0.001)
    pkt_count = max(flow.get("packet_count", 1), 1)

    flow["packets_per_second"] = flow["packet_count"] / duration
    flow["bytes_per_second"]   = flow["byte_count"] / duration
    flow["avg_packet_size"]    = flow["byte_count"] / pkt_count
    flow["syn_ratio"]          = flow.get("syn_count", 0) / pkt_count
    flow["rst_ratio"]          = flow.get("rst_count", 0) / pkt_count

    return flow


def flow_to_feature_vector(flow, scaler):
   
    if "syn_ratio" not in flow:
        flow = compute_derived_features(flow)

    # build vector in exact training order
    vector = np.array(
        [[flow.get(f, 0.0) for f in FEATURE_ORDER]],
        dtype=np.float64
    )

    # scale using training-time scaler
    vector_scaled = scaler.transform(vector)

    return vector_scaled


def validate_flow_features(flow):
  
    missing = [f for f in FEATURE_ORDER if f not in flow]
    if missing:
        print(f"[!] WARNING: flow missing features: {missing}")
        return False
    return True
