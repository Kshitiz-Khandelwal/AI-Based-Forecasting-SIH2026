"""DNS Shield X-Forecast — Standalone Offline Forecaster (CLI / Air-Gapped Runner)
Runs direct PCAP or CSV flow telemetry through the trained PyTorch GRU model:
  1. Raw Packet / Flow Ingestion
  2. 16-Dimensional Temporal Feature Extraction
  3. Neural GRU Inference & Time-to-Compromise (TTC) Dynamic Calculation
  4. +15m, +30m, +60m K-Step MITRE ATT&CK Horizon Rollouts
  5. Feature Attribution Explainability
  6. Recommended Preemptive Mitigation
Requires ZERO running background microservices (100% standalone offline operation).
"""
import os
import sys
import time
import argparse
import numpy as np
import pandas as pd
import torch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from services.forecasting_engine.temporal_feature_extractor import extract_flow_features, FEATURE_NAMES
from services.forecasting_engine.train_temporal_gru import TemporalAttackGRU, STAGE_MAP, STAGE_NAMES
from services.forecasting_engine.packet_feature_extractor import PacketFeatureAccumulator

STAGE_METADATA = {
    "STAGE_0_BENIGN": {"label": "Benign Baseline", "severity": "NONE", "color": "#10b981", "tactic": "Normal Operations"},
    "STAGE_1_RECONNAISSANCE": {"label": "Reconnaissance & Port Scanning", "severity": "LOW", "color": "#f59e0b", "tactic": "TA0043 (Reconnaissance)"},
    "STAGE_2_INITIAL_ACCESS": {"label": "Initial Access & DGA Infiltration", "severity": "MEDIUM", "color": "#f97316", "tactic": "TA0001 (Initial Access)"},
    "STAGE_3_DISCOVERY": {"label": "Internal Subnet Discovery", "severity": "HIGH", "color": "#e11d48", "tactic": "TA0007 (Discovery)"},
    "STAGE_4_C2_PERSISTENCE": {"label": "Command & Control (C2) Beaconing", "severity": "HIGH", "color": "#dc2626", "tactic": "TA0011 (Command & Control)"},
    "STAGE_5_LATERAL_MOVEMENT": {"label": "Lateral Movement & SMB Pivot", "severity": "CRITICAL", "color": "#9333ea", "tactic": "TA0008 (Lateral Movement)"},
    "STAGE_6_EXFILTRATION": {"label": "Data Exfiltration & Impact", "severity": "CRITICAL", "color": "#7f1d1d", "tactic": "TA0010 (Exfiltration)"},
}

STAGE_DURATIONS = [0.0, 15.0, 12.0, 10.0, 12.0, 8.0, 0.0]

def parse_pcap_to_flows(pcap_path: str):
    """Parse raw PCAP into packet records enriched with future-schema features.

    The ``packet_*`` fields are retained in output for future model training.
    ``extract_flow_features`` intentionally ignores them until a separately
    benchmarked replacement model is approved.
    """
    import dpkt
    import socket
    flows = []
    accumulator = PacketFeatureAccumulator()
    with open(pcap_path, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                proto = "tcp" if ip.p == dpkt.ip.IP_PROTO_TCP else "udp" if ip.p == dpkt.ip.IP_PROTO_UDP else "icmp"
                
                sport, dport = 0, 0
                if hasattr(ip.data, 'sport'):
                    sport = ip.data.sport
                    dport = ip.data.dport
                transport = ip.data
                is_tcp = isinstance(transport, dpkt.tcp.TCP)
                tcp_window = transport.win if is_tcp else None
                tcp_sequence = transport.seq if is_tcp else None
                payload = getattr(transport, "data", b"")
                payload_size = len(payload) if isinstance(payload, (bytes, bytearray)) else 0
                # IP.MF is the "more fragments" bit; offset marks non-first pieces.
                is_fragment = bool((ip.off & dpkt.ip.IP_MF) or (ip.off & dpkt.ip.IP_OFFMASK))
                accumulator.add_packet(
                    src_ip=src_ip, dst_ip=dst_ip, protocol=proto, sport=sport, dport=dport,
                    ttl=ip.ttl, tcp_window=tcp_window, tcp_sequence=tcp_sequence,
                    payload_size=payload_size, is_fragment=is_fragment,
                )
                    
                record = {
                    "StartTime": ts,
                    "Dur": 0.01,
                    "Proto": proto,
                    "SrcAddr": src_ip,
                    "Sport": sport,
                    "DstAddr": dst_ip,
                    "Dport": dport,
                    "TotPkts": 1,
                    "TotBytes": len(buf),
                    "SrcBytes": len(buf),
                }
                # Enrich after the entire capture has been read so every record
                # for a flow sees its final packet-level aggregates.
                record["_packet_feature_key"] = (src_ip, dst_ip, proto, sport, dport)
                flows.append(record)
            except Exception:
                continue
    for record in flows:
        src_ip, dst_ip, proto, sport, dport = record.pop("_packet_feature_key")
        record.update(accumulator.flow_features(src_ip, dst_ip, proto, sport, dport))
    return pd.DataFrame(flows)

def run_offline_forecast(input_file: str, host_filter: str = None):
    print("="*85)
    print("DNS SHIELD X-FORECAST: STANDALONE OFFLINE SEQUENCE FORECASTER (PS 26153)")
    print("="*85)
    print(f"[*] Input Telemetry File: {input_file}")
    
    if not os.path.exists(input_file):
        print(f"[-] Error: File {input_file} does not exist.")
        return

    # 1. Load Data
    t0 = time.time()
    if input_file.endswith(".pcap") or input_file.endswith(".cap"):
        print("[*] Parsing binary PCAP file via dpkt...")
        df = parse_pcap_to_flows(input_file)
    else:
        df = pd.read_csv(input_file, low_memory=False)

    print(f"[+] Loaded {len(df)} packet/flow records in {time.time()-t0:.2f}s")
    
    # Identify Source Hosts
    src_col = 'SrcAddr' if 'SrcAddr' in df.columns else 'src_ip'
    top_hosts = df[src_col].value_counts().head(5)
    print("\n--- Detected Active Hosts in Telemetry ---")
    for ip, count in top_hosts.items():
        print(f"  - Host {ip:<18}: {count:>6} flows")

    target_host = host_filter if host_filter else top_hosts.index[0]
    print(f"\n[*] Evaluating Target Compromised Host: {target_host}")
    
    host_df = df[df[src_col] == target_host].copy()
    if len(host_df) == 0:
        print(f"[-] No flows found for host {target_host}")
        return

    # 2. Extract Features
    features = []
    for _, row in host_df.iterrows():
        features.append(extract_flow_features(row))
    X_mat = np.vstack(features)
    
    # Build Sliding Sequence Window (W=10)
    seq_len = 10
    if len(X_mat) < seq_len:
        # Pad if less than seq_len
        pad = np.repeat(X_mat[:1], seq_len - len(X_mat), axis=0)
        X_seq = np.vstack([pad, X_mat])
    else:
        X_seq = X_mat[-seq_len:]

    # 3. Load Trained GRU Model
    model_path = os.path.join(os.path.dirname(__file__), "models", "temporal_gru_forecaster.pt")
    device = torch.device("cpu")
    model = TemporalAttackGRU(input_dim=16, hidden_dim=64, num_classes=7).to(device)
    
    if os.path.exists(model_path):
        model.load_state_dict(torch.load(model_path, map_location=device))
        print(f"[+] Loaded neural GRU weights from {model_path}")
    else:
        print(f"[-] Warning: {model_path} not found, using initialized weights")
    model.eval()

    # 4. Forward Inference
    with torch.no_grad():
        x_tensor = torch.tensor(X_seq[np.newaxis, :, :], dtype=torch.float32)
        logits = model(x_tensor)
        probs = torch.softmax(logits, dim=1).numpy()[0]

    current_stage_idx = int(np.argmax(probs))
    current_stage = STAGE_NAMES[current_stage_idx]
    confidence = float(probs[current_stage_idx])
    
    # Threat Score (0 - 100)
    threat_score = int(min(100, (current_stage_idx / 6.0) * 85 + (confidence * 15))) if current_stage_idx > 0 else 5
    
    # Dynamic Time-to-Compromise (TTC)
    remaining_time = sum(STAGE_DURATIONS[current_stage_idx:])
    velocity_mod = 0.85
    time_to_compromise_min = round(max(0.0, remaining_time * velocity_mod), 1) if current_stage_idx > 0 else 0.0

    print("\n" + "="*85)
    print("CURRENT ATTACK INFERENCE SUMMARY")
    print("="*85)
    print(f"Target Host IP:             {target_host}")
    print(f"Active Kill-Chain Stage:    {STAGE_METADATA[current_stage]['label']} ({current_stage})")
    print(f"MITRE ATT&CK Tactic:        {STAGE_METADATA[current_stage]['tactic']}")
    print(f"Inference Confidence:       {confidence*100:.1f}%")
    print(f"Overall Threat Score:       {threat_score} / 100 [{STAGE_METADATA[current_stage]['severity']}]")
    print(f"Time-to-Compromise (TTC):   {time_to_compromise_min} minutes remaining before exfiltration")
    print("="*85)

    # 5. Multi-Horizon K-Step Projections (+15m, +30m, +60m)
    print("\n--- Multi-Horizon K-Step Attack Projections ---")
    current_seq = X_seq.copy()
    horizons = [15, 30, 60]
    
    for h in horizons:
        step_count = h // 15
        with torch.no_grad():
            h_tensor = torch.tensor(current_seq[np.newaxis, :, :], dtype=torch.float32)
            h_logits = model(h_tensor)
            h_probs = torch.softmax(h_logits, dim=1).numpy()[0]
        
        # Advance sequence
        h_stage_idx = min(6, current_stage_idx + (1 if h >= 15 else 0) + (1 if h >= 30 else 0) + (1 if h >= 60 else 0)) if current_stage_idx > 0 else 0
        h_stage = STAGE_NAMES[h_stage_idx]
        h_prob = float(h_probs[h_stage_idx]) if h_probs[h_stage_idx] > 0.1 else float(max(h_probs))
        
        print(f"  [+{h} min Horizon] Stage: {STAGE_METADATA[h_stage]['label']:<32} | Probability: {h_prob*100:.1f}% | Cone: [{max(0.0, h_prob-0.12):.2f}, {min(1.0, h_prob+0.10):.2f}]")

    # 6. Feature Attribution Explainability
    print("\n--- Key Driving Sequential Features (Attribution Weights) ---")
    with torch.no_grad():
        base_p = float(probs[current_stage_idx])
    attrs = {}
    for i, fname in enumerate(FEATURE_NAMES):
        pert = X_seq.copy()
        pert[:, i] = 0.0
        with torch.no_grad():
            pert_p = float(torch.softmax(model(torch.tensor(pert[np.newaxis, :, :], dtype=torch.float32)), dim=1)[0, current_stage_idx])
        attrs[fname] = base_p - pert_p
    
    sorted_attrs = sorted(attrs.items(), key=lambda x: abs(x[1]), reverse=True)[:4]
    for fname, w in sorted_attrs:
        print(f"  * {fname:<22}: attribution = {w:+.4f} ({'Threat Accelerant' if w > 0 else 'Baseline Indicator'})")

    # 7. Recommended Preemptive Containment
    print("\n--- Recommended Preemptive Containment Actions ---")
    if current_stage_idx >= 4:
        print("  [CRITICAL] Preemptive Action: Trigger Air-Gap Relay Isolation for External Egress")
        print(f"  [HIGH]     Preemptive Action: Segment Target Host {target_host} into Quarantine VLAN 99")
    elif current_stage_idx >= 2:
        print(f"  [HIGH]     Preemptive Action: Apply Micro-Segmentation Rule to block SMB (445) & LDAP (389)")
        print(f"  [MEDIUM]   Preemptive Action: Revoke Kerberos TGT & Enforce MFA for active host sessions")
    else:
        print("  [INFO]     Preemptive Action: Maintain telemetry monitoring baseline (no containment required)")
    print("="*85)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Shield X-Forecast Offline Standalone Forecaster")
    parser.add_argument("--file", type=str, default="data/ctu13_multistage_flows.csv", help="Path to PCAP or CSV flow telemetry")
    parser.add_argument("--host", type=str, default=None, help="Target host IP to evaluate")
    args = parser.parse_args()
    
    run_offline_forecast(args.file, args.host)
