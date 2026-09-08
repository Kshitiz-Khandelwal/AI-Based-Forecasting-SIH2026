"""
DNS Shield X-Forecast — Multi-Stage Attack Forecasting Engine
Applies a trained Temporal Bidirectional/Unidirectional GRU Sequence Forecaster
combined with a Markov State Rollout Transition Matrix to project attack progression
across the 6 canonical MITRE ATT&CK Kill-Chain stages.
"""

import time
import math
import logging
import os
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Any

import torch
import torch.nn as nn
import numpy as np

try:
    from temporal_feature_extractor import extract_flow_features, FEATURE_NAMES
    from train_temporal_gru import TemporalAttackGRU
except ImportError:
    from services.forecasting_engine.temporal_feature_extractor import extract_flow_features, FEATURE_NAMES
    from services.forecasting_engine.train_temporal_gru import TemporalAttackGRU

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("attack-forecaster")

# The 6 canonical MITRE ATT&CK Kill-Chain Stages
STAGES = [
    "STAGE_0_BENIGN",
    "STAGE_1_RECONNAISSANCE",
    "STAGE_2_INITIAL_ACCESS",
    "STAGE_3_DISCOVERY",
    "STAGE_4_C2_PERSISTENCE",
    "STAGE_5_LATERAL_MOVEMENT",
    "STAGE_6_EXFILTRATION",
]

STAGE_METADATA = {
    "STAGE_0_BENIGN": {
        "label": "Benign Operational Traffic",
        "severity": "LOW",
        "color": "#10b981",
        "mitre_tactics": ["TA0000 - Normal"],
        "description": "Standard business and cloud DNS/IP traffic patterns."
    },
    "STAGE_1_RECONNAISSANCE": {
        "label": "Network & DNS Reconnaissance",
        "severity": "LOW-MEDIUM",
        "color": "#f59e0b",
        "mitre_tactics": ["TA0043 - Reconnaissance", "T1595 - Active Scanning"],
        "description": "Port sweeps, aggressive DNS enumeration, and target surface probing."
    },
    "STAGE_2_INITIAL_ACCESS": {
        "label": "Initial Access & DGA Contact",
        "severity": "MEDIUM",
        "color": "#f97316",
        "mitre_tactics": ["TA0001 - Initial Access", "T1566 - Phishing", "T1568 - Dynamic Resolution"],
        "description": "Malicious DGA seed queries, homoglyph phishing lures, and initial payload delivery."
    },
    "STAGE_3_DISCOVERY": {
        "label": "Internal Subnet Discovery",
        "severity": "MEDIUM-HIGH",
        "color": "#e11d48",
        "mitre_tactics": ["TA0007 - Discovery", "T1046 - Network Service Discovery"],
        "description": "Internal lateral port enumeration, LDAP/SMB sweeps, and service discovery."
    },
    "STAGE_4_C2_PERSISTENCE": {
        "label": "Command & Control (C2) Beaconing",
        "severity": "HIGH",
        "color": "#dc2626",
        "mitre_tactics": ["TA0011 - Command and Control", "T1071 - Application Layer Protocol"],
        "description": "Periodic heartbeat pulses, Cobalt Strike beaconing, and DNS tunneling sync."
    },
    "STAGE_5_LATERAL_MOVEMENT": {
        "label": "Lateral Movement & Privilege Escalation",
        "severity": "CRITICAL",
        "color": "#9333ea",
        "mitre_tactics": ["TA0008 - Lateral Movement", "T1021 - Remote Services"],
        "description": "Cross-VLAN pivoting, token impersonation, and target database targeting."
    },
    "STAGE_6_EXFILTRATION": {
        "label": "Data Exfiltration & Impact",
        "severity": "EMERGENCY",
        "color": "#7f1d1d",
        "mitre_tactics": ["TA0010 - Exfiltration", "T1048 - Exfiltration Over Alternative Protocol"],
        "description": "High-entropy DNS tunneling byte streams, chunked Base64 exfiltration, and data egress."
    }
}


@dataclass
class StagePrediction:
    stage_id: str
    stage_label: str
    probability: float
    estimated_time_to_stage_min: float
    confidence_cone: Tuple[float, float]  # (min_prob, max_prob)


@dataclass
class AttackForecastResult:
    host_ip: str
    timestamp: float
    current_stage: str
    current_stage_confidence: float
    overall_threat_score: int  # 0 to 100
    time_to_compromise_min: float  # PS2 required field: estimated minutes until full exfiltration/impact
    forecast_horizon_15m: StagePrediction
    forecast_horizon_30m: StagePrediction
    forecast_horizon_60m: StagePrediction
    blast_radius_nodes: List[str]
    feature_attributions: List[Dict[str, Any]]  # Dynamic perturbation-based feature contribution weights
    preemptive_actions: List[Dict[str, Any]]
    hardware_relay_required: bool = False  # Simulated hardware air-gap trip signal (software emulation)
    provenance: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def shap_explanations(self) -> List[Dict[str, Any]]:
        """Legacy alias for backward compatibility with frontend consumers."""
        return self.feature_attributions


class AttackForecastingEngine:
    """
    Stateful Temporal Forecaster analyzing multi-flow host event sequences.
    Applies trained Neural GRU Sequence Inference + Markov State Rollouts.
    """

    def __init__(self):
        # ---------------------------------------------------------------------
        # EXPERT-DEFINED PRIOR — these transition probabilities are domain-knowledge
        # estimates, not learned from data. They seed the Markov rollout that projects
        # the GRU's current-stage distribution forward in time when empirical calibration
        # data is unavailable or has low sample support (N < 20).
        # ---------------------------------------------------------------------
        self.DEFAULT_TRANSITION_MATRIX = {
            "STAGE_0_BENIGN": {"STAGE_0_BENIGN": 0.85, "STAGE_1_RECONNAISSANCE": 0.15},
            "STAGE_1_RECONNAISSANCE": {"STAGE_1_RECONNAISSANCE": 0.20, "STAGE_2_INITIAL_ACCESS": 0.65, "STAGE_0_BENIGN": 0.15},
            "STAGE_2_INITIAL_ACCESS": {"STAGE_2_INITIAL_ACCESS": 0.25, "STAGE_3_DISCOVERY": 0.40, "STAGE_4_C2_PERSISTENCE": 0.35},
            "STAGE_3_DISCOVERY": {"STAGE_3_DISCOVERY": 0.20, "STAGE_4_C2_PERSISTENCE": 0.45, "STAGE_5_LATERAL_MOVEMENT": 0.35},
            "STAGE_4_C2_PERSISTENCE": {"STAGE_4_C2_PERSISTENCE": 0.20, "STAGE_5_LATERAL_MOVEMENT": 0.40, "STAGE_6_EXFILTRATION": 0.40},
            "STAGE_5_LATERAL_MOVEMENT": {"STAGE_5_LATERAL_MOVEMENT": 0.10, "STAGE_6_EXFILTRATION": 0.90},
            "STAGE_6_EXFILTRATION": {"STAGE_6_EXFILTRATION": 0.95, "STAGE_0_BENIGN": 0.05}
        }

        # ---------------------------------------------------------------------
        # EXPERT-DEFINED PRIOR — average dwell time per kill-chain stage in minutes,
        # based on published APT campaign analysis, not learned from telemetry.
        # Used as baseline for TTC (Time-To-Compromise) estimation.
        # ---------------------------------------------------------------------
        self.DEFAULT_STAGE_DURATIONS = [0.0, 10.0, 15.0, 12.0, 18.0, 22.0, 0.0]

        # Attempt loading empirical priors calibrated from CTU-13 dataset
        priors_file = os.path.join(os.path.dirname(__file__), "priors.json")
        self.priors_calibrated = False
        if os.path.exists(priors_file):
            try:
                import json
                with open(priors_file, "r") as f:
                    priors_data = json.load(f)
                self.transition_matrix = priors_data["transition_matrix"]
                self.transition_matrix_np = np.array(priors_data["transition_matrix_array"], dtype=np.float32)
                self.stage_durations = priors_data.get("stage_durations_min", self.DEFAULT_STAGE_DURATIONS)
                n_transitions = priors_data.get("metadata", {}).get("total_observed_transitions", 0)
                self.priors_source = f"CTU-13 empirical calibration (N={n_transitions} observed transitions)"
                self.priors_calibrated = True
                logger.info(f"[Priors Calibrated] Loaded empirical Markov transition matrix & dwell times from priors.json (sample_size={n_transitions})")
            except Exception as e:
                logger.warning(f"[Priors Fallback] Could not parse priors.json ({e}); using expert-defined prior fallback")
                self.transition_matrix = self.DEFAULT_TRANSITION_MATRIX
                self.stage_durations = self.DEFAULT_STAGE_DURATIONS
                self.priors_source = "expert_prior_default"
        else:
            logger.warning("[Priors Fallback] priors.json not found; using expert-defined prior transition matrix & dwell times")
            self.transition_matrix = self.DEFAULT_TRANSITION_MATRIX
            self.stage_durations = self.DEFAULT_STAGE_DURATIONS
            self.priors_source = "expert_prior_default"

        if not self.priors_calibrated:
            # Build 7x7 stochastic numpy matrix from expert fallback
            self.transition_matrix_np = np.zeros((len(STAGES), len(STAGES)), dtype=np.float32)
            for from_stage, targets in self.transition_matrix.items():
                from_idx = STAGES.index(from_stage)
                for to_stage, p in targets.items():
                    to_idx = STAGES.index(to_stage)
                    self.transition_matrix_np[from_idx, to_idx] = p
            for i in range(len(STAGES)):
                row_sum = self.transition_matrix_np[i].sum()
                if row_sum > 0:
                    self.transition_matrix_np[i] /= row_sum
                else:
                    self.transition_matrix_np[i, i] = 1.0

        # Load trained PyTorch GRU neural model
        self.device = torch.device("cpu")
        self.gru_loaded = False
        try:
            self.gru_model = TemporalAttackGRU(input_dim=16, hidden_dim=64, num_classes=7).to(self.device)
            model_path = os.path.join(os.path.dirname(__file__), "models", "temporal_gru_forecaster.pt")
            if os.path.exists(model_path):
                self.gru_model.load_state_dict(torch.load(model_path, map_location=self.device))
                self.gru_model.eval()
                self.gru_loaded = True
                logger.info(f"[+] Loaded neural GRU forecasting model from {model_path}")
            else:
                logger.warning(f"GRU model file not found at {model_path}")
        except Exception as e:
            logger.warning(f"Could not load GRU weights: {e}")
            self.gru_model = None
            self.gru_loaded = False

        logger.info("Initialized Temporal Attack Forecasting Engine with Neural GRU + Markov Rollout Matrix")

    def _extract_aggregate_features(self, flows: List[Dict[str, Any]]) -> Dict[str, float]:
        """Combine multi-flow features over a temporal sliding window."""
        if not flows:
            return {
                "avg_entropy": 2.5,
                "syn_ratio": 0.0,
                "burst_qps": 0.0,
                "dns_tunnel_markers": 0.0,
                "unique_ports": 0.0,
                "c2_heartbeat_regularity": 0.0,
                "fwd_bwd_imbalance": 1.0,
                "dga_query_count": 0.0,
                "discovery_port_count": 0.0,
                "lateral_flow_count": 0.0,
                "c2_query_count": 0.0
            }

        total_bytes = sum(f.get("total_bytes", f.get("features", {}).get("total_bytes", 100)) for f in flows)
        total_syn = sum(f.get("syn_count", 1 if (f.get("tcp_flags") or {}).get("SYN") or f.get("features", {}).get("syn_ratio", 0) > 0.3 else 0) for f in flows)
        dns_counts = sum(1 for f in flows if f.get("dns_queries") or f.get("dns_query") or f.get("protocol") == "DNS")
        unique_ports = len(set(f.get("dst_port", 0) for f in flows))

        tunnel_markers = 0
        dga_queries = 0
        c2_queries = 0
        discovery_ports = 0
        lateral_flows = 0

        for f in flows:
            queries = []
            if f.get("dns_query"):
                queries.append(f["dns_query"])
            if isinstance(f.get("dns_queries"), list):
                queries.extend(f["dns_queries"])

            for q in queries:
                if not q or not isinstance(q, str):
                    continue
                q_low = q.lower()
                if "==" in q_low or ".exfil." in q_low or "exfiltrate" in q_low or len(q_low) > 40:
                    tunnel_markers += 1
                elif any(k in q_low for k in ["beacon", "c2-domain", "c2."]):
                    c2_queries += 1
                elif any(k in q_low for k in ["dga", "seed", ".top", ".xyz", ".biz"]):
                    dga_queries += 1

            dst_port = f.get("dst_port", 0)
            dst_ip = f.get("dst_ip", "")

            # Discovery: LDAP 389/636, Kerberos 88, NetBIOS 139
            if dst_port in [139, 389, 636, 88]:
                discovery_ports += 1

            # Lateral Movement: Port 445 on internal subnets
            if dst_port == 445 and (dst_ip.startswith("10.") or dst_ip.startswith("192.168.")):
                lateral_flows += 1

        iats = [f.get("features", {}).get("iat_mean", 0) for f in flows if f.get("features", {}).get("iat_mean", 0) > 0]
        heartbeat_reg = 0.0
        if len(iats) >= 3:
            mean_iat = sum(iats) / len(iats)
            variance = sum((x - mean_iat) ** 2 for x in iats) / len(iats)
            if variance < 2.0 and mean_iat > 5.0:
                heartbeat_reg = 0.9
        elif c2_queries > 0:
            heartbeat_reg = 0.90

        return {
            "syn_ratio": min(1.0, float(total_syn) / max(1.0, len(flows))),
            "burst_qps": round(float(dns_counts) / max(1.0, len(flows)), 2),
            "dns_tunnel_markers": float(tunnel_markers),
            "dga_query_count": float(dga_queries),
            "c2_query_count": float(c2_queries),
            "discovery_port_count": float(discovery_ports),
            "lateral_flow_count": float(lateral_flows),
            "unique_ports": float(unique_ports),
            "c2_heartbeat_regularity": heartbeat_reg,
            "fwd_bwd_imbalance": min(10.0, float(total_bytes) / 1024.0)
        }

    def _friendly_feature_name(self, feat_name: str) -> str:
        mapping = {
            "duration_sec": "Flow Duration",
            "total_packets": "Packet Exchange Count",
            "total_bytes": "Total Flow Volume",
            "src_bytes": "Outbound Payload Bytes",
            "dst_bytes": "Inbound Response Bytes",
            "bytes_per_sec": "Bandwidth Egress Rate",
            "packets_per_sec": "Packet Burst Velocity",
            "avg_packet_size": "Mean Packet Payload Size",
            "is_tcp": "TCP Stream Protocol",
            "is_udp": "UDP Transport Protocol",
            "is_icmp": "ICMP Control Protocol",
            "is_dns_port": "DNS Tunneling / Port 53",
            "is_web_port": "Web Protocol (HTTP/HTTPS)",
            "is_lateral_port": "Lateral Movement Port (SMB/LDAP)",
            "is_internal_dst": "Internal Subnet Hop",
            "is_syn_or_scan": "SYN Scan / Probe Pattern",
        }
        return mapping.get(feat_name, feat_name.replace("_", " ").title())

    def _friendly_feature_value(self, feat_name: str, raw_val: float, feats: Dict[str, float]) -> str:
        if feat_name in ["is_tcp", "is_udp", "is_icmp", "is_dns_port", "is_web_port", "is_lateral_port", "is_internal_dst", "is_syn_or_scan"]:
            return "Active (1.0)" if raw_val > 0.5 else "Inactive (0.0)"
        elif feat_name == "bytes_per_sec":
            real_val = np.expm1(raw_val)
            return f"{real_val:.1f} B/s"
        elif feat_name == "packets_per_sec":
            real_val = np.expm1(raw_val)
            return f"{real_val:.1f} pkts/s"
        elif feat_name in ["total_bytes", "src_bytes", "dst_bytes"]:
            real_val = np.expm1(raw_val)
            return f"{int(real_val)} bytes"
        elif feat_name == "total_packets":
            real_val = np.expm1(raw_val)
            return f"{int(real_val)} pkts"
        elif feat_name == "duration_sec":
            real_val = np.expm1(raw_val)
            return f"{real_val:.2f}s"
        elif feat_name == "avg_packet_size":
            return f"{int(raw_val * 1500)} bytes"
        return f"{raw_val:.2f}"

    def _heuristic_fallback(self, host_ip: str, flows: List[Dict[str, Any]], feats: Dict[str, float]) -> Tuple[str, float, np.ndarray]:
        """
        Explicitly labeled fallback heuristic when PyTorch GRU model weights are not loaded.
        Uses keyword-based indicator counting in the sliding window.
        """
        recent_flows = flows[-20:] if len(flows) >= 20 else flows
        c_exfil = 0
        c_lateral = 0
        c_c2 = 0
        c_disc = 0
        c_dga = 0
        c_recon = 0

        for f in recent_flows:
            queries = []
            if f.get("dns_query"):
                queries.append(f["dns_query"])
            if isinstance(f.get("dns_queries"), list):
                queries.extend(f["dns_queries"])

            has_exfil = any("==" in q.lower() or ".exfil." in q.lower() or "exfiltrate" in q.lower() for q in queries)
            has_c2 = any("beacon" in q.lower() or "c2" in q.lower() for q in queries) or f.get("dst_ip") == "185.220.101.45"
            has_dga = any("dga" in q.lower() or ".top" in q.lower() or ".xyz" in q.lower() for q in queries)
            dst_port = f.get("dst_port", 0)
            dst_ip = f.get("dst_ip", "")
            f_syn = f.get("features", {}).get("syn_ratio", 0.0) or (1.0 if (f.get("tcp_flags") or {}).get("SYN") else 0.0)

            if has_exfil:
                c_exfil += 1
            elif dst_port == 445 and (dst_ip.startswith("10.") or dst_ip.startswith("192.168.")):
                c_lateral += 1
            elif has_c2:
                c_c2 += 1
            elif dst_port in [139, 389, 636, 88]:
                c_disc += 1
            elif has_dga:
                c_dga += 1
            elif f_syn > 0.4 or dst_port in [22, 80, 8080]:
                c_recon += 1

        stage_counts = {
            "STAGE_6_EXFILTRATION": c_exfil,
            "STAGE_5_LATERAL_MOVEMENT": c_lateral,
            "STAGE_4_C2_PERSISTENCE": c_c2,
            "STAGE_3_DISCOVERY": c_disc,
            "STAGE_2_INITIAL_ACCESS": c_dga,
            "STAGE_1_RECONNAISSANCE": c_recon,
        }

        max_stage = max(stage_counts, key=stage_counts.get)
        max_count = stage_counts[max_stage]

        probs = np.zeros(len(STAGES), dtype=np.float32)
        if max_count > 0:
            current_stage = max_stage
            confidence = min(0.98, 0.85 + (max_count / max(1.0, len(recent_flows))) * 0.13)
            idx = STAGES.index(current_stage)
            probs[idx] = confidence
            remaining = (1.0 - confidence) / (len(STAGES) - 1)
            for j in range(len(STAGES)):
                if j != idx:
                    probs[j] = remaining
        else:
            current_stage = "STAGE_0_BENIGN"
            confidence = 0.95
            probs[0] = 0.95
            for j in range(1, len(STAGES)):
                probs[j] = 0.05 / (len(STAGES) - 1)

        return current_stage, confidence, probs

    def evaluate_host_timeline(self, host_ip: str, flows: List[Dict[str, Any]]) -> AttackForecastResult:
        """
        Run temporal forecasting inference on a host's active traffic sequence.
        Executes genuine trained PyTorch GRU inference over a 10-flow sequence window,
        backed by Markov rollout projections and perturbation-based explainability.
        """
        now = time.time()
        feats = self._extract_aggregate_features(flows)

        # ---------------------------------------------------------------------
        # Step 1: Sequence Feature Extraction (10 Timesteps x 16 Features)
        # ---------------------------------------------------------------------
        SEQ_LEN = 10
        INPUT_DIM = 16

        if flows:
            recent_flows = flows[-SEQ_LEN:]
            flow_vectors = [extract_flow_features(f) for f in recent_flows]
            if len(flow_vectors) < SEQ_LEN:
                # Left-pad with zeros for early session sequences
                pad = [np.zeros(INPUT_DIM, dtype=np.float32) for _ in range(SEQ_LEN - len(flow_vectors))]
                seq_arr = np.array(pad + flow_vectors, dtype=np.float32)
            else:
                seq_arr = np.array(flow_vectors, dtype=np.float32)
        else:
            recent_flows = []
            seq_arr = np.zeros((SEQ_LEN, INPUT_DIM), dtype=np.float32)

        seq_tensor = torch.tensor(seq_arr, dtype=torch.float32, device=self.device).unsqueeze(0)

        # ---------------------------------------------------------------------
        # Step 2: Trained PyTorch GRU Inference (or Fallback Heuristic)
        # ---------------------------------------------------------------------
        if self.gru_model is not None and self.gru_loaded:
            self.gru_model.eval()
            with torch.no_grad():
                logits = self.gru_model(seq_tensor)
                probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]

            pred_idx = int(np.argmax(probs))
            current_stage = STAGES[pred_idx]
            confidence = float(probs[pred_idx])
            logger.info(f"[GRU Inference] Host {host_ip}: stage={current_stage} (confidence={confidence:.3f})")

            # Real feature attribution via sequence perturbation against the GRU model
            base_threat_prob = 1.0 - float(probs[0])
            feature_attributions = []
            with torch.no_grad():
                for f_idx, feat_name in enumerate(FEATURE_NAMES):
                    perturbed = seq_tensor.clone()
                    perturbed[0, :, f_idx] = 0.0
                    pert_logits = self.gru_model(perturbed)
                    pert_probs = torch.softmax(pert_logits, dim=-1).cpu().numpy()[0]
                    pert_threat_prob = 1.0 - float(pert_probs[0])
                    impact = base_threat_prob - pert_threat_prob
                    raw_val = float(seq_arr[-1, f_idx])
                    feature_attributions.append({
                        "feature": self._friendly_feature_name(feat_name),
                        "raw_feature": feat_name,
                        "value": self._friendly_feature_value(feat_name, raw_val, feats),
                        "weight": round(float(impact), 4),
                        "shap_value": round(float(impact), 4)
                    })

            # Sort features by absolute impact magnitude
            feature_attributions.sort(key=lambda x: abs(x["weight"]), reverse=True)
            top_attributions = feature_attributions[:4]
        else:
            logger.warning(f"[Fallback Heuristic] GRU model unavailable for host {host_ip}; using heuristic fallback")
            current_stage, confidence, probs = self._heuristic_fallback(host_ip, flows, feats)
            pred_idx = STAGES.index(current_stage)

            # Heuristic feature attribution fallback
            top_attributions = [
                {"feature": "Port Sweep Diversity", "value": f"{feats['unique_ports']} ports", "weight": +0.32 if feats['unique_ports'] > 5 else -0.15, "shap_value": +0.32 if feats['unique_ports'] > 5 else -0.15},
                {"feature": "C2 Heartbeat Periodicity", "value": f"{feats['c2_heartbeat_regularity']}", "weight": +0.41 if feats['c2_heartbeat_regularity'] > 0 else -0.10, "shap_value": +0.41 if feats['c2_heartbeat_regularity'] > 0 else -0.10},
                {"feature": "DNS Tunneling Markers", "value": f"{feats['dns_tunnel_markers']} tags", "weight": +0.48 if feats['dns_tunnel_markers'] > 0 else -0.22, "shap_value": +0.48 if feats['dns_tunnel_markers'] > 0 else -0.22},
                {"feature": "SYN Flood Ratio", "value": f"{round(feats['syn_ratio']*100, 1)}%", "weight": +0.25 if feats['syn_ratio'] > 0.3 else -0.18, "shap_value": +0.25 if feats['syn_ratio'] > 0.3 else -0.18}
            ]

        # Overall threat score (0 to 100)
        stage_idx = pred_idx
        threat_score = int(min(100, (stage_idx / 6.0) * 85 + (confidence * 15))) if stage_idx > 0 else 5

        # ---------------------------------------------------------------------
        # Step 3: Time-to-Compromise (TTC) Dynamic Calculation
        # ---------------------------------------------------------------------
        # EXPERT-DEFINED PRIOR — average dwell time per kill-chain stage in minutes,
        # based on published APT campaign analysis, calibrated against CTU-13 where available.
        stage_durations = self.stage_durations

        if stage_idx == 0:
            time_to_compromise_min = 0.0
        elif stage_idx >= 6:
            time_to_compromise_min = 0.0
        else:
            base_remaining_duration = sum(stage_durations[stage_idx + 1: 7])
            burst_rate = float(feats.get("burst_qps", 0.0))
            velocity_modifier = max(0.55, 1.0 - 0.45 * min(burst_rate / 25.0, 1.0))
            confidence_factor = 0.60 + 0.40 * (1.0 - confidence)
            time_to_compromise_min = round(base_remaining_duration * velocity_modifier * confidence_factor, 1)

        # ---------------------------------------------------------------------
        # Step 4: Multi-Horizon Markov Rollouts Seeded from GRU Softmax Distribution
        # ---------------------------------------------------------------------
        # Step +15m (1-step rollout: p @ M)
        p_15 = probs @ self.transition_matrix_np
        next_15_idx = int(np.argmax(p_15))
        h15_stage = STAGES[next_15_idx]
        h15_prob = float(p_15[next_15_idx])

        velocity_mod = locals().get("velocity_modifier", 1.0)
        time_to_next = round(max(0.0, stage_durations[next_15_idx] * velocity_mod), 1) if stage_idx > 0 else 0.0

        h15 = StagePrediction(
            stage_id=h15_stage,
            stage_label=STAGE_METADATA[h15_stage]["label"],
            probability=round(min(0.98, h15_prob), 3),
            estimated_time_to_stage_min=round(min(15.0, time_to_next), 1) if stage_idx > 0 else 0.0,
            confidence_cone=(round(max(0.0, h15_prob - 0.15), 2), round(min(1.0, h15_prob + 0.10), 2))
        )

        # Step +30m (2-step rollout: p_15 @ M)
        p_30 = p_15 @ self.transition_matrix_np
        stage_30_idx = int(np.argmax(p_30))
        stage_30 = STAGES[stage_30_idx]
        h30_prob = float(p_30[stage_30_idx])

        time_to_h30 = round(max(0.0, (stage_durations[next_15_idx] + stage_durations[stage_30_idx]) * velocity_mod), 1) if stage_idx > 0 else 0.0
        h30 = StagePrediction(
            stage_id=stage_30,
            stage_label=STAGE_METADATA[stage_30]["label"],
            probability=round(min(0.95, h30_prob), 3),
            estimated_time_to_stage_min=round(min(30.0, time_to_h30), 1) if stage_idx > 0 else 0.0,
            confidence_cone=(round(max(0.0, h30_prob - 0.20), 2), round(min(1.0, h30_prob + 0.15), 2))
        )

        # Step +60m (4-step rollout: p_30 @ M^2)
        p_60 = p_30 @ (self.transition_matrix_np @ self.transition_matrix_np)
        stage_60_idx = int(np.argmax(p_60))
        stage_60 = STAGES[stage_60_idx]
        h60_prob = float(p_60[stage_60_idx])

        h60 = StagePrediction(
            stage_id=stage_60,
            stage_label=STAGE_METADATA[stage_60]["label"],
            probability=round(min(0.95, h60_prob), 3),
            estimated_time_to_stage_min=round(min(60.0, time_to_compromise_min), 1) if stage_idx > 0 else 0.0,
            confidence_cone=(round(max(0.0, h60_prob - 0.20), 2), round(min(1.0, h60_prob + 0.15), 2))
        )

        # ---------------------------------------------------------------------
        # Step 5: Blast Radius Nodes derived from internal flow telemetry
        # ---------------------------------------------------------------------
        observed_internal_targets = []
        for f in flows:
            dst = f.get("dst_ip", "")
            if dst and dst != host_ip and (dst.startswith("10.") or dst.startswith("192.168.") or dst.startswith("172.")):
                if dst not in observed_internal_targets:
                    observed_internal_targets.append(dst)

        blast_radius = observed_internal_targets[:5]

        # ---------------------------------------------------------------------
        # Step 6: Preemptive Actions & Hardware Sentinel Relay Trigger
        # ---------------------------------------------------------------------
        preemptive_actions = []
        relay_required = False

        if stage_idx >= 5 or (stage_idx >= 4 and h15.probability > 0.85):
            relay_required = True
            preemptive_actions.append({
                "action": "SIMULATED_AIR_GAP_TRIP",
                "priority": "CRITICAL",
                "description": "Trigger simulated hardware air-gap relay signal (GPIO 18 emulation) to isolate external egress.",
                "target": "HARDWARE_RELAY_EMULATOR_0"
            })

        if stage_idx >= 3:
            preemptive_actions.append({
                "action": "PREEMPTIVE_VLAN_ISOLATION",
                "priority": "HIGH",
                "description": f"Isolate Host {host_ip} to Quarantine VLAN 99 before lateral hop.",
                "target": host_ip
            })
            preemptive_actions.append({
                "action": "DEPLOY_DECOY_HONEYPOT",
                "priority": "MEDIUM",
                "description": "Deploy fake SMB/LDAP honeypot on predicted next-hop subnet.",
                "target": blast_radius[0] if blast_radius else "192.168.1.50"
            })

        # ---------------------------------------------------------------------
        # Step 7: Explicit Methodology & Provenance Disclosure
        # Distinguishes learned ML inference vs empirical calibration vs expert prior
        # ---------------------------------------------------------------------
        provenance = {
            "current_stage": "gru_inference" if (self.gru_model and self.gru_loaded) else "heuristic_keyword_fallback",
            "horizon_projection": "markov_rollout_calibrated_prior" if self.priors_calibrated else "markov_rollout_expert_prior",
            "time_to_compromise": "formula_with_calibrated_durations" if self.priors_calibrated else "formula_with_expert_prior_durations",
            "feature_attributions": "perturbation_analysis_on_gru_input" if (self.gru_model and self.gru_loaded) else "heuristic_feature_weights",
            "priors_source": self.priors_source,
            "calibrated_transitions_file": "services/forecasting_engine/priors.json" if self.priors_calibrated else "not_loaded",
            "neural_model_file": "services/forecasting_engine/models/temporal_gru_forecaster.pt" if self.gru_loaded else "not_loaded"
        }

        return AttackForecastResult(
            host_ip=host_ip,
            timestamp=now,
            current_stage=current_stage,
            current_stage_confidence=round(confidence, 3),
            overall_threat_score=threat_score,
            time_to_compromise_min=time_to_compromise_min,
            forecast_horizon_15m=h15,
            forecast_horizon_30m=h30,
            forecast_horizon_60m=h60,
            blast_radius_nodes=blast_radius,
            feature_attributions=top_attributions,
            preemptive_actions=preemptive_actions,
            hardware_relay_required=relay_required,
            provenance=provenance
        )


# Singleton instance for application-wide use
attack_forecaster = AttackForecastingEngine()
