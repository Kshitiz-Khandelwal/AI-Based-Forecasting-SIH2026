# Architecture Document — Cyber World Model Network Attack Forecaster
> **Problem Statement ID**: 26153 | **Organization**: National Technical Research Organisation (NTRO)  
> **Challenge**: AI based Network Attack Forecasting from Network Traffic Data  
> **Evaluation Deliverable**: Architecture Document (Max 2 Pages Equivalent)  
> **Classification**: Software Architecture Specification / CII Defense Specification

---

## PAGE 1 — High-Level Ingestion, State Representation & World Model Dynamics

### 1. Architectural Philosophy: Causal State Dynamics over Static Triage
Conventional Intrusion Detection Systems (IDS) evaluate network flows as isolated atomic events, mapping an instantaneous 5-tuple to a binary label ($y \in \{0, 1\}$). This approach fundamentally fails against advanced persistent threats (APTs) that execute multi-stage kill chains with deliberate low-and-slow inter-arrival times. 

Our architecture implements a **Cyber World Model**: an AI system that maintains an evolving latent representation of the network state $S_t$ and learns the underlying transition dynamics:
$$P(S_{t+1} \mid S_t, A_t)$$
By modeling environment dynamics rather than signature patterns, the system performs **$K$-step forward rollouts** ($S_{t+1}, S_{t+2}, \dots, S_{t+K}$), predicting adversary trajectory up to $60\text{ minutes}$ prior to data exfiltration or credential destruction.

```
                                    INGESTION LAYER
                                           │
         ┌─────────────────────────────────┴─────────────────────────────────┐
         ▼                                                                   ▼
[ Level 1: NetFlow / IPFIX Telemetry ]               [ Level 2: Packet-Level PCAP Telemetry ]
• 5-Tuple, Protocol, Duration, Bytes, Packets       • Session TTL Variance & TCP Window Size
• TCP Flag Bitmask (SYN/ACK/FIN/RST/PSH/URG)        • IP Fragment Flags (DF/MF evasion checks)
• Inter-Arrival Time (Mean, Variance, Max IAT)      • Payload Size Distributions & Retransmissions
• Bidirectional flow ratios                         • Sequential / Randomized Port Scan Signatures
         │                                                                   │
         └─────────────────────────────────┬─────────────────────────────────┘
                                           ▼
                 [ Synchronous Temporal Alignment & Feature Normalization ]
                 [ 16-Dimensional Network State Tensor per Host: S_t in R^16 ]
                                           │
                                           ▼
                 ┌───────────────────────────────────────────────────┐
                 │       CYBER WORLD MODEL DYNAMICS (PyTorch)        │
                 ├───────────────────────────────────────────────────┤
                 │ • Deep Sequence Core: 2-Layer Bi-GRU / Transformer│
                 │   (input_dim=16, hidden_dim=64, seq_len=10)       │
                 │ • Latent State Progression: P(S_{t+1} | S_t)      │
                 │ • Bayesian-Calibrated State Transition Matrix M   │
                 └───────────────────────────────────────────────────┘
```

### 2. Dual-Level Telemetry Ingestion Layer
1. **Flow-Level Telemetry (Level 1)**: Ingests aggregate NetFlow v9/IPFIX flow records. Captures macro-level volumetric dynamics, TCP flag combinations, and inter-arrival timing statistics across bidirectional sessions.
2. **Packet-Level Telemetry (Level 2)**: Extracts micro-level transport signatures from raw PCAP/PCAP-NG streams. Analyzes IP fragmentation, initial TTL degradation (indicating NAT traversal or spoofing), TCP zero-window probing, and scan sequencing.
3. **State Normalizer**: Maps the dual telemetry streams into a sliding-window tensor $S_t \in \mathbb{R}^{16}$ normalized against rolling host baselines.

---

## PAGE 2 — Forecasting Engine, MITRE ATT&CK Mapping, Explainability & Response

```
                  ┌───────────────────────────────────────────────────┐
                  │       K-STEP FORWARD PROJECTION & MITRE MAP       │
                  └───────────────────────────────────────────────────┘
                                           │
        ┌──────────────────────────────────┼──────────────────────────────────┐
        ▼                                  ▼                                  ▼
[ Horizon t+15m ]                  [ Horizon t+30m ]                  [ Horizon t+60m ]
p_{t+15} = p_0 * M                 p_{t+30} = p_0 * M^2               p_{t+60} = p_0 * M^4
Reconnaissance -> Initial Access   Initial Access -> Discovery/C2     C2 -> Lateral/Exfiltration
        │                                  │                                  │
        └──────────────────────────────────┼──────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                    TIME-TO-COMPROMISE (TTC) & EXPLAINABILITY ENGINE (XAI)                  │
├────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Formal TTC Formulation:                                                                  │
│     TTC(s, x) = sum(T_k) * (1.0 - 0.45 * clip(QPS/25, 0, 1)) * (0.60 + 0.40 * (1.0 - C))  │
│ • Sequence Perturbation Attribution: Explains temporal delta dP(threat)/dx_i               │
│ • Exact TreeSHAP: Additive Shapley feature breakdown on lexical & flow attributes          │
└────────────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           ▼
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                    PROACTIVE DECISION SUPPORT & ACTIVE RESPONSE LAYER                      │
├────────────────────────────────────────────────────────────────────────────────────────────┤
│ • Preemptive Micro-Segmentation: Automated dynamic VLAN / IP isolation via Active Response │
│ • Next.js 15 SOC Console: Real-time telemetry, kill-chain trajectory cones, MITRE heatmaps │
│ • Air-Gap Software Relay Trip: Emulated GPIO hardware killswitch for critical segment drop │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 3. Attack Progression Mapping & Time-to-Compromise (TTC)
- **MITRE ATT&CK Progression Pipeline**: The predicted trajectory maps to six standardized stages:
  1. *Reconnaissance* (T1595, T1046) $\to$ 2. *Initial Access* (T1190, T1566) $\to$ 3. *Discovery* (T1082) $\to$ 4. *C2 Persistence* (T1071, T1572) $\to$ 5. *Lateral Movement* (T1021) $\to$ 6. *Exfiltration / Impact* (T1048).
- **Time-to-Compromise Calculation**: Incorporates empirical stage duration priors ($T_k$ derived from CTU-13 benchmark runs), attack velocity acceleration ($\text{burst\_qps}$ discount factor up to $45\%$), and model uncertainty scaling.

### 4. Interpretable Decision Support (XAI)
To satisfy the strict non-black-box requirement of Critical Information Infrastructure:
- **Dynamic Sequence Perturbation**: Measures gradient/output shift over temporal steps to identify whether inter-arrival jitter, SYN flag surges, or destination port spreads triggered the state transition.
- **TreeSHAP Feature Attribution**: Generates local explanations with exact Shapley values, providing SOC analysts with mathematical evidence for every alert.

### 5. Deployment Topology & Resilience
- **Zero Cloud Footprint**: Microservice architecture communicating via bounded REST APIs (FastAPI) and in-memory Redis message queues. Operates 100% offline within air-gapped sovereign datacenters.
- **Graceful Degradation**: If deep sequence inference experiences backlog, the system cascades back to local deterministic rule evaluation and fast-path Bloom filter allowlists, ensuring line-rate availability without packet dropping.
