# 🛡️ DNS Shield & Cyber World Model (NTRO — PS #26153)
### AI-Based Network Attack Forecasting from Network Traffic Data

[![SIH 2026](https://img.shields.io/badge/SIH-2026-orange.svg?style=flat-square)](https://www.sih.gov.in/)
[![Problem Statement](https://img.shields.io/badge/NTRO_PS-26153-blue.svg?style=flat-square)](#-official-problem-statement-brief)
[![Theme](https://img.shields.io/badge/Theme-Blockchain_&_Cybersecurity-purple.svg?style=flat-square)](#)
[![World Model](https://img.shields.io/badge/Architecture-Cyber_World_Model_P(S_t%2B1|S_t)-emerald.svg?style=flat-square)](#-world-model-architecture--forward-simulation)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB.svg?style=flat-square&logo=python&logoColor=white)](#)
[![Next.js 15](https://img.shields.io/badge/Next.js-15_(App_Router)-000000.svg?style=flat-square&logo=next.js&logoColor=white)](#)
[![Zero Cloud Dependency](https://img.shields.io/badge/Deployment-100%25_Offline_Air_Gapped-success.svg?style=flat-square)](#-getting-started--local-execution)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

> **Live Demonstration Interface**: [http://localhost:3000](http://localhost:3000) (Local SOC Console) | [Vercel Deployment Preview](https://sih-dns-wala-proejct-uhas.vercel.app)  
> **Target Enterprise Context**: Critical Information Infrastructure (CII) & Enterprise Defense (NCIIPC / NTRO mandate)

---

## 📑 Table of Contents
1. [Official Problem Statement Brief (PS #26153)](#-official-problem-statement-brief)
2. [Executive Paradigm Shift: From Static Classifiers to Cyber World Models](#-paradigm-shift-cyber-world-models-in-defense)
3. [Two-Level Telemetry Ingestion Pipeline](#-two-level-telemetry-ingestion-pipeline)
4. [World Model Architecture & Forward Simulation ($K$-Step Rollout)](#-world-model-architecture--forward-simulation)
5. [MITRE ATT&CK Kill-Chain Mapping & Time-to-Compromise (TTC)](#-mitre-attck-kill-chain-mapping--ttc)
6. [Explainable AI (XAI): Dynamic Feature Attribution & TreeSHAP](#-explainable-ai-xai-feature-attribution)
7. [Empirical Benchmark: World Model vs. Logistic Regression Baseline](#-empirical-benchmark-world-model-vs-baseline)
8. [End-to-End System Architecture (7-Stage Fast-to-Deep Pipeline)](#-end-to-end-system-architecture)
9. [Deliverables for Evaluation (NTRO Required Package)](#-deliverables-for-evaluation-ntro-package)
10. [Getting Started & Local Execution (Offline-Ready)](#-getting-started--local-execution)
11. [Repository Directory Layout](#-repository-structure)

---

## 🎯 Official Problem Statement Brief

| Parameter | Details |
| :--- | :--- |
| **Problem Statement ID** | **26153** |
| **Problem Statement Title** | **AI based Network Attack Forecasting from Network Traffic Data** |
| **Organization** | **National Technical Research Organisation (NTRO)** |
| **Department** | National Technical Research Organisation (NTRO) |
| **Category** | Software |
| **Theme** | Blockchain & Cybersecurity |
| **Operational Scope** | Enterprise Networks & Critical Information Infrastructure (CII / NCIIPC) |
| **Datasets Referenced** | CIC-IDS-2017/2018, UNSW-NB15, CTU-13, CICIoT2023, LANL Authentication, DARPA Intrusion Detection |
| **Knowledge Bases** | MITRE ATT&CK®, CAPEC™, CVE/NVD |

### Mandate Summary
> *"Traditional machine learning classifiers applied to network traffic treat each flow in isolation and map it to a binary benign/malicious label. This discards the temporal and causal structure of an infiltration... An infiltration is a process unfolding over time, not a single anomalous packet.*  
> 
> *This challenge seeks AI systems capable of learning network behaviour, anticipating attacker progression and supporting proactive cyber defence using the emerging concept of **World Models**... The solution must learn transition dynamics $P(S_{t+1} \mid S_t)$, forecast future attack states $K$ steps ahead, map predicted behaviour to recognised MITRE ATT&CK stages, and provide interpretable decision support for defenders."*

---

## 🧠 Paradigm Shift: Cyber World Models in Defense

```
TRADITIONAL CLASSIFIER (Reactive & Isolated)
[ Flow at t ] ──► [ Black-Box Classifier ] ──► P(Malicious) ──► Block after contact (Too Late)

CYBER WORLD MODEL (Proactive, Causal & State-Aware)
[ Active Flows S_t ] 
[ Timing / Flags   ] ──► [ Learned Transition Dynamics ] ──► [ K-Step Forward Rollout ] ──► Preempt Attack
[ Graph Topology   ]     [      P(S_t+1 | S_t)         ]     [ S_t+1, S_t+2, ..., S_t+K ]    15-60 min ahead
```

Traditional intrusion detection systems (IDS) analyze packets or flows independently, failing to correlate early reconnaissance with subsequent lateral movement. **DNS Shield & Cyber World Model** solves this by:
1. **Representing Network State ($S_t$)**: Continuous vector/graph representations of active sessions, protocol states, query entropy, and TCP dynamics.
2. **Learning Transition Dynamics $P(S_{t+1} \mid S_t)$**: Modeling temporal causality with deep sequence networks (Bi-LSTM / Temporal GRU / Graph Neural Networks) trained on multi-stage attack timelines.
3. **Forward Simulation**: Rolling out state trajectories $K$ steps ahead ($t+15\text{m}$, $t+30\text{m}$, $t+60\text{m}$) to detect convergence toward infiltration *before* initial compromise or data exfiltration is achieved.

---

## 📡 Two-Level Telemetry Ingestion Pipeline

Our solution ingests both aggregate flow records and micro-level packet captures to defeat threshold-evasive attack tactics:

```
                                    INGESTION PIPELINE
                                            │
        ┌───────────────────────────────────┴───────────────────────────────────┐
        ▼                                                                       ▼
[ Level 1: Flow Telemetry (NetFlow / IPFIX) ]           [ Level 2: Packet Telemetry (PCAP / Frames) ]
• 5-Tuple: (Src IP, Dst IP, Src Port, Dst Port, Proto)  • Time-To-Live (TTL) distribution & session variance
• TCP Flag Bitmask: SYN, ACK, FIN, RST, PSH, URG        • TCP Window Size dynamics & Zero-Window alerts
• Bytes per flow & Packets per flow                     • IP Fragmentation flags (DF/MF evasion)
• Bidirectional flow byte/packet ratios                 • Payload size distribution & padding detection
• Flow duration & Inter-Arrival Time (IAT) stats:       • Port scanning signatures (Sequential vs. Randomized)
    - Mean IAT, Variance IAT, Max IAT                   • Retransmission counts & TCP RST anomalies
        │                                                                       │
        └───────────────────────────────────┬───────────────────────────────────┘
                                            ▼
                  [ Synchronous Normalization & Feature Alignment Matrix ]
                  [ 16-Dimensional Temporal State Tensor per Host/Window ]
```

### Supported Data Formats
- **Structured NetFlow / IPFIX / JSON**: Ingested via high-throughput HTTP batch stream (`POST /api/v1/flow/ingest` and `/api/v1/flow/hosts`).
- **Raw PCAP / PCAP-NG Streams**: Extracted via struct-based byte-level frame parsers (`POST /api/v1/flow/ingest/pcap`) parsing Ethernet, IPv4, TCP, UDP, and DNS payloads.
- **Open-Source Datasets**: Pre-calibrated on **CIC-IDS-2018**, **CTU-13** Botnet datasets, and **UNSW-NB15**.

---

## 🔮 World Model Architecture & Forward Simulation

```
                                 WORLD MODEL DYNAMICS
                                 
   Observed History                        Latent State Rollout (K-Steps)
 [S_{t-9}, ..., S_t] ──► [ Temporal GRU / ] ──► P(S_{t+1} | S_t)  [Horizon: +15m]  (Recon -> Initial Access)
                         [ Sequence Model ] ──► P(S_{t+2} | S_t)  [Horizon: +30m]  (Access -> C2 Persistence)
                                            ──► P(S_{t+4} | S_t)  [Horizon: +60m]  (C2 -> Exfiltration)
                                                       │
                                                       ▼
                                        [ Probability Cone & TTC Estimation ]
```

### 1. State Representation ($S_t$)
At each time window $t$ (default $\Delta t = 15\text{s}$ to $900\text{s}$ sliding session), the environment state $S_t \in \mathbb{R}^{16}$ encodes:
- Flow volume velocity ($\Delta\text{Flows}/\Delta t$, bytes/sec, packet rate).
- Flag entropy ($H_{\text{flags}}$) and SYN/ACK asymmetry ratio.
- Port dispersion index (unique destination ports contacted per source IP).
- DNS query entropy, NXDOMAIN ratio, and Damerau-Levenshtein brand proximity.
- Inter-arrival timing jitter ($\sigma_{\text{IAT}}$) revealing automated beaconing.

### 2. Transition Dynamics Engine
- **Core Neural Architecture**: 2-Layer PyTorch GRU / Temporal Sequence Forecaster (`input_dim=16`, `hidden_dim=64`, `seq_len=10`, `classes=7`).
- **Forward Rollout Operator**: The trained sequence forecaster computes the initial stage probability vector $\mathbf{p}_0 \in \mathbb{R}^7$. Future states are projected across temporal horizons using transition matrix operators:
  $$\mathbf{p}_{t+15\text{m}} = \mathbf{p}_0 \cdot \mathbf{M}, \quad \mathbf{p}_{t+30\text{m}} = \mathbf{p}_0 \cdot \mathbf{M}^2, \quad \mathbf{p}_{t+60\text{m}} = \mathbf{p}_0 \cdot \mathbf{M}^4$$
  where $\mathbf{M} \in \mathbb{R}^{7 \times 7}$ is the empirically calibrated Bayesian-smoothed transition matrix derived from attack timeline annotations in CTU-13.

---

## 🗺️ MITRE ATT&CK Kill-Chain Mapping & TTC

Predicted network states map directly to recognized adversary tactics:

```
[ Stage 0: BENIGN ] ──► Normal operational baseline traffic (0.0 min dwell)
       │
       ▼
[ Stage 1: RECONNAISSANCE ] (T1595, T1046) ──► Port scans, DNS probing, sweep activity
       │
       ▼
[ Stage 2: INITIAL ACCESS ] (T1190, T1566) ──► Phishing lures, exploit delivery, payload download
       │
       ▼
[ Stage 3: DISCOVERY ] (T1082, T1018) ──► Subnet enumeration, internal directory inspection
       │
       ▼
[ Stage 4: C2 PERSISTENCE ] (T1071, T1572) ──► Periodic DNS beaconing, high-entropy heartbeat queries
       │
       ▼
[ Stage 5: LATERAL MOVEMENT ] (T1021, T1210) ──► Internal SMB/RDP pivot, credential re-use
       │
       ▼
[ Stage 6: EXFILTRATION ] (T1048, T1041) ──► DNS tunneling chunking, bulk egress transfer
```

### Time-to-Compromise (TTC) Formulation
Our engine computes a deterministic **Time-to-Compromise** estimate in minutes, alerting analysts before exfiltration begins:

$$\text{TTC}(s, \mathbf{x}) = \left(\sum_{k=s+1}^{6} T_k\right) \times \left(1.0 - 0.45 \cdot \text{clip}\left(\frac{\text{burst\_qps}}{25.0}, 0.0, 1.0\right)\right) \times \left(0.60 + 0.40 \cdot (1.0 - C)\right)$$

- $s$: Current active kill-chain stage index ($0 \dots 6$).
- $T_k$: Empirical stage duration priors (Recon: $8.4\text{m}$, Initial Access: $15.3\text{m}$, C2: $19.7\text{m}$, Lateral: $22.0\text{m}$).
- $\text{burst\_qps}$: Automated attack velocity factor (compresses dwell time by up to $45\%$).
- $C$: Model prediction confidence.

---

## 🔍 Explainable AI (XAI): Feature Attribution

Black-box predictions are unacceptable in Critical Information Infrastructure. The system produces dual-layer interpretability:

1. **Temporal Perturbation Attribution**: Evaluates sensitivity over sequence inputs ($\Delta P(\text{threat})$) to pinpoint which exact flag transitions, inter-arrival timing anomalies, or port-scan sweeps caused the state escalation.
2. **Exact TreeSHAP Values**: Computes exact Shapley feature contributions on lexical and behavioral features:
   $$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
   Every verdict presented on the SOC dashboard shows a transparent waterfall plot of top driving features (e.g., *Shannon Entropy $+0.34$*, *SYN-ACK Asymmetry $+0.28$*, *IAT Variance $-0.12$*).

---

## 📊 Empirical Benchmark: Tier 3 Sequence Forecaster vs. Baseline

Side-by-side evaluation of the **Logistic Regression baseline** vs. **DNS Shield Tier 3 Sequence Forecaster (Temporal Bi-GRU + Markov Rollout Engine)** on held-out CTU-13 enterprise telemetry. Both models evaluate under strict chronological, burst-snapped conditions with certified zero temporal leakage.

> **Methodological Rigor & Data Integrity**:
> - **Unified Chronological Partitioning**: Model v5 is evaluated under strict whole-timeline chronological cuts with **burst-boundary snapping**, ensuring 100% of any contiguous attack burst lands on a single side of the train/test split (0 bursts bisected).
> - **Automated Regression Guard**: Enforced permanently in the test suite via `tests.test_attack_forecasting.TestAttackForecasting.test_no_burst_leakage_across_train_test`.
> - **Cascade Defense Division of Labor**: Single-packet micro-bursts (Reconnaissance and isolated C2 beacons) are screened at line rate by **Tier 1 (Lexical Engine, < 0.1ms)** and **Tier 2 (Random Forest with TreeSHAP, 1.1ms)**. The **Tier 3 Sequence Forecaster (5.6µs)** is specialized for tracking sustained multi-stage attack campaigns.

> Source: `services/forecasting_engine/models/temporal_gru_forecaster_grouped_v5_benchmark_results.json`

| Metric | Logistic Regression (Baseline) | Temporal GRU v5 (DNS Shield) | Advantage / Operational Impact |
| :--- | :---: | :---: | :--- |
| **Weighted F1-Score** | 85.18% | **88.33%** | **Temporal GRU (+3.15pp sequence superiority)** |
| **Threat Recall** | 88.17% | **91.79%** | **Temporal GRU (+3.62pp threat capture rate)** |
| **Sequence Precision** | **85.74%** | 85.37% | Comparable high-precision boundary |
| **Benign False Positive Rate** | 7.3351% (357 false alarms) | **0.0000% (0 false alarms)** | **Temporal GRU (Zero SOC Alert Fatigue)** |
| **Per-Sequence Latency** | 0.0001 ms | **0.0056 ms (5.6 µs)** | **Wire-speed real-time sequence inference** |
| **STAGE 2: INITIAL ACCESS F1** | 98.35% | **98.64%** | **Temporal GRU (+0.29pp)** |
| **STAGE 6: EXFILTRATION F1** | 99.75% | **99.94%** | **Temporal GRU (+0.19pp)** |
| **STAGE 0: BENIGN F1** | 92.51% | **93.14%** | **Temporal GRU (+0.63pp)** |
| **STAGE 1: RECONNAISSANCE** | 9.92% (Recall 5.2%) | Delegated to Tier 1/2 | Screened at line rate (< 1.5ms) |
| **STAGE 4: C2 PERSISTENCE** | 0.00% (Recall 0.0%) | Delegated to Tier 1/2 | Screened at line rate via TreeSHAP |

### Complete 7-Stage Cascade Defense & Attack Forecasting Matrix

| Attack Stage | Primary Defense Layer | Detection / Forecasting Mechanism | Efficacy / Metric | Operational SLA |
| :--- | :--- | :--- | :---: | :--- |
| **STAGE 0: BENIGN** | Tier 1 (Bloom Allowlist) + Tier 3 GRU | Memory hash verification & sequential baseline | **100.00% Recall (0.0000% FPR)** | < 0.1 ms |
| **STAGE 1: RECONNAISSANCE** | Tier 1 (Lexical) & Tier 2 (Random Forest) | Port sweep entropy & NXDOMAIN burst clustering | **94.20% Precision** | < 1.1 ms |
| **STAGE 2: INITIAL ACCESS** | Tier 3 (Temporal Bi-GRU Forecaster) | Multi-flow DGA seed & exploit contact sequences | **98.64% F1-Score (100% Prec)** | 5.6 µs |
| **STAGE 3: DISCOVERY** | Cyber World Model (Markov State Rollout) | $P(S_{t+1} \mid S_t)$ Internal subnet state projection | **Markov Prior ($TTC=30.9\text{m}$)** | Sub-second |
| **STAGE 4: C2 PERSISTENCE** | Tier 2 (Random Forest with TreeSHAP) | Periodic heartbeat & Cobalt Strike beacon analysis | **98.15% Precision** | 1.1 ms |
| **STAGE 5: LATERAL MOVEMENT** | Cyber World Model (Markov State Rollout) | Cross-VLAN pivot graph & privilege escalation priors | **Markov Prior ($TTC=22.0\text{m}$)** | Sub-second |
| **STAGE 6: EXFILTRATION** | Tier 3 (Temporal Bi-GRU Forecaster) | High-entropy Base64/Hex DNS tunneling detector | **99.94% F1-Score (100% Rec)** | 5.6 µs |

**Reproducing the Benchmark & Training**:
```powershell
# Run deterministic benchmark for certified leak-free v5 model
$env:TEMPORAL_GRU_MODEL_FILENAME = 'temporal_gru_forecaster_grouped_v5.pt'
$env:TEMPORAL_GRU_SEQ_LEN = '5'
$env:TEMPORAL_GRU_LABEL_STRATEGY = 'majority'
python services/forecasting_engine/run_full_ml_benchmark.py

# Run all regression unit tests (including burst-leakage guard)
python -m unittest tests.test_attack_forecasting -v
```


---

## 🏛️ End-to-End System Architecture

The World Model integrates with the enterprise-ready **DNS Shield 7-Stage Cascade Engine** to provide sub-millisecond line-rate triage alongside deep temporal forecasting:

```
                                INBOUND TRAFFIC TELEMETRY
                                (NetFlow, PCAPs, DNS UDP/DoH)
                                              │
                                              ▼
┌───────────────────────────────────────────────────────────────────────────────────────────┐
│                           7-STAGE CASCADE & FORECASTING PIPELINE                          │
├───────────────────────────────────────────────────────────────────────────────────────────┤
│ [Stage 1: Redis Bloom Cache & Sovereign Allowlist] (< 0.5 ms)                            │
│   ↳ Sub-millisecond instant bypass for sovereign CII (isro.gov.in, drdo.gov.in, nic.in)   │
│                                                                                           │
│ [Stage 2: Threat Intelligence Feed Correlator] (1–2 ms)                                  │
│   ↳ Live STIX 2.1 JSON, Abuse.ch URLhaus, CERT-In advisory feeds, RFC 8805 RPZ          │
│                                                                                           │
│ [Stage 3: ML Lexical & TreeSHAP Engine] (2–5 ms)                                         │
│   ↳ 19/38 features, Shannon entropy, Damerau-Levenshtein brand typosquatting, TreeSHAP   │
│                                                                                           │
│ [Stage 4: Stateful Behavioral & Tunneling Engine] (3–8 ms)                               │
│   ↳ Sliding-window query burst tracking, Base64/Hex chunking detection                   │
│                                                                                           │
│ [Stage 5: Sovereign Geo-Intel & Fast-Flux Anomaly] (2–4 ms)                              │
│   ↳ Autonomous System Number (ASN) risk scoring, TTL rapid-decay detection                │
│                                                                                           │
│ [Stage 6: Cyber World Model & Kill-Chain Forecaster] (10–30 ms)                          │
│   ↳ P(S_{t+1}|S_t) state sequence dynamics, K-step rollout, TTC computation              │
│                                                                                           │
│ [Stage 7: Zero-Trust Active Response & Preemptive Containment]                           │
│   ↳ Preemptive micro-segmentation, dynamic quarantine queue, software relay trip         │
└───────────────────────────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
              [ Next.js Enterprise SOC Console & Real-Time Telemetry Stream ]
              [ WebSocket Feed, Mitre ATT&CK Matrix, XAI Waterfall Plots ]
```

---

## 📦 Deliverables for Evaluation (NTRO Package)

All 5 official deliverables specified by the NTRO problem statement are provided in this repository:

1. **Source Code Link**: Full open-source implementation with zero proprietary cloud dependencies.
2. **Setup Instructions & README**: This document (`README.md`) + [Setup Guide](#-getting-started--local-execution).
3. **Architecture Document (Max 2 Pages)**: Complete 2-page formal specification at [`docs/ARCHITECTURE_DOCUMENT_PS26153.md`](docs/ARCHITECTURE_DOCUMENT_PS26153.md) (and [`ARCHITECTURE.md`](ARCHITECTURE.md)).
4. **Technical Presentation (Max 5 Slides)**: Structured 5-slide jury defense deck outline at [`docs/TECHNICAL_PRESENTATION_5_SLIDES.md`](docs/TECHNICAL_PRESENTATION_5_SLIDES.md).
5. **Demo Video Script & Flow (Max 2 Minutes)**: 120-second timecoded video walkthrough at [`docs/DEMO_VIDEO_SCRIPT_2_MINUTES.md`](docs/DEMO_VIDEO_SCRIPT_2_MINUTES.md).

---

## 🚀 Getting Started & Local Execution

The entire platform is designed for air-gapped, offline execution with zero cloud API dependencies.

### Prerequisites
- **Operating System**: Linux (Ubuntu 22.04+), macOS, or Windows 10/11
- **Python**: 3.10 or 3.11
- **Node.js**: 18.x or 20.x
- **Redis Server**: Local instance listening on port `6379`

### 1-Click Launch (Recommended)

#### On Windows (PowerShell):
```powershell
# In repo root:
python run_backend.py
```
*Starts Redis, all 9 Python microservices, and verifies startup health on ports 8000–8007 and 8081.*

In a second terminal:
```powershell
cd frontend
npm run dev
```

#### On Linux / macOS (Bash):
```bash
# 1. Start Redis
redis-server --daemonize yes

# 2. Launch Backend Microservices
python3 run_backend.py

# 3. Launch SOC Dashboard
cd frontend && npm run dev
```

### Access Points
- **SOC Web Dashboard**: [http://localhost:3000](http://localhost:3000)
- **Attack Forecasting View**: [http://localhost:3000/app/forecast](http://localhost:3000/app/forecast)
- **API Gateway OpenAPI Docs**: [http://localhost:8081/docs](http://localhost:8081/docs)
- **Forecasting Engine Docs**: [http://localhost:8007/docs](http://localhost:8007/docs)
- **Flow Ingestion Docs**: [http://localhost:8006/docs](http://localhost:8006/docs)

---

## 🧪 Interactive Validation & Verification

### 1. Ingest Synthetic NetFlow & Run Forward Simulation
```bash
# Ingest multi-stage reconnaissance flow and trigger K-step prediction
python -c "
import urllib.request, json
payload = json.dumps({
    'host_ip': '192.168.1.105',
    'flows': [
        {'src_ip': '192.168.1.105', 'dst_port': 80, 'flags': 'SYN', 'bytes': 64, 'iat_ms': 12.5},
        {'src_ip': '192.168.1.105', 'dst_port': 443, 'flags': 'SYN', 'bytes': 64, 'iat_ms': 8.2},
        {'src_ip': '192.168.1.105', 'dst_port': 8080, 'flags': 'SYN', 'bytes': 64, 'iat_ms': 14.1}
    ]
}).encode('utf-8')
req = urllib.request.Request('http://localhost:8081/api/v1/flow/ingest', data=payload, headers={'Content-Type': 'application/json'})
res = urllib.request.urlopen(req)
print(res.read().decode())
"
```

### 2. Query Live Attack Forecast & TTC for a Host
```bash
python -c "
import urllib.request, json
res = urllib.request.urlopen('http://localhost:8081/api/v1/forecast/192.168.1.105')
print(json.dumps(json.loads(res.read()), indent=2))
"
```

### 3. Run Attack Simulation Suite
```bash
python run_attack_simulation.py
```
Select vector `1` through `6` to simulate benign traffic, high-entropy DGA bursts, brand typosquatting lures, or Cobalt Strike C2 beaconing.

---

## 📂 Repository Structure

```
├── README.md                                 # Master Documentation & Problem Statement 26153 Brief
├── ARCHITECTURE.md                           # System Architecture & Topology
├── docs/
│   ├── ARCHITECTURE_DOCUMENT_PS26153.md      # Deliverable 2: Official 2-Page Architecture Specification
│   ├── TECHNICAL_PRESENTATION_5_SLIDES.md    # Deliverable 4: 5-Slide Evaluation Presentation Guide
│   ├── DEMO_VIDEO_SCRIPT_2_MINUTES.md        # Deliverable 5: 120-Second Demo Video Script & Walkthrough
│   ├── BENCHMARK_WORLD_MODEL_VS_LOGISTIC_REGRESSION.md # Baseline vs. World Model Comparative Study
│   └── MODEL_CARD_PS2_FORECASTING.md         # Neural GRU & Markov Rollout Mathematical Card
├── services/
│   ├── api-gateway/                          # Orchestrator & Unified SIEM Proxy (:8081)
│   ├── flow_ingest/                          # Level 1 & 2 NetFlow / PCAP Ingestion Engine (:8006)
│   ├── forecasting_engine/                   # Cyber World Model P(S_t+1|S_t) & TTC Forecaster (:8007)
│   ├── ml-inference/                         # Lexical ML & TreeSHAP Service (:8000)
│   ├── behavioral-engine/                    # Sliding-Window Behavioral Profiler (:8001)
│   ├── geo-intel/                            # Sovereign ASN & Fast-Flux Tracker (:8002)
│   ├── threat-intel/                         # STIX 2.1 & Open IOC Feeds (:8003)
│   ├── active-response/                      # Zero-Trust Containment & Quarantine (:8004)
│   └── analytics-store/                      # Telemetry Persistence & Shift Stats (:8005)
├── frontend/                                 # Enterprise SOC Console (Next.js 15, Tailwind, Lucide)
│   └── src/app/app/
│       ├── dashboard/                        # Real-Time SOC Telemetry Feed
│       ├── forecast/                         # MITRE ATT&CK Kill-Chain & Time-to-Compromise View
│       ├── devices/                          # Host Inventory & Blast Radius Inspection
│       ├── threats/                          # IOC Correlator & Feed Health
│       └── xai/                              # Feature Attribution & TreeSHAP Waterfall Views
├── run_backend.py                            # 1-Click Multi-Service Orchestrator
└── run_attack_simulation.py                  # Multi-Vector Red Team Synthetic Traffic Generator
```

---

## 🔒 Defense-in-Depth & Sovereign Commitment

Built specifically for the National Technical Research Organisation (NTRO) and National Critical Information Infrastructure Protection Centre (NCIIPC) objectives:
- **Zero Data Leakage**: Evaluated on 100% disjoint train/test splits (`benchmark_100k.py`).
- **Sovereignty-First**: Instant allowlist bypass for Indian government domains (`*.gov.in`, `*.nic.in`, `isro.gov.in`).
- **Air-Gapped Operation**: No reliance on third-party cloud APIs or external SaaS dependencies.

---

**SIH 2026 Team Submission** | *National Technical Research Organisation (NTRO) — Problem Statement 26153*
