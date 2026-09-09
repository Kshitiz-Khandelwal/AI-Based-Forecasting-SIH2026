# DNS Shield & Cyber World Model — System Architecture
> **Problem Statement ID**: 26153 | **Organization**: National Technical Research Organisation (NTRO)  
> **Challenge**: AI based Network Attack Forecasting from Network Traffic Data  
> **Official 2-Page Deliverable**: See [`docs/ARCHITECTURE_DOCUMENT_PS26153.md`](docs/ARCHITECTURE_DOCUMENT_PS26153.md)  
> **Version**: 3.0 (World Model & Dual-Level Telemetry Release)  
> **Status**: `[IMPLEMENTED ✅]` Multi-service temporal forecasting pipeline and Next.js 15 SOC dashboard.

---

## 1. High-Level Topology: Fast-Path Defense & Cyber World Model

The system integrates synchronous line-rate DNS filtering (< 10 ms SLA) with deep temporal attack progression forecasting ($15 \dots 60\text{ minutes}$ ahead) using a Cyber World Model that learns network state dynamics $P(S_{t+1} \mid S_t)$.

```mermaid
flowchart TD
    %% Telemetry Ingestion
    subgraph Ingestion [Dual-Level Telemetry Ingestion]
        T1[Level 1: NetFlow / IPFIX\n5-tuple, TCP flags, IAT stats, byte ratios]
        T2[Level 2: Packet PCAP Stream\nTTL variance, Window size, Port scan seq]
        T3[DNS Queries: UDP 53 / DoH 443]
    end

    %% Ingestion & Normalizer
    Ingestion --> GW[API Gateway Orchestrator\nPort 8081]
    Ingestion --> FI[Flow Ingestion Engine\nPort 8006]

    %% Fast Path Layer
    subgraph FastPath [Fast-Path Triage Layer (< 5 ms)]
        GW --> Redis[(Redis In-Memory\nBloom Filter & Hot Cache)]
        GW --> TI[Threat Intel Service\nPort 8003]
        GW --> Geo[Geo-Intel & ASN\nPort 8002]
    end

    %% Deep Analysis Layer
    subgraph DeepAnalysis [Lexical & Behavioral Layer]
        GW --> ML[ML Lexical & TreeSHAP\nPort 8000]
        GW --> BE[Behavioral Sliding Window\nPort 8001]
    end

    %% Cyber World Model Layer
    subgraph WorldModel [Cyber World Model & Forecasting Engine]
        FI --> StateBuf[16-Dim State Tensor S_t\nSliding 900s Session Buffer]
        StateBuf --> FE[Forecasting Engine\nPort 8007\nPyTorch Bi-GRU Sequence Forecaster]
        FE --> Rollout[K-Step Forward Rollout\nt+15m, t+30m, t+60m Horizons]
        FE --> TTC[Time-to-Compromise Estimator\nFormal Bayesian Prior Calculation]
        FE --> XAI[Dynamic Sequence Perturbation\nFeature Attribution]
    end

    %% Proactive Action & Telemetry
    subgraph Response [Proactive Defense & SOC Telemetry]
        GW --> AR[Active Response\nPort 8004\nQuarantine & Micro-Segmentation]
        GW --> DB[(Analytics Store\nPort 8005)]
        WorldModel --> AR
        WorldModel --> UI[Enterprise SOC Dashboard\nNext.js 15 App Router\nPort 3000]
    end
```

---

## 2. Microservice Port Specifications & Roles

| Service | Port | Primary Responsibility | Key Libraries & Technologies |
| :--- | :---: | :--- | :--- |
| **`api-gateway`** | `:8081` | Central API orchestrator, rate limiter, and fast-to-deep router | FastAPI, Requests, Redis client, Pydantic |
| **`flow_ingest`** | `:8006` | Ingests NetFlow/IPFIX JSON and raw PCAP frame streams (Levels 1 & 2) | Scapy/struct, NumPy, Pandas |
| **`forecasting_engine`** | `:8007` | Cyber World Model $P(S_{t+1}\mid S_t)$, $K$-step rollout, and TTC | PyTorch Bi-GRU, Markov Matrix, SciPy |
| **`ml-inference`** | `:8000` | 19-feature lexical classifier with exact TreeSHAP attribution | scikit-learn, LightGBM, SHAP, Joblib |
| **`behavioral-engine`**| `:8001` | Sliding-window host profiling and burst QPS tracking | Redis sorted sets, Python collections |
| **`geo-intel`** | `:8002` | Sovereign IP, ASN risk scoring, and fast-flux TTL decay tracking | MaxMind GeoLite2, IPWhois |
| **`threat-intel`** | `:8003` | Live STIX 2.1 JSON parser, URLhaus, and CERT-In IOC feeds | Python, Redis cache |
| **`active-response`** | `:8004` | Preemptive micro-segmentation, quarantine, and emulated relay | REST API, Software GPIO driver |
| **`analytics-store`** | `:8005` | Telemetry persistence, shift reporting, and metric rollups | SQLite / Redis / JSONL logs |
| **`frontend`** | `:3000` | Enterprise SOC Console, MITRE matrix, and forecasting UI | Next.js 15 (App Router), Tailwind CSS, Lucide |

---

## 3. Resilience, Fail-Open & Degradation Architecture

To protect Critical Information Infrastructure without creating a single point of failure:
1. **Synchronous DNS Fail-Open**: If the deep forecasting engine or behavioral profiler experiences queue saturation, DNS resolution instantly falls back to fast-path Redis Bloom filters and local deterministic rules in $< 1\text{ ms}$, ensuring network uptime.
2. **Offline Air-Gapped Operation**: All models, threat intelligence caches, and UI assets are hosted locally. Zero external API calls to public cloud providers are made.
3. **Formal Mathematical Explainability**: No black-box outputs. Predictions are paired with exact TreeSHAP values ($\phi$) and dynamic sequence perturbation scores ($\Delta P(\text{threat})$).

---

For full architectural blueprints, mathematical formulas, and benchmark comparisons, refer to:
- [`docs/ARCHITECTURE_DOCUMENT_PS26153.md`](docs/ARCHITECTURE_DOCUMENT_PS26153.md) (Official 2-Page Architecture Deliverable)
- [`docs/TECHNICAL_PRESENTATION_5_SLIDES.md`](docs/TECHNICAL_PRESENTATION_5_SLIDES.md) (5-Slide Jury Defense Deck)
- [`docs/DEMO_VIDEO_SCRIPT_2_MINUTES.md`](docs/DEMO_VIDEO_SCRIPT_2_MINUTES.md) (2-Minute Demo Video Script)
- [`docs/BENCHMARK_WORLD_MODEL_VS_LOGISTIC_REGRESSION.md`](docs/BENCHMARK_WORLD_MODEL_VS_LOGISTIC_REGRESSION.md) (Benchmark Study)
