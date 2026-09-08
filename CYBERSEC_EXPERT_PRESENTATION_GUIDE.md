# 🛡️ DNS Shield — Cybersecurity Expert Presentation & Defense Guide
### *A Rigorous, Audited Technical Walkthrough for Cybersecurity Professionals, Evaluators & Judges*

---

## 📑 Executive Overview & Table of Contents

This presentation guide is strictly calibrated against the actual files, models, and datasets currently committed in the repository. **Every single number, formula, dataset size, and feature name cited here is verified and reproducible from source artifacts via `python scripts/generate_presentation_numbers.py`.**

1. [The 30-Second Security Pitch](#1-the-30-second-security-pitch)
2. [Audited Repository Facts & True Dataset Scale](#2-audited-repository-facts--true-dataset-scale)
3. [Pillar 1: 7-Stage Zero-Trust DNS Defense Pipeline](#3-pillar-1-7-stage-zero-trust-dns-defense-pipeline)
4. [Pillar 2: Temporal AI Attack Forecasting Engine](#4-pillar-2-temporal-ai-attack-forecasting-engine)
5. [The Exact 16 GRU Network Flow Features](#5-the-exact-16-gru-network-flow-features)
6. [Markov Prior Calibration & Contiguous Dwell Times](#6-markov-prior-calibration--contiguous-dwell-times)
7. [Hardware Sentinel & Zephyr RTOS Air-Gap Signal](#7-hardware-sentinel--zephyr-rtos-air-gap-signal)
8. [Dashboard Walkthrough (Button by Button)](#8-dashboard-walkthrough-button-by-button)
9. [Anticipated Technical Questions & Hard Defenses](#9-anticipated-technical-questions--hard-defenses)

---

## 1. The 30-Second Security Pitch

> *"Traditional DNS firewalls and SIEMs are purely reactive: they only alert you after an adversary has already resolved a C2 domain or exfiltrated data. DNS Shield solves this with two tightly integrated subsystems:*
> 1. *A **sub-millisecond 7-Stage Cascading DNS Interceptor** that filters safe traffic in $<0.05\text{ms}$ and applies real TreeSHAP game-theoretic explainability to block zero-day DGA and covert DNS tunneling in $<1.2\text{ms}$.*
> 2. *A **Temporal AI Attack Forecasting Engine** that analyzes host network flow sequences with a PyTorch 2-Layer GRU and an empirically calibrated Markov chain to predict where an attacker is progressing across the MITRE ATT&CK kill chain 15, 30, and 60 minutes before compromise occurs."*

---

## 2. Audited Repository Facts & True Dataset Scale

To maintain absolute credibility before technical evaluators, DNS Shield quotes only verified dataset sizes from disk:

| Component | Repository File Path | Audited Size / Metric | Purpose |
| :--- | :--- | :---: | :--- |
| **ML Lexical Training Set** | `data/dga_dataset.csv` | **$10,000$ labeled domains** | Trains Random Forest & LightGBM lexical classifiers (Tranco benign vs. 5 DGA families). |
| **Leak-Free Benchmark Corpus** | `data/eval_100k_domains.csv` | **$110,150$ domains** | Rigorous offline generalization evaluation across 5 stratified splits without data leakage. |
| **CTU-13 Multistage NetFlows** | `data/ctu13_multistage_flows.csv` | **$83,010$ flow records** | Real multi-scenario botnet captures used to train the GRU and calibrate Markov state priors. |
| **Sequential Markov Transitions** | `services/forecasting_engine/priors.json` | **$60,273$ transitions** | Empirical transitions observed between consecutive flow windows across CTU-13 scenarios. |
| **Active Threat Intel IOC Cache** | `services/threat-intel/data/ioc_cache.jsonl` | **$138$ curated indicators** | Verified live malicious IPs and DGA domains synced from threat feeds. |
| **Enterprise Authority Allowlist** | `data/dns_shield_allowlist.txt` | **$30$ verified roots** | High-authority sovereign and cloud infrastructure roots (ISRO, NIC, Google, Cloudflare). |

*(Run `python scripts/generate_presentation_numbers.py` at any time to regenerate and verify these exact numbers).*

---

## 3. Pillar 1: 7-Stage Zero-Trust DNS Defense Pipeline

DNS Shield does not pass every packet to a heavy neural network. Doing so would collapse enterprise throughput. Instead, it short-circuits queries through a **7-stage zero-trust cascade**:

```
Incoming DNS Query (Port 53 UDP/TCP)
  │
  ├─► [Stage 1: Redis Bloom & Memory Cache] (< 0.05 ms) ──► 90%+ benign traffic instantly resolved
  │
  ├─► [Stage 2: Threat Intelligence Matcher] (< 0.30 ms) ──► 138 curated IOCs / STIX feeds blocked
  │
  ├─► [Stage 3: ML Lexical Analysis]        (< 1.20 ms) ──► 150-tree Random Forest on 10,000 domains
  │
  ├─► [Stage 4: Behavioral & Tunneling]     (< 2.50 ms) ──► Base64/Hex chunking & Shannon entropy
  │
  ├─► [Stage 5: GeoIP & Fast-Flux Tracker]  (< 3.80 ms) ──► Rapid TTL decay (<60s) & ASN dispersion
  │
  ├─► [Stage 6: Policy & Authority Arbiter] (< 4.20 ms) ──► Strict sovereign enterprise rules
  │
  └─► [Stage 7: TreeSHAP Forensic XAI]      (< 5.00 ms) ──► Exact mathematical feature attribution
```

### Why This Architecture Wins Over Black-Box Models:
1. **Sub-Millisecond Line Rate:** Over 90% of ordinary corporate lookups hit Stage 1, incurring $<0.05\text{ms}$ overhead.
2. **True Game-Theoretic Explainability:** When Stage 3 or 4 flags a zero-day domain, Stage 7 computes **TreeSHAP** Shapley values ($\phi_i$):
   $$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
   It mathematically substantiates whether the block was caused by Shannon entropy, consonant clustering, or high-risk TLD, providing auditable evidence for compliance and forensics.

---

## 4. Pillar 2: Temporal AI Attack Forecasting Engine

While traditional intrusion detection systems alert on historical events ($t \le 0$), DNS Shield forecasts future trajectory across the **6 canonical MITRE ATT&CK Kill-Chain stages**:
`STAGE_0_BENIGN ➔ STAGE_1_RECON ➔ STAGE_2_INITIAL_ACCESS ➔ STAGE_3_DISCOVERY ➔ STAGE_4_C2 ➔ STAGE_5_LATERAL ➔ STAGE_6_EXFILTRATION`.

### Two-Tier Hybrid Architecture:
1. **Current State Inference ($t = 0$):**
   - **Model:** PyTorch 2-Layer Gated Recurrent Unit (GRU) (`services/forecasting_engine/models/temporal_gru_forecaster.pt`).
   - **Input:** Sequence of 10 consecutive flow windows, each parameterized by 16 network telemetry features.
   - **Output:** Softmax probability distribution over kill-chain stages (e.g., $95.2\%$ probability host is currently in `STAGE_1_RECONNAISSANCE`).
2. **Future Horizon Projection ($+15\text{m}, +30\text{m}, +60\text{m}$):**
   - Takes the active GRU probability vector $\mathbf{s}_0$ and rolls it forward using the CTU-13 Markov Transition Matrix $\mathbf{P}$:
     $$\mathbf{s}_k = \mathbf{s}_0 \cdot \mathbf{P}^k$$
   - Provides future stage predictions with calibrated confidence cones (`[min_prob, max_prob]`).
3. **Time-to-Compromise (TTC):**
   - Calculates estimated minutes until full exfiltration (`STAGE_6_EXFILTRATION`) by summing the calibrated dwell times of intervening stages.

---

## 5. The Exact 16 GRU Network Flow Features

The temporal feature extractor (`services/forecasting_engine/temporal_feature_extractor.py::FEATURE_NAMES`) extracts **exactly 16 normalized numeric features** per flow window:

| Index | Feature Name | Description | Forensic Relevance |
| :---: | :--- | :--- | :--- |
| **1** | `duration_sec` | Total flow duration in seconds | Long-lived TCP streams indicate interactive C2 shells. |
| **2** | `total_packets` | Total packet count in window | Volumetric tracking for scan bursts vs. trickle beacons. |
| **3** | `total_bytes` | Cumulative byte count | Egress volume monitoring for data exfiltration spikes. |
| **4** | `src_bytes` | Outbound bytes from monitored host | Identifies exfiltration uploads vs. inbound file downloads. |
| **5** | `dst_bytes` | Inbound bytes returned to host | Responses from C2 controllers or external targets. |
| **6** | `bytes_per_sec` | Flow byte rate (bandwidth density) | Differentiates low-and-slow heartbeats from bulk egress. |
| **7** | `packets_per_sec` | Flow packet rate (cadence density) | High packet frequency indicates SYN sweeps or port scans. |
| **8** | `avg_packet_size` | Average bytes per packet | Small packets imply DNS queries; large imply bulk tunneling. |
| **9** | `is_tcp` | Binary flag for TCP protocol | TCP handshakes for web protocols, SSH, or reverse shells. |
| **10** | `is_udp` | Binary flag for UDP protocol | UDP transport used by standard DNS and amplification attacks. |
| **11** | `is_icmp` | Binary flag for ICMP protocol | Network sweeps, ping sweeps, and ICMP covert tunneling. |
| **12** | `is_dns_port` | Binary flag for Port 53 / 853 | Specifically isolates DNS control-plane traffic. |
| **13** | `is_web_port` | Binary flag for Ports 80, 443, 8080 | Identifies web C2 channels (HTTPS/REST beacons). |
| **14** | `is_lateral_port` | Binary flag for Ports 445, 139, 389, 88 | SMB, NetBIOS, LDAP, and Kerberos lateral movement probes. |
| **15** | `is_internal_dst` | Destination IP is in RFC 1918 range | Cross-subnet internal pivoting vs. external Internet egress. |
| **16** | `is_syn_or_scan` | TCP flags indicate SYN-only probe | Port sweeping and reconnaissance without completing handshake. |

*(Note: Never cite non-existent names like "port_diversity" or "payload_entropy" for the GRU—those belong to lexical and packet inspection tiers, not the temporal flow tensor).*

---

## 6. Markov Prior Calibration & Contiguous Dwell Times

The Markov transition matrix and stage dwell times were calibrated directly on the CTU-13 dataset using `calibrate_priors.py`. To prevent statistical distortions, two rigorous methodological corrections are enforced:

### 1. Scaled Bayesian Smoothing & Escalation Sanity Floor
- **The Defect Fixed:** Naive Laplace smoothing with fixed $\alpha=10$ caused $P(\text{Benign} \to \text{Recon})$ to collapse to $0.000028$ ($2.8 \times 10^{-5}$) due to $52,715$ benign self-transitions.
- **The Solution:** Effective sample size ceiling (`eff_sum = min(row_sum, 1000)`) with row-scaled smoothing weight $\alpha = \max(10, 0.08 \times \text{eff\_sum})$ and an explicit $2.5\%$ sanity floor on documented escalation paths.
- **Calibrated Value:** $P(\text{Benign} \to \text{Recon}) = 0.024658$ (~$2.47\%$) with $P(\text{Benign} \to \text{Benign}) = 0.975342$ ($97.53\%$).

### 2. Contiguous Run Wall-Clock Dwell Times (Option A)
- **The Defect Fixed:** Measuring time deltas between adjacent CSV rows measured NetFlow packet capture intervals rather than attacker dwell time.
- **The Solution:** Dwell times are computed across contiguous stage runs using the wall-clock span from the `StartTime` of the first flow to the `StartTime` of the last flow in that run plus that flow's `Dur` duration.

### Live-Audited Dual-Provenance Table:
*(Transition calibration and dwell-time calibration are presented as two independent dimensions—never conflated into a single blended badge).*

| Stage ID | Kill-Chain Stage | Dwell Time | Dwell Status & Sample | Transition Status & Sample | Real Data Coverage |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `STAGE_0_BENIGN` | 0 Benign Traffic | $0.0\text{ min}$ | `terminal_boundary_zero` ($N=22,714$) | `calibrated_empirical` ($N=52,715$) | `observed_in_ctu13` |
| `STAGE_1_RECONNAISSANCE` | 1 Reconnaissance | $8.4\text{ min}$ | `calibrated_empirical` ($N=65$ runs) | `calibrated_empirical` ($N=391$) | `observed_in_ctu13` |
| `STAGE_2_INITIAL_ACCESS` | 2 Initial Access | $15.3\text{ min}$ | `calibrated_empirical` ($N=1,622$ runs) | `calibrated_empirical` ($N=4,388$) | `observed_in_ctu13` |
| `STAGE_3_DISCOVERY` | 3 Subnet Discovery | $12.0\text{ min}$ | `expert_prior_default` ($N=0$ runs) | `expert_prior_default` ($N=0$) | **`no_real_examples_observed`** ⚠ |
| `STAGE_4_C2_PERSISTENCE` | 4 C2 Beaconing | $19.7\text{ min}$ | `calibrated_empirical` ($N=60$ runs) | `calibrated_empirical` ($N=332$) | `observed_in_ctu13` |
| `STAGE_5_LATERAL_MOVEMENT` | 5 Lateral Movement | $22.0\text{ min}$ | `expert_prior_default` ($N=2$ runs) | `expert_prior_default` ($N=2$) | `low_sample_support` |
| `STAGE_6_EXFILTRATION` | 6 Data Exfiltration | $0.0\text{ min}$ | `terminal_boundary_zero` ($N=1,557$) | `calibrated_empirical` ($N=2,445$) | `observed_in_ctu13` |

### Honest Defense for Evaluators:
- **Why does Stage 3 (Discovery) have $N=0$?** The CTU-13 dataset was captured in a laboratory environment where infected hosts communicated outbound with external botnet controllers; internal subnet scanning was not captured in these specific pcap captures. DNS Shield explicitly flags Discovery as `⚠ untested on real traffic` across the UI and model card rather than concealing this reality.
- **Why is $P(\text{Access} \to \text{Exfil})$ high ($0.327$)?** In automated botnet malware (e.g., Mirai, Neris), compromised devices immediately begin DDoS flood traffic or exfiltrating host credentials upon infection, skipping internal lateral reconnaissance entirely.

---

## 7. Hardware Sentinel & Zephyr RTOS Air-Gap Signal

To prevent catastrophic data loss during advanced APT exfiltration, DNS Shield implements a physical/emulated **Hardware Sentinel**:

```
[Forecasting Engine] (TTC < 15m or Stage 5/6 Detected)
        │
        ▼ (UART / GPIO REST Signal)
[Zephyr RTOS Microcontroller] (ESP32-S3 / RP2040 Sentinel)
        │
        ├─► Trip 5V Electromagnetic Isolation Relay (GPIO 18)
        ├─► Physical Air-Gap Disconnection of Compromised Trunk
        └─► OLED Visual Alert: "AIR-GAP ISOLATED - HOST 172.28.100.58"
```

* **Software Emulation Disclosure:** In standard software demo environments, the relay is software-emulated via GPIO 18 mock signals in `attack_forecaster.py` with an interactive toggle button in the console.

---

## 8. Dashboard Walkthrough (Button by Button)

When presenting `http://localhost:3000/app/forecast`:

| UI Element / Button | Underlying Mechanism | What to Point Out to Evaluators |
| :--- | :--- | :--- |
| **"Monitored Hosts" List** | Queries `GET /forecast/hosts` | Displays real-time monitored IP addresses, their GRU-inferred kill-chain stages, threat scores ($0\text{--}100$), and active flow counts. |
| **"Live Polling" (Green Badge)** | SWR / interval fetch (3s) | Auto-refreshes host threat states as new flow telemetries are ingested by the backend. |
| **"PCAP Ingestion" Dropzone** | `POST /flow/ingest/pcap` | Parses raw `.pcap` packets via `scapy`/`dpkt`, extracts 5-tuple flows, and evaluates them with the GRU sequence model. |
| **"Simulate Attack" Buttons** | `POST /forecast/simulate` | Injects synthetic multi-stage flow bursts (Port sweep $\to$ DGA query $\to$ C2 beaconing $\to$ Exfiltration) to demonstrate stage progression live. |
| **"TRIP AIR-GAP RELAY SIGNAL"** | `POST /forecast/relay/toggle` | Manually or automatically triggers the Zephyr RTOS GPIO 18 air-gap killswitch signal to isolate Patient Zero. |
| **"Kill-Chain Trajectory" List** | Evaluates active stage & horizons | Highlights the active stage in amber, resolved stages in green (`✓`), and projected stages. Point out the `⚠ untested on real traffic` badge on Stage 3. |
| **"Feature Attributions & Evidence"** | Dynamic GRU Perturbation XAI | Shows exact positive and negative sensitivity weights for flow characteristics that influenced the neural classification. |
| **"Dual-Provenance Audit Table"** | Live `priors.json` metadata | Shows the exact sample sizes and independent calibration statuses for Transition Probabilities vs. Dwell Times. |

---

## 9. Anticipated Technical Questions & Hard Defenses

### Q1: "Why did you use Random Forest and GRU instead of an end-to-end Transformer?"
> *"DNS is an ultra-low-latency protocol. A transformer model takes 50–100ms per query and requires GPU acceleration, which would collapse enterprise DNS throughput. Random Forest executes in $<1.2\text{ms}$ on CPU and allows exact mathematical explanation via TreeSHAP. For multi-flow host progression, a 2-layer GRU operates on 10-step sequence tensors in $<5\text{ms}$, giving us temporal awareness with zero line-rate penalty."*

### Q2: "Isn't your Markov chain just projecting fixed rules?"
> *"No. The Markov chain is seeded dynamically by the GRU's real-time softmax state vector $\mathbf{s}_0$. Furthermore, the transition probabilities and contiguous dwell times were empirically calibrated from 60,273 transitions in CTU-13. Where empirical data was insufficient (e.g. Discovery $N=0$), we explicitly mark it as an expert default rather than pretending it was learned from data."*

### Q3: "How do you prevent false positives from breaking business traffic?"
> *"Three safeguards: First, Stage 1 has a high-authority allowlist for verified sovereign and enterprise roots. Second, suspicious domains enter a `FLAG` state rather than an immediate hard drop, sending them to the Quarantine Queue. Third, host quarantine leases have an automated 15-minute countdown rollback, guaranteeing that an erroneous block never causes permanent network downtime."*
