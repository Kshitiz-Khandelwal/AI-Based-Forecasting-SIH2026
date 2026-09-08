# Model Card — DNS Shield X-Forecast (PS2 Temporal Attack Forecaster)

## 1. Model Overview & Purpose
- **Model Name**: DNS Shield Temporal GRU Sequence Forecaster (`v2.1.0-ps2`)
- **Problem Statement**: SIH 2026 PS2 — AI-Based Cyber Attack Forecasting System & Temporal Kill-Chain Trajectory.
- **Architecture**: 
  - **Current-Stage Classification**: Trained 2-Layer PyTorch GRU Sequence Forecaster (`input_dim=16`, `hidden_dim=64`, `seq_len=10`, `classes=7`) evaluating normalized 16-dimensional temporal flow vectors extracted via `temporal_feature_extractor`.
  - **Future-Horizon Projections (+15m, +30m, +60m)**: Stochastic Markov state rollout matrix seeded directly from the GRU model's real softmax probability distribution $\mathbf{p} \in \mathbb{R}^7$.
  - **Explainability & Attribution**: Real sequence perturbation-based feature attribution computed dynamically against the GRU input tensor.
  - **Fail-Safe Heuristic Fallback**: Explicitly labeled keyword-based sliding-window fallback engaged only if model weights fail to load.
- **Target Horizons**: 
  - $t+0$: Current Active MITRE ATT&CK Phase (GRU argmax class + confidence)
  - $t+15\text{m}$: 15-Minute Next Hop Stage & Confidence Cone ($\mathbf{p} \cdot M$)
  - $t+30\text{m}$: 30-Minute Intermediate Escalation Projection ($\mathbf{p} \cdot M^2$)
  - $t+60\text{m}$: 60-Minute Exfiltration / Culmination Horizon ($\mathbf{p} \cdot M^4$)

---

## 2. Mathematical Formalization of Time-to-Compromise (TTC)

### Formal Formula Disclosure
$$\text{TTC}(s, \mathbf{x}) = \left(\sum_{k=s+1}^{6} T_k\right) \times \left(1.0 - 0.45 \cdot \text{clip}\left(\frac{\text{burst\_qps}}{25.0}, 0.0, 1.0\right)\right) \times \left(0.60 + 0.40 \cdot (1.0 - C)\right)$$

Where:
1. **$s \in \{0, 1, 2, 3, 4, 5, 6\}$**: Current classified kill-chain stage index from GRU model output.
2. **$T_k$**: Canonical baseline stage duration constants (minutes):
   - $T_1$ (Reconnaissance): $10.0\text{ min}$
   - $T_2$ (Initial Access): $15.0\text{ min}$
   - $T_3$ (Discovery): $12.0\text{ min}$
   - $T_4$ (C2 Persistence): $18.0\text{ min}$
   - $T_5$ (Lateral Movement): $22.0\text{ min}$
   - $T_6$ (Exfiltration / Impact): $0.0\text{ min}$ (Terminal state)
3. **$\text{burst\_qps}$**: Measured query / flow burst rate over the 900-second session window. Automated APT scripting with high burst velocity compresses phase duration by up to $45\%$.
4. **$C \in [0.0, 1.0]$**: Current stage model confidence. High confidence projects streamlined attacker advancement ($0.60\times$), whereas low confidence models attacker hesitation and dwell time ($1.00\times$).
5. **Boundary Conditions**: For Benign ($s=0$) and Terminal Exfiltration ($s=6$), $\text{TTC} = 0.0\text{ min}$.

---

## 3. Scope & Operational Boundaries

### Supported Ingestion Modalities
- **Structured NetFlow / IPFIX JSON**: Ingestion via `POST /flow/batch` and `POST /flow/packet`.
- **PCAP / PCAP-NG File Parsing**: Struct-based raw Ethernet / IPv4 / TCP / UDP / DNS frame extractor via `POST /flow/pcap`.

### Explicit Scope Constraints & Limitations
- **No Raw UDP Socket Kernel Daemon**: In accordance with the modular microservice architecture, live packet ingestion operates over structured HTTP endpoints. A promiscuous kernel socket daemon (e.g. `AF_PACKET` / raw `pcap_loop`) is omitted in this demonstration build in favor of reproducible containerized JSON/PCAP flow telemetry.
- **PCAP Safety Boundary**: PCAP file uploads are capped at $20\text{ MB}$ (`MAX_PCAP_SIZE_BYTES`), execute with bounded memory allocation, and are designated as a **Lab & Evaluation Diagnostic Endpoint**.

---

## 4. Hardware Relay Preemptive Trigger Logic (Software Emulation)
- When the projected threat reaches $\text{STAGE\_5}$ (Lateral Movement) or $\text{STAGE\_4}$ with high velocity ($\text{TTC} < 15\text{m}$), the engine flags `hardware_relay_required = True`.
- **Software Emulation Disclosure**: In this reference implementation, the relay trip is an emulated software signal payload designed to interface with a Zephyr RTOS Microcontroller (ESP32-S3 / RP2040) over GPIO 18. **No physical microcontroller board is required or physically attached in this standard software evaluation build.**

---

## 5. Explainability Architecture & Taxonomy
- **ML Lexical Inference (`services/ml-inference`)**: Uses true TreeSHAP (`shap.TreeExplainer`) on Random Forest & LightGBM lexical models to generate exact mathematical Shapley attribution values ($\phi$) for character entropy, n-grams, and vowel ratios.
- **Temporal Attack Forecasting (`services/forecasting_engine`)**: Uses dynamic feature perturbation against the GRU model input sequence to calculate feature impact on threat probability $(\Delta P(\text{threat}))$. Features are ranked by absolute magnitude to explain why the neural sequence forecaster identified the active attack phase.

---

## 6. Provenance & Empirical Calibration of Priors (CTU-13 Dataset)

To ensure scientific honesty and transparency, DNS Shield explicitly separates **trained neural model parameters**, **data-calibrated transition priors**, and **domain-expert baseline assumptions**:

| Component | Methodology | Source | Confidence Tier |
| :--- | :--- | :--- | :--- |
| **Current Stage Classification** | PyTorch 2-Layer GRU Forward Pass | `temporal_gru_forecaster.pt` | **Learned from Data** (71.3% test accuracy) |
| **Feature Explanations** | Continuous Input Perturbation Sensitivity | Real-time GRU tensor perturbation | **Dynamic Input Gradient** |
| **Markov Horizon (+15m/+30m/+60m)** | Empirical Transition Matrix ($\mathbf{P} \cdot M^k$) | `services/forecasting_engine/priors.json` (via `calibrate_priors.py`) | **Empirically Calibrated** (60,273 transitions) |
| **Stage 0, 1, 2, 4, 6 Transitions** | Bayesian Smoothed Transition Counts ($N \ge 20$) | CTU-13 NetFlow (83,010 flows, 5 scenarios) | **High Confidence Calibrated** |
| **Stage 3 (Discovery) Transitions** | Domain-Expert Prior ($N < 20$) | Published APT Campaign Analysis | **Low-Confidence Prior (Inherited Default)** |
| **Stage 5 (Lateral) Transitions** | Domain-Expert Prior ($N = 2$) | Published APT Campaign Analysis | **Low-Confidence Prior (Inherited Default)** |
| **Stage Dwell Times (TTC)** | Blended CTU-13 Run Durations + Expert Priors | `priors.json` (`[0, 8.3, 15, 12, 13.2, 22, 0]` min) | **Hybrid Calibrated Prior** |

### Calibration Sample Size Audit (CTU-13 Multistage NetFlow)
Generated via `python services/forecasting_engine/calibrate_priors.py`:
- **Total Labeled Flows**: $83,010$ across 5 CTU-13 botnet scenarios.
- **Total Observed Transitions**: $60,273$ sequential stage-to-stage transitions.
- **Observed Transitions by Originating Stage**:
  - `STAGE_0_BENIGN`: $N = 52,715$ transitions $\to$ **High Confidence**
  - `STAGE_1_RECONNAISSANCE`: $N = 391$ transitions $\to$ **High Confidence** (Dwell time: $8.3\text{ min}$)
  - `STAGE_2_INITIAL_ACCESS`: $N = 4,388$ transitions $\to$ **High Confidence** (Dwell time: $15.0\text{ min}$)
  - `STAGE_3_DISCOVERY`: $N = 0$ transitions $\to$ **Low-Confidence Inherited Prior** (No internal sweeps in CTU-13 capture)
  - `STAGE_4_C2_PERSISTENCE`: $N = 332$ transitions $\to$ **High Confidence** (Dwell time: $13.2\text{ min}$)
  - `STAGE_5_LATERAL_MOVEMENT`: $N = 2$ transitions $\to$ **Low-Confidence Inherited Prior** (CTU-13 was single-host botnet egress)
  - `STAGE_6_EXFILTRATION`: $N = 2,445$ transitions $\to$ **High Confidence**

### API Provenance Object
Every response from `/forecast/{host}` and `/forecast/timeline` includes the `provenance` dictionary:
```json
"provenance": {
  "current_stage": "gru_inference",
  "horizon_projection": "markov_rollout_calibrated_prior",
  "time_to_compromise": "formula_with_calibrated_durations",
  "feature_attributions": "perturbation_analysis_on_gru_input",
  "priors_source": "CTU-13 empirical calibration (N=60273 observed transitions)",
  "calibrated_transitions_file": "services/forecasting_engine/priors.json",
  "neural_model_file": "services/forecasting_engine/models/temporal_gru_forecaster.pt"
}
```

