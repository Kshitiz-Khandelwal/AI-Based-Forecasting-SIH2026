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

To ensure scientific honesty and transparency, DNS Shield explicitly separates **trained neural model parameters**, **transition matrix calibration**, and **dwell-time velocity calibration**. The two calibration dimensions are evaluated and reported independently—never conflated into a single blended badge.

### Dual-Provenance Stage Audit Table

| Stage ID | Transition Sample Size ($N$) | Transition Calibration Status | Contiguous Runs ($N$) | Dwell Time | Dwell Time Calibration Status | Data Coverage |
| :--- | :---: | :--- | :---: | :---: | :--- | :--- |
| `STAGE_0_BENIGN` | $52,715$ | `calibrated_empirical` | $22,714$ | $0.0\text{ min}$ | `terminal_boundary_zero` | `calibrated_empirical` |
| `STAGE_1_RECONNAISSANCE` | $391$ | `calibrated_empirical` | $65$ | $8.4\text{ min}$ | `calibrated_empirical` | `calibrated_empirical` |
| `STAGE_2_INITIAL_ACCESS` | $4,388$ | `calibrated_empirical` | $1,622$ | $15.3\text{ min}$ | `calibrated_empirical` | `calibrated_empirical` |
| `STAGE_3_DISCOVERY` | $0$ | `expert_prior_default` | $0$ | $12.0\text{ min}$ | `expert_prior_default` | `no_real_examples_observed` ⚠ |
| `STAGE_4_C2_PERSISTENCE` | $332$ | `calibrated_empirical` | $60$ | $19.7\text{ min}$ | `calibrated_empirical` | `calibrated_empirical` |
| `STAGE_5_LATERAL_MOVEMENT` | $2$ | `expert_prior_default` | $2$ | $22.0\text{ min}$ | `expert_prior_default` | `sparse_empirical_reverted_to_default` |
| `STAGE_6_EXFILTRATION` | $2,445$ | `calibrated_empirical` | $1,557$ | $0.0\text{ min}$ | `terminal_boundary_zero` | `calibrated_empirical` |

---

### Methodological Fixes Applied in Calibration (`calibrate_priors.py`)

1. **Fix 1 — Scaled Bayesian Smoothing & Escalation Sanity Floor**:
   - **Problem**: With a fixed $\alpha = 10$ pseudo-count, the $52,715$ benign-benign observations overwhelmed the expert escalation prior, collapsing $P(\text{Benign} \to \text{Recon})$ to $2.8 \times 10^{-5}$ and preventing the system from forecasting attack onset from a clean baseline.
   - **Solution**: Implemented an effective sample size ceiling (`eff_sum = min(row_sum, 1000)`) with row-scaled smoothing weight $\alpha = \max(10, 0.08 \times \text{eff\_sum})$ and an explicit sanity floor ($2.5\%$) on documented escalation paths.
   - **Result**: $P(\text{Benign} \to \text{Recon})$ is calibrated at **$0.024658$ (~$2.47\%$)**, maintaining baseline stability ($P(0 \to 0) = 0.975342$) while retaining realistic sensitivity to attack onset.

2. **Fix 2 — Option A Contiguous Run Dwell-Time Calculation**:
   - **Problem**: Measuring delta between adjacent CSV flow rows measured NetFlow packet capture intervals rather than attacker dwell time, resulting in near-zero means.
   - **Solution**: Computed dwell time per *contiguous stage run* using the wall-clock span from the `StartTime` of the first flow to the `StartTime` of the last flow in that run plus that flow's `Dur` duration. Stages with $N < 20$ runs (`STAGE_3_DISCOVERY` $N=0$, `STAGE_5_LATERAL` $N=2$) explicitly revert to domain-expert defaults and are transparently labeled `expert_prior_default`.

3. **Fix 3 — Full-Precision Consistency in `priors.json`**:
   - Removed the arbitrary `if prob > 0.01` filter that caused human-readable `transition_matrix` to diverge from runtime `transition_matrix_array`. Both now reflect identical 6-decimal values.

4. **Fix 5 — Explicit Warning for Untested Discovery Stage**:
   - `STAGE_3_DISCOVERY` had zero observed flows in CTU-13 (the dataset captured external botnet traffic without internal subnet scanning). It is tagged `"data_coverage": "no_real_examples_observed"` and badged with `⚠ untested on real traffic` across the UI and API.

### API Provenance Object
Every response from `/forecast/{host}` and `/forecast/timeline` includes the `provenance` dictionary:
```json
"provenance": {
  "current_stage": "gru_inference",
  "horizon_projection": "markov_rollout_calibrated_prior",
  "time_to_compromise": "formula_with_calibrated_durations",
  "feature_attributions": "perturbation_analysis_on_gru_input",
  "priors_source": "CTU-13 empirical calibration (N=60273 transitions, Option A contiguous run dwell times)",
  "calibrated_transitions_file": "services/forecasting_engine/priors.json",
  "neural_model_file": "services/forecasting_engine/models/temporal_gru_forecaster.pt"
}
```

