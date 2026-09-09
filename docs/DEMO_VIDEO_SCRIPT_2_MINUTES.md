# Demo Video Script & Walkthrough (Max 2 Minutes / 120s)
> **Problem Statement ID**: 26153 | **Organization**: National Technical Research Organisation (NTRO)  
> **Challenge**: AI based Network Attack Forecasting from Network Traffic Data  
> **Evaluation Deliverable**: Demo Video Guide & Production Script  
> **Target Duration**: Exactly 120 Seconds (2 Minutes 00 Seconds)

---

## ⏱️ Master Timeline & Scene Breakdown

```
[00:00 - 00:20] ──► Scene 1: The Problem & The Cyber World Model Paradigm
[00:20 - 00:45] ──► Scene 2: Two-Level Traffic Ingestion (NetFlow + PCAP)
[00:45 - 01:15] ──► Scene 3: Live Forward Simulation & Time-to-Compromise (TTC)
[01:15 - 01:40] ──► Scene 4: Interpretable Decision Support & MITRE ATT&CK Mapping
[01:40 - 02:00] ──► Scene 5: Preemptive Active Response & Sovereign Conclusion
```

---

### Scene 1: Introduction & The Core Problem (00:00 – 00:20)
- **Visual**: Screen capture opens on the **DNS Shield Enterprise SOC Console** (`http://localhost:3000/app/dashboard`) showing live event streams, risk meters, and threat ratios. Title overlay: *Problem Statement #26153: AI Based Network Attack Forecasting (NTRO)*.
- **Voiceover / Narration**:
  > *"Traditional cybersecurity relies on reactive, isolated intrusion detection. A firewall or IDS classifies a packet only after contact, generating an alert when data is already compromised. For Critical Information Infrastructure, this is too late.*  
  > *Introducing the Cyber World Model: an AI system that learns network state dynamics $P(S_{t+1} \mid S_t)$ to forecast attack progression before the adversary completes the kill chain."*

---

### Scene 2: Dual-Level Ingestion — NetFlow & PCAP (00:20 – 00:45)
- **Visual**: Cut to the **Pipeline & Ingestion View** (`http://localhost:3000/app/pipeline`) or split-screen showing a terminal sending a NetFlow/PCAP stream to `POST /api/v1/flow/ingest` alongside the normalized 16-dimensional state vector updating live.
- **Voiceover / Narration**:
  > *"To defeat attackers who evade volume thresholds, our pipeline ingests two levels of traffic:*  
  > *Level 1 extracts NetFlow flow statistics: TCP flag bitmasks, inter-arrival time distributions, and byte ratios.*  
  > *Level 2 extracts packet-level PCAP features: TTL variance, TCP window dynamics, IP fragmentation, and port scan signatures.*  
  > *These synchronize into a rolling network state tensor capturing temporal causality over time."*

---

### Scene 3: Live Forward Simulation & Time-to-Compromise (00:45 – 01:15)
- **Visual**: Transition to the **Attack Forecasting View** (`http://localhost:3000/app/forecast`). An active host (`192.168.1.105`) is highlighted. The camera zooms in on the **$+15\text{m}$, $+30\text{m}$, $+60\text{m}$ Horizon Probability Cone** and the **Time-to-Compromise Countdown Clock** displaying `18.4 Minutes Remaining`.
- **Voiceover / Narration**:
  > *"Watch our World Model in action. Here, a host begins low-and-slow port probing. A traditional IDS treats this as an isolated benign scan.*  
  > *Our deep sequence model rolls out the state trajectory $K$ steps forward. It projects a 78% probability of Initial Access within 15 minutes, escalating to C2 persistence at 30 minutes.*  
  > *The engine computes a Time-to-Compromise of 18.4 minutes, providing defenders with actionable warning before lateral movement begins."*

---

### Scene 4: Interpretable Decision Support & MITRE ATT&CK (01:15 – 01:40)
- **Visual**: Click on host details to open the **Explainability Drawer / Modal**. Display the **TreeSHAP & Sequence Perturbation Waterfall Plot**, highlighting driving features: `SYN-ACK Asymmetry (+0.31)`, `Entropy Variance (+0.24)`, `IAT Jitter (+0.18)`. Transition to the **MITRE ATT&CK Matrix** showing the projected path highlighted in glowing amber.
- **Voiceover / Narration**:
  > *"In Critical Infrastructure, black-box AI is unacceptable. Every prediction is backed by dynamic feature attribution and exact TreeSHAP proofs, showing analysts the exact flags, timing anomalies, and port sequences driving the forecast.*  
  > *All states map directly to recognized MITRE ATT&CK tactics, from T1595 Reconnaissance to T1048 Exfiltration."*

---

### Scene 5: Preemptive Active Response & Sovereign Readiness (01:40 – 02:00)
- **Visual**: Navigate to the **Active Response / Quarantine Tab** (`http://localhost:3000/app/quarantine`). The host is quarantined preemptively; the emulated hardware relay indicator flashes *TRIPPED*. Show the terminal running 100% offline with sub-millisecond allowlist bypass for Indian sovereign domains (`*.nic.in`, `isro.gov.in`).
- **Voiceover / Narration**:
  > *"With the threat anticipated, the system triggers proactive defense: automated micro-segmentation, quarantine isolation, and an emulated hardware air-gap killswitch.*  
  > *100% offline, air-gapped, zero cloud dependencies, and line-rate performance for sovereign Indian networks.*  
  > *DNS Shield & Cyber World Model: Predictive cyber defense for national security."*
- **Final Screen**: Team Details, Problem Statement ID 26153, NTRO / SIH 2026 Submission.
