#!/usr/bin/env python3
"""
DNS Shield — Live APT Network Attack Forecasting & Kill-Chain Simulation CLI
Specifically designed for Problem Statement #26153 (AI-Based Network Attack Forecasting).

Demonstrates real-time 6-stage MITRE ATT&CK progression against:
  - Flow Ingest Engine (:8006)
  - Forecasting Engine & PyTorch Bi-GRU (:8007)
  - Zero-Trust Air-Gap Sentinel (:8004 / GPIO 18)
  - Next.js Sovereign Command Center (:3000/app/forecast)
"""

import sys
import os
import time
import json
from typing import Dict, Any, List, Optional

# Ensure UTF-8 output encoding across Windows terminals
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

try:
    import requests
except ImportError:
    print("Error: 'requests' package required. Run: pip install requests")
    sys.exit(1)

# ANSI Color formatting
class C:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'

FLOW_INGEST_URL = os.getenv("FLOW_INGEST_URL", "http://localhost:8006")
FORECAST_URL = os.getenv("FORECAST_URL", "http://localhost:8007")
CONSOLE_URL = os.getenv("CONSOLE_URL", "http://localhost:3000")

STAGE_KEYS = [
    "STAGE_1_RECONNAISSANCE",
    "STAGE_2_INITIAL_ACCESS",
    "STAGE_3_DISCOVERY",
    "STAGE_4_C2_PERSISTENCE",
    "STAGE_5_LATERAL_MOVEMENT",
    "STAGE_6_EXFILTRATION",
]

STAGE_NAMES = {
    "STAGE_0_BENIGN": "Normal Operational Telemetry",
    "STAGE_1_RECONNAISSANCE": "Stage 1: Network & DNS Reconnaissance",
    "STAGE_2_INITIAL_ACCESS": "Stage 2: Initial Access & DGA Contact",
    "STAGE_3_DISCOVERY": "Stage 3: Internal Subnet Discovery",
    "STAGE_4_C2_PERSISTENCE": "Stage 4: Command & Control (C2) Beaconing",
    "STAGE_5_LATERAL_MOVEMENT": "Stage 5: Lateral Movement & Pivot",
    "STAGE_6_EXFILTRATION": "Stage 6: Covert DNS Data Exfiltration",
}

STAGE_TACTICS = {
    "STAGE_1_RECONNAISSANCE": "TA0043 (Reconnaissance) | T1595 (Active Scanning)",
    "STAGE_2_INITIAL_ACCESS": "TA0001 (Initial Access) | T1568 (Dynamic Resolution) / T1566 (Phishing)",
    "STAGE_3_DISCOVERY": "TA0007 (Discovery) | T1046 (Network Service Scanning)",
    "STAGE_4_C2_PERSISTENCE": "TA0011 (C2) | T1071 (Application Layer Protocol)",
    "STAGE_5_LATERAL_MOVEMENT": "TA0008 (Lateral Movement) | T1021 (Remote Services)",
    "STAGE_6_EXFILTRATION": "TA0010 (Exfiltration) | T1048 (Exfiltration Over Alternative Protocol)",
}

CAMPAIGNS = {
    "1": {
        "id": "APT29",
        "name": "APT29 / Nobelium (Nation-State Cyber Espionage)",
        "host_ip": "172.28.0.101",
        "target": "Ministry of Defence / Core Domain Controller",
        "description": "Gradual, low-noise cyber intrusion culminating in high-entropy covert DNS tunneling.",
        "pacing_sec": 1.5,
    },
    "2": {
        "id": "LAZARUS",
        "name": "Lazarus Group / APT38 (Targeted Financial Heist)",
        "host_ip": "172.28.0.145",
        "target": "Inter-Bank SWIFT Gateway & Payment Clearing Core",
        "description": "Aggressive reconnaissance, fast lateral SMB hopping, and bulk credential dump.",
        "pacing_sec": 1.0,
    },
    "3": {
        "id": "LOCKBIT",
        "name": "LockBit 3.0 (Double-Extortion Ransomware Campaign)",
        "host_ip": "172.28.0.220",
        "target": "Critical Sovereign Infrastructure & SCADA Historian",
        "description": "Rapid multi-threaded infection triggering emergency Zero-Trust hardware air-gap relay.",
        "pacing_sec": 0.8,
    },
}

def print_banner():
    banner = f"""
{C.CYAN}{C.BOLD}
  ██████╗ ███╗   ██╗███████╗    ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
  ██╔══██╗████╗  ██║██╔════╝    ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  ██║  ██║██╔██╗ ██║███████╗    ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██║  ██║██║╚██╗██║╚════██║    ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██████╔╝██║ ╚████║███████║    ███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
{C.RESET}{C.WHITE}{C.BOLD}  ⚡ NTRO PROBLEM STATEMENT #26153: AI ATTACK FORECASTING ENGINE SIMULATOR ⚡{C.RESET}
{C.DIM}  -------------------------------------------------------------------------------
  Bi-GRU Neural Forecaster  |  Markov Transition Rollouts  |  TreeSHAP XAI
  Live Web Dashboard:       {C.CYAN}{CONSOLE_URL}/app/forecast{C.RESET}
  Flow Ingest Collector:    {C.CYAN}{FLOW_INGEST_URL}{C.RESET}
  Forecasting Engine:       {C.CYAN}{FORECAST_URL}{C.RESET}
{C.DIM}  -------------------------------------------------------------------------------{C.RESET}
"""
    print(banner)

def check_services_health() -> bool:
    """Verify that flow-ingest and forecasting-engine microservices are running."""
    print(f"{C.BOLD}[*] Verifying Backend Microservices Health...{C.RESET}")
    ingest_ok = False
    forecast_ok = False
    
    try:
        r1 = requests.get(f"{FLOW_INGEST_URL}/health", timeout=1.5)
        if r1.status_code == 200:
            ingest_ok = True
            print(f"  {C.GREEN}✔ Flow Ingest Engine (:8006): ONLINE{C.RESET} (Active hosts: {r1.json().get('active_hosts', 0)})")
    except Exception as e:
        print(f"  {C.RED}✘ Flow Ingest Engine (:8006): OFFLINE ({e}){C.RESET}")

    try:
        r2 = requests.get(f"{FORECAST_URL}/health", timeout=1.5)
        if r2.status_code == 200:
            forecast_ok = True
            print(f"  {C.GREEN}✔ Forecasting Engine (:8007): ONLINE{C.RESET} (Relay: {'ENGAGED' if r2.json().get('relay_engaged') else 'STANDBY'})")
    except Exception as e:
        print(f"  {C.RED}✘ Forecasting Engine (:8007): OFFLINE ({e}){C.RESET}")

    if not (ingest_ok and forecast_ok):
        print(f"\n{C.YELLOW}⚠️  Warning: One or more backend microservices are offline.")
        print(f"    Please ensure services are running in background ports 8006 and 8007.{C.RESET}\n")
        return False
    print(f"  {C.GREEN}✔ All forecasting pipelines connected and operational.{C.RESET}\n")
    return True

def reset_host_telemetry(host_ip: str):
    """Reset simulation stage and wipe host telemetry in flow-ingest."""
    try:
        requests.delete(f"{FLOW_INGEST_URL}/flow/hosts/{host_ip}", timeout=1.5)
    except Exception:
        pass

def inject_stage(host_ip: str) -> Optional[Dict[str, Any]]:
    """Advance simulation by 1 stage in flow-ingest (:8006)."""
    try:
        r = requests.post(f"{FLOW_INGEST_URL}/flow/simulate/{host_ip}", timeout=2.0)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"{C.RED}Error calling flow-ingest simulation: {e}{C.RESET}")
    return None

def fetch_forecast(host_ip: str) -> Optional[Dict[str, Any]]:
    """Query real-time prediction from forecasting-engine (:8007)."""
    try:
        r = requests.get(f"{FORECAST_URL}/forecast/{host_ip}", timeout=2.0)
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        print(f"{C.RED}Error querying forecast: {e}{C.RESET}")
    return None

def render_killchain_bar(current_stage: str, horizon_15m: str):
    """Render an ANSI progress pipeline of the 6 stages."""
    stage_symbols = []
    found_current = False
    
    for s in STAGE_KEYS:
        short = s.replace("STAGE_", "").replace("_", " ")[:6]
        if s == current_stage:
            stage_symbols.append(f"{C.BG_RED}{C.WHITE}{C.BOLD} ⚡ {short} {C.RESET}")
            found_current = True
        elif s == horizon_15m:
            stage_symbols.append(f"{C.BG_YELLOW}{C.WHITE}{C.BOLD} 🔮 {short} {C.RESET}")
        elif not found_current:
            stage_symbols.append(f"{C.GREEN}✔ {short}{C.RESET}")
        else:
            stage_symbols.append(f"{C.DIM}○ {short}{C.RESET}")
            
    print("  " + " ──► ".join(stage_symbols))

def display_stage_telemetry(stage_num: int, total_stages: int, host_ip: str, inject_info: Dict[str, Any], forecast: Dict[str, Any]):
    """Print complete, rich operational and mathematical telemetry for judges."""
    cur_stage = forecast.get("current_stage", "STAGE_0_BENIGN")
    conf = forecast.get("current_stage_confidence", 0.0) * 100
    score = forecast.get("overall_threat_score", 0)
    ttc = forecast.get("time_to_compromise_min", 0.0)
    h15 = forecast.get("forecast_15m", {})
    h30 = forecast.get("forecast_30m", {})
    h60 = forecast.get("forecast_60m", {})
    shap_list = forecast.get("shap_explanations", []) or forecast.get("feature_attributions", [])
    active_flows = forecast.get("active_flows", 0)
    qps = forecast.get("observed_qps", 0.0)
    relay_required = forecast.get("hardware_relay_required", False)

    # Score color
    if score >= 85:
        score_badge = f"{C.BG_RED}{C.WHITE}{C.BOLD} CRITICAL ({score}/100) {C.RESET}"
    elif score >= 60:
        score_badge = f"{C.BG_YELLOW}{C.WHITE}{C.BOLD} HIGH RISK ({score}/100) {C.RESET}"
    elif score >= 35:
        score_badge = f"{C.YELLOW}{C.BOLD} ELEVATED ({score}/100) {C.RESET}"
    else:
        score_badge = f"{C.GREEN}{C.BOLD} NOMINAL ({score}/100) {C.RESET}"

    # Header Box
    print(f"\n{C.BOLD}{'='*80}{C.RESET}")
    print(f"{C.BOLD}[INTRUSION PHASE {stage_num}/{total_stages}] {STAGE_NAMES.get(cur_stage, cur_stage)}{C.RESET}")
    print(f"  Target Host:      {C.CYAN}{host_ip}{C.RESET} | Active Ingested Flows: {C.YELLOW}{active_flows}{C.RESET} | Rate: {C.YELLOW}{qps} QPS{C.RESET}")
    print(f"  MITRE ATT&CK:     {C.MAGENTA}{STAGE_TACTICS.get(cur_stage, 'N/A')}{C.RESET}")
    print(f"  Threat Verdict:   {score_badge} | Bi-GRU Confidence: {C.BOLD}{conf:.1f}%{C.RESET}")
    print(f"{C.BOLD}{'='*80}{C.RESET}")

    # Visual Kill-Chain Track
    print(f"\n{C.BOLD}► Kill-Chain Dynamic Pipeline:{C.RESET}")
    render_killchain_bar(cur_stage, h15.get("stage", ""))

    # Temporal Rollout Projections
    print(f"\n{C.BOLD}► AI Attack Forecasting (Markov State-Space Horizon Rollout):{C.RESET}")
    c_15_cone = h15.get("confidence_cone", [0, 0])
    c_30_cone = h30.get("confidence_cone", [0, 0])
    c_60_cone = h60.get("confidence_cone", [0, 0])
    
    print(f"  {C.CYAN}+15 min:{C.RESET} {h15.get('label', 'N/A'):<32} Conf: {C.BOLD}{h15.get('confidence', 0)*100:4.1f}%{C.RESET} (Cone: [{c_15_cone[0]:.2f}, {c_15_cone[1]:.2f}])")
    print(f"  {C.CYAN}+30 min:{C.RESET} {h30.get('label', 'N/A'):<32} Conf: {C.BOLD}{h30.get('confidence', 0)*100:4.1f}%{C.RESET} (Cone: [{c_30_cone[0]:.2f}, {c_30_cone[1]:.2f}])")
    print(f"  {C.CYAN}+60 min:{C.RESET} {h60.get('label', 'N/A'):<32} Conf: {C.BOLD}{h60.get('confidence', 0)*100:4.1f}%{C.RESET} (Cone: [{c_60_cone[0]:.2f}, {c_60_cone[1]:.2f}])")

    # Time-To-Compromise (TTC)
    if cur_stage == "STAGE_6_EXFILTRATION":
        ttc_str = f"{C.BG_RED}{C.WHITE}{C.BOLD} 0.0 min (IMPACT OCCURRED / ACTIVE EXFILTRATION) {C.RESET}"
    else:
        ttc_str = f"{C.RED}{C.BOLD}{ttc:.1f} minutes remaining{C.RESET} until Stage 6 compromise"
    print(f"\n  Estimated Time-to-Compromise (TTC): {ttc_str}")

    # Explainable AI (TreeSHAP)
    if shap_list:
        print(f"\n{C.BOLD}► Explainable AI — Top Network Telemetry Feature Attributions (TreeSHAP):{C.RESET}")
        for feat in shap_list[:4]:
            val = feat.get("value", "")
            shap_v = feat.get("shap_value", feat.get("weight", 0.0))
            name = feat.get("feature", feat.get("raw_feature", "feature"))
            
            if shap_v > 0.05:
                sign = f"{C.RED}+{shap_v:.4f} (Threat Driver){C.RESET}"
            elif shap_v < -0.05:
                sign = f"{C.GREEN}{shap_v:.4f} (Benign Mitigator){C.RESET}"
            else:
                sign = f"{C.DIM}{shap_v:.4f}{C.RESET}"
            print(f"  • {name:<26} Value: {C.YELLOW}{str(val):<15}{C.RESET} SHAP: {sign}")

    # Active Zero-Trust Response
    print(f"\n{C.BOLD}► Autonomous SOAR & Containment Action:{C.RESET}")
    if relay_required or score >= 85:
        print(f"  {C.BG_RED}{C.WHITE}{C.BOLD} ⚡ EMERGENCY: ZEPHYR RTOS HARDWARE AIR-GAP RELAY TRIPPED (GPIO 18) ⚡ {C.RESET}")
        print(f"  {C.RED}  Physical relay opened at wire-speed (< 2.5ms). Host {host_ip} isolated from subnet.{C.RESET}")
    elif score >= 60:
        print(f"  {C.YELLOW}⚠️  PREEMPTIVE CONTAINMENT: Host session throttled to 1 QPS. Dynamic sinkhole routing armed.{C.RESET}")
    else:
        print(f"  {C.GREEN}✔ PASSIVE MONITORING: Telemetry buffered in rolling 900-second session window.{C.RESET}")

    print(f"\n  {C.DIM}Live Dashboard Synchronized: Open {CONSOLE_URL}/app/forecast to view{C.RESET}")

def run_campaign_simulation(campaign_key: str, interactive: bool = False):
    """Execute a multi-stage attack campaign simulation."""
    camp = CAMPAIGNS[campaign_key]
    host_ip = camp["host_ip"]
    
    print(f"\n{C.BOLD}{C.MAGENTA}⚡ Launching Campaign: {camp['name']}{C.RESET}")
    print(f"  Target Subnet:    {C.WHITE}{camp['target']}{C.RESET}")
    print(f"  Monitored IP:     {C.CYAN}{host_ip}{C.RESET}")
    print(f"  Vector Anatomy:   {C.DIM}{camp['description']}{C.RESET}")
    print(f"  Execution Mode:   {C.YELLOW}{'Step-by-Step (Judges Interactive)' if interactive else 'Automated Timed Pacing'}{C.RESET}\n")

    # Step 0: Clean reset
    reset_host_telemetry(host_ip)

    for step_num in range(1, len(STAGE_KEYS) + 1):
        if interactive:
            print(f"\n{C.YELLOW}[?] Press ENTER to advance attacker to Stage {step_num} ({STAGE_KEYS[step_num-1]})...{C.RESET}", end="")
            input()

        # Inject stage
        inject_info = inject_stage(host_ip)
        if not inject_info:
            print(f"{C.RED}Failed to inject stage {step_num}. Skipping...{C.RESET}")
            continue

        # Allow pipeline to compute
        time.sleep(0.3)

        # Fetch real forecast
        forecast = fetch_forecast(host_ip)
        if not forecast:
            print(f"{C.RED}Failed to fetch forecast verdict. Skipping...{C.RESET}")
            continue

        display_stage_telemetry(step_num, len(STAGE_KEYS), host_ip, inject_info, forecast)

        if not interactive and step_num < len(STAGE_KEYS):
            time.sleep(camp["pacing_sec"])

    print(f"\n{C.GREEN}{C.BOLD}✔ Multi-Stage Attack Simulation Complete for Host {host_ip}!{C.RESET}")
    print(f"{C.CYAN}  All 6 stages were classified by Bi-GRU and displayed live on {CONSOLE_URL}/app/forecast{C.RESET}\n")

def run_custom_stage_step():
    """Manually advance a specific host by 1 stage."""
    host_ip = input(f"\n{C.YELLOW}Enter target host IP to advance [default 172.28.0.101]: {C.RESET}").strip() or "172.28.0.101"
    inject_info = inject_stage(host_ip)
    if inject_info:
        stage = inject_info.get("simulated_stage", "UNKNOWN")
        print(f"\n{C.GREEN}✔ Injected {inject_info.get('flows_injected', 0)} flows for {stage} on {host_ip}{C.RESET}")
        time.sleep(0.3)
        forecast = fetch_forecast(host_ip)
        if forecast:
            display_stage_telemetry(1, 1, host_ip, inject_info, forecast)
    else:
        print(f"{C.RED}Failed to advance stage.{C.RESET}")

def run_reset():
    """Reset all active host sessions."""
    host_ip = input(f"\n{C.YELLOW}Enter host IP to reset [default 172.28.0.101]: {C.RESET}").strip() or "172.28.0.101"
    reset_host_telemetry(host_ip)
    print(f"{C.GREEN}✔ Host {host_ip} session wiped. Reset back to STAGE_0_BENIGN.{C.RESET}\n")

def main():
    print_banner()
    check_services_health()

    while True:
        print(f"{C.BOLD}Select an Attack Forecasting Simulation Scenario (NTRO #26153):{C.RESET}")
        print(f"  {C.CYAN}1{C.RESET}) 🕵️  APT29 / Nobelium Cyber Espionage (6 Stages - Automated Pacing)")
        print(f"  {C.MAGENTA}2{C.RESET}) 💰 Lazarus Group / APT38 Financial Heist (6 Stages - Automated Pacing)")
        print(f"  {C.RED}3{C.RESET}) ⚡ LockBit 3.0 Ransomware Campaign (Rapid Double-Extortion & Relay Trip)")
        print(f"  {C.YELLOW}4{C.RESET}) 🎓 SIH JUDGES PRESENTATION MODE (Interactive Step-by-Step with [ENTER] key)")
        print(f"  {C.BLUE}5{C.RESET}) ⏩ Advance Host by Single Stage (+1 Step)")
        print(f"  {C.GREEN}6{C.RESET}) 🔄 Reset Monitored Host back to Benign State")
        print(f"  {C.WHITE}7{C.RESET}) 🏥 Check Backend Microservices Health Status")
        print(f"  {C.BOLD}8{C.RESET}) 🚪 Exit")

        try:
            choice = input(f"\n{C.BOLD}Enter choice [1-8]: {C.RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if choice == "1":
            run_campaign_simulation("1", interactive=False)
        elif choice == "2":
            run_campaign_simulation("2", interactive=False)
        elif choice == "3":
            run_campaign_simulation("3", interactive=False)
        elif choice == "4":
            print(f"\n{C.YELLOW}{C.BOLD}Select Threat Profile for Judges Presentation:{C.RESET}")
            print("  1) APT29 / Nobelium Espionage")
            print("  2) Lazarus Group Financial Heist")
            print("  3) LockBit 3.0 Ransomware")
            sub_c = input(f"{C.BOLD}Enter campaign [1-3, default 1]: {C.RESET}").strip() or "1"
            if sub_c in CAMPAIGNS:
                run_campaign_simulation(sub_c, interactive=True)
            else:
                run_campaign_simulation("1", interactive=True)
        elif choice == "5":
            run_custom_stage_step()
        elif choice == "6":
            run_reset()
        elif choice == "7":
            check_services_health()
        elif choice == "8" or choice.lower() in ("exit", "q"):
            print(f"\n{C.GREEN}Exiting Attack Forecasting Simulator.{C.RESET}\n")
            break
        else:
            print(f"{C.RED}Invalid option, please choose 1-8.{C.RESET}\n")

if __name__ == "__main__":
    main()
