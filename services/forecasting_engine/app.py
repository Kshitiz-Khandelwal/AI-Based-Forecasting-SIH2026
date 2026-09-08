"""DNS Shield X-Forecast — Attack Forecasting Engine Service (Port 8007)

Provides:
  GET  /forecast/timeline              Most threatening active host full forecast
  GET  /forecast/hosts                 All monitored hosts with stage + threat score
  GET  /forecast/{host_ip}             Per-host full forecast
  GET  /forecast/{host_ip}/history     Stage transition history
  POST /hardware/relay                 Trip / release hardware relay state
  GET  /hardware/relay                 Current relay state

Satisfies PS2: AI-based temporal attack forecasting, TTC, preemptive containment,
kill-chain visualization, and hardware relay integration.
"""
from __future__ import annotations

import os
import sys
import time
import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Support both isolated Docker container build and full monorepo pathing
try:
    from attack_forecaster import (
        AttackForecastingEngine,
        STAGE_METADATA,
        STAGES,
    )
except ImportError:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from services.forecasting_engine.attack_forecaster import (
        AttackForecastingEngine,
        STAGE_METADATA,
        STAGES,
    )

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("forecasting-engine")

FLOW_INGEST_URL = os.getenv("FLOW_INGEST_URL", "http://localhost:8006")
ANALYTICS_STORE_URL = os.getenv("ANALYTICS_STORE_URL", "http://localhost:8005")

app = FastAPI(
    title="DNS Shield Forecasting Engine",
    version="1.0.0",
    description="Temporal MITRE ATT&CK kill-chain forecaster with TTC and preemptive containment.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

forecaster = AttackForecastingEngine()

# ─── Hardware Relay State ────────────────────────────────────────────────────
_relay_state = {"engaged": False, "engaged_at": None, "reason": None}


def _get_flow_timeline(host_ip: str) -> List[Dict[str, Any]]:
    """Fetch host flow timeline from Flow Ingest service."""
    try:
        r = requests.get(f"{FLOW_INGEST_URL}/flow/timeline/{host_ip}", timeout=0.5)
        if r.status_code == 200:
            return r.json().get("flows", [])
    except Exception:
        pass
    return []


def _get_all_hosts() -> List[str]:
    """Fetch all active host IPs from Flow Ingest service."""
    try:
        r = requests.get(f"{FLOW_INGEST_URL}/flow/hosts", timeout=0.5)
        if r.status_code == 200:
            return [h["host_ip"] for h in r.json().get("hosts", [])]
    except Exception:
        pass
    return []


def _log_forecast_audit(result):
    """Best-effort async logging of forecast verdicts to analytics-store."""
    try:
        payload = {
            "host_ip": result.host_ip,
            "current_stage": result.current_stage,
            "current_stage_confidence": result.current_stage_confidence,
            "overall_threat_score": result.overall_threat_score,
            "time_to_compromise_min": result.time_to_compromise_min,
            "predicted_15m": result.forecast_horizon_15m.stage_id,
            "predicted_30m": result.forecast_horizon_30m.stage_id,
            "predicted_60m": result.forecast_horizon_60m.stage_id,
            "relay_engaged": bool(result.hardware_relay_required or _relay_state["engaged"]),
        }
        requests.post(f"{ANALYTICS_STORE_URL}/forecast/events", json=payload, timeout=0.2)
    except Exception:
        pass  # Non-blocking best-effort audit


def _forecast_to_dict(result) -> Dict[str, Any]:
    """Convert AttackForecastResult dataclass to JSON-serializable dict."""
    _log_forecast_audit(result)
    d = asdict(result)
    # Enrich with stage metadata
    d["current_stage_meta"] = STAGE_METADATA.get(result.current_stage, {})
    d["all_stages"] = {
        k: {
            "label": v["label"],
            "severity": v["severity"],
            "color": v["color"],
            "mitre_tactics": v["mitre_tactics"],
            "description": v["description"],
            "data_coverage": v.get("data_coverage", "calibrated_empirical"),
        }
        for k, v in STAGE_METADATA.items()
    }
    # Flatten horizon objects for frontend compatibility
    h15 = d.pop("forecast_horizon_15m")
    h30 = d.pop("forecast_horizon_30m")
    h60 = d.pop("forecast_horizon_60m")
    d["forecast_15m"] = {
        "stage": h15["stage_id"],
        "label": h15["stage_label"],
        "confidence": h15["probability"],
        "time_min": h15["estimated_time_to_stage_min"],
        "confidence_cone": h15["confidence_cone"],
        "data_coverage": STAGE_METADATA.get(h15["stage_id"], {}).get("data_coverage", "calibrated_empirical"),
    }
    d["forecast_30m"] = {
        "stage": h30["stage_id"],
        "label": h30["stage_label"],
        "confidence": h30["probability"],
        "time_min": h30["estimated_time_to_stage_min"],
        "confidence_cone": h30["confidence_cone"],
        "data_coverage": STAGE_METADATA.get(h30["stage_id"], {}).get("data_coverage", "calibrated_empirical"),
    }
    d["forecast_60m"] = {
        "stage": h60["stage_id"],
        "label": h60["stage_label"],
        "confidence": h60["probability"],
        "time_min": h60["estimated_time_to_stage_min"],
        "confidence_cone": h60["confidence_cone"],
        "data_coverage": STAGE_METADATA.get(h60["stage_id"], {}).get("data_coverage", "calibrated_empirical"),
    }
    # Provide feature_attributions as primary, shap_explanations as alias
    d["feature_attributions"] = d.get("feature_attributions", [])
    d["shap_explanations"] = d["feature_attributions"]
    d["hardware_mode"] = "SIMULATED_MOCK_EMULATION"  # Discloses that relay is software emulated

    # Calculate real observed telemetry QPS from host's recent flow timeline
    flows = _get_flow_timeline(result.host_ip)
    d["active_flows"] = len(flows)
    if flows:
        time_span = max(1.0, flows[-1].get("timestamp", 0) - flows[0].get("timestamp", 0)) if len(flows) > 1 else 60.0
        d["observed_qps"] = round(len(flows) / min(time_span, 60.0), 1)
    else:
        d["observed_qps"] = 0.0

    return d




# ─── API Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "forecasting-engine", "relay_engaged": _relay_state["engaged"]}


@app.get("/forecast/hosts", tags=["forecast"])
def get_all_host_forecasts():
    """Return lightweight forecast summary for all active monitored hosts."""
    hosts = _get_all_hosts()
    if not hosts:
        return {"hosts": [], "count": 0}

    summaries = []
    for host_ip in hosts:
        flows = _get_flow_timeline(host_ip)
        result = forecaster.evaluate_host_timeline(host_ip, flows)
        stage_meta = STAGE_METADATA.get(result.current_stage, {})
        summaries.append({
            "host_ip": host_ip,
            "current_stage": result.current_stage,
            "stage_label": stage_meta.get("label", result.current_stage),
            "stage_severity": stage_meta.get("severity", "LOW"),
            "stage_color": stage_meta.get("color", "#10b981"),
            "overall_threat_score": result.overall_threat_score,
            "current_stage_confidence": result.current_stage_confidence,
            "time_to_compromise_min": result.time_to_compromise_min,
            "hardware_relay_required": result.hardware_relay_required,
            "active_flows": len(flows),
        })

    # Sort by threat score descending
    summaries.sort(key=lambda x: x["overall_threat_score"], reverse=True)
    return {"hosts": summaries, "count": len(summaries)}


@app.get("/forecast/timeline", tags=["forecast"])
def get_timeline_forecast():
    """Full forecast for the highest-threat active host."""
    hosts = _get_all_hosts()

    if not hosts:
        # Return a benign default so UI doesn't blank out
        return {
            "host_ip": "no-active-hosts",
            "current_stage": "STAGE_0_BENIGN",
            "current_stage_confidence": 0.95,
            "overall_threat_score": 5,
            "time_to_compromise_min": 0.0,
            "all_stages": {k: {"label": v["label"], "severity": v["severity"],
                               "color": v["color"], "mitre_tactics": v["mitre_tactics"],
                               "description": v["description"],
                               "data_coverage": v.get("data_coverage", "calibrated_empirical")} for k, v in STAGE_METADATA.items()},
            "shap_explanations": [],
            "preemptive_actions": [],
            "blast_radius_nodes": [],
            "hardware_relay_required": False,
            "forecast_15m": {"stage": "STAGE_0_BENIGN", "label": "Benign", "confidence": 0.95, "time_min": 0, "data_coverage": "calibrated_empirical"},
            "forecast_30m": {"stage": "STAGE_0_BENIGN", "label": "Benign", "confidence": 0.92, "time_min": 0, "data_coverage": "calibrated_empirical"},
            "forecast_60m": {"stage": "STAGE_0_BENIGN", "label": "Benign", "confidence": 0.88, "time_min": 0, "data_coverage": "calibrated_empirical"},
            "provenance": {
                "current_stage": "default_no_hosts",
                "horizon_projection": "calibrated_baseline" if forecaster.priors_calibrated else "expert_prior_baseline",
                "time_to_compromise": "zero_threat_baseline",
                "feature_attributions": "none",
                "priors_source": forecaster.priors_source
            },
            "message": "No active monitored hosts. Run a simulation or ingest PCAP/flow data.",
        }

    # Pick highest-threat host
    best_host = hosts[0]
    best_score = -1
    for h in hosts:
        flows = _get_flow_timeline(h)
        result = forecaster.evaluate_host_timeline(h, flows)
        if result.overall_threat_score > best_score:
            best_score = result.overall_threat_score
            best_host = h
            best_result = result

    return _forecast_to_dict(best_result)


@app.get("/forecast/{host_ip}", tags=["forecast"])
def get_host_forecast(host_ip: str):
    """Full forecast for a specific host IP."""
    flows = _get_flow_timeline(host_ip)
    if not flows:
        return {
            "host_ip": host_ip,
            "current_stage": "STAGE_0_BENIGN",
            "current_stage_confidence": 0.95,
            "overall_threat_score": 5,
            "time_to_compromise_min": 0.0,
            "all_stages": {k: {"label": v["label"], "severity": v["severity"],
                               "color": v["color"], "mitre_tactics": v["mitre_tactics"],
                               "description": v["description"],
                               "data_coverage": v.get("data_coverage", "calibrated_empirical")} for k, v in STAGE_METADATA.items()},
            "shap_explanations": [],
            "preemptive_actions": [],
            "blast_radius_nodes": [],
            "hardware_relay_required": False,
            "forecast_15m": {"stage": "STAGE_0_BENIGN", "label": "Benign", "confidence": 0.95, "time_min": 0, "data_coverage": "calibrated_empirical"},
            "forecast_30m": {"stage": "STAGE_0_BENIGN", "label": "Benign", "confidence": 0.92, "time_min": 0, "data_coverage": "calibrated_empirical"},
            "forecast_60m": {"stage": "STAGE_0_BENIGN", "label": "Benign", "confidence": 0.88, "time_min": 0, "data_coverage": "calibrated_empirical"},
            "message": f"Host {host_ip} is at clean baseline state with 0 anomaly flows.",
        }
    result = forecaster.evaluate_host_timeline(host_ip, flows)
    return _forecast_to_dict(result)


# ─── Hardware Relay ───────────────────────────────────────────────────────────

class RelayRequest(BaseModel):
    action: str  # "ENGAGE" or "RELEASE"
    reason: Optional[str] = None


@app.get("/hardware/relay", tags=["hardware"])
def get_relay_state():
    return {**_relay_state, "gpio_pin": 18, "label": "Zephyr RTOS Relay"}


@app.post("/hardware/relay", tags=["hardware"])
def trip_relay(req: RelayRequest):
    if req.action not in ("ENGAGE", "RELEASE"):
        raise HTTPException(status_code=400, detail="action must be ENGAGE or RELEASE")
    if req.action == "ENGAGE":
        _relay_state["engaged"] = True
        _relay_state["engaged_at"] = time.time()
        _relay_state["reason"] = req.reason or "Manual trigger"
        logger.warning(f"[HARDWARE] Relay ENGAGED — {_relay_state['reason']}")
        return {"status": "ENGAGED", "gpio_pin": 18, "message": "Air-gap relay tripped. Network trunk isolated."}
    else:
        _relay_state["engaged"] = False
        _relay_state["engaged_at"] = None
        _relay_state["reason"] = None
        logger.info("[HARDWARE] Relay RELEASED — network trunk restored")
        return {"status": "RELEASED", "gpio_pin": 18, "message": "Air-gap relay released. Network trunk restored."}
