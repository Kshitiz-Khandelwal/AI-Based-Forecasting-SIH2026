"use client";

import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock,
  Cpu,
  FileUp,
  Layers,
  Play,
  Radio,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  TrendingUp,
  Users,
  Zap,
  Activity,
  Target,
  Crosshair,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ShapFeature {
  feature: string;
  value: string;
  shap_value: number;
}

interface ForecastHorizon {
  stage: string;
  label: string;
  confidence: number;
  time_min: number;
  confidence_cone?: [number, number];
}

interface StageMeta {
  label: string;
  description: string;
  severity?: string;
  color?: string;
  mitre_tactics?: string[];
}

interface ForecastData {
  host_ip: string;
  current_stage: string;
  current_stage_confidence: number;
  overall_threat_score: number;
  time_to_compromise_min: number;
  forecast_15m?: ForecastHorizon;
  forecast_30m?: ForecastHorizon;
  forecast_60m?: ForecastHorizon;
  shap_explanations: ShapFeature[];
  all_stages: Record<string, StageMeta>;
  hardware_relay_required?: boolean;
  blast_radius_nodes?: string[];
  preemptive_actions?: Array<{ action: string; priority: string; description: string; target: string }>;
  observed_qps?: number;
  active_flows?: number;
  provenance?: Record<string, string>;
  message?: string;
}

interface HostSummary {
  host_ip: string;
  current_stage: string;
  stage_label: string;
  stage_severity: string;
  stage_color: string;
  overall_threat_score: number;
  current_stage_confidence: number;
  time_to_compromise_min: number;
  hardware_relay_required: boolean;
  active_flows: number;
}

interface PcapResult {
  status: string;
  filename: string;
  packets_parsed: number;
  source_hosts: string[];
}

// ─── Constants ────────────────────────────────────────────────────────────────

const STAGE_ORDER = [
  "STAGE_1_RECONNAISSANCE",
  "STAGE_2_INITIAL_ACCESS",
  "STAGE_3_DISCOVERY",
  "STAGE_4_C2_PERSISTENCE",
  "STAGE_5_LATERAL_MOVEMENT",
  "STAGE_6_EXFILTRATION",
];

const STAGE_COLORS: Record<string, string> = {
  STAGE_0_BENIGN: "#10b981",
  STAGE_1_RECONNAISSANCE: "#f59e0b",
  STAGE_2_INITIAL_ACCESS: "#f97316",
  STAGE_3_DISCOVERY: "#e11d48",
  STAGE_4_C2_PERSISTENCE: "#dc2626",
  STAGE_5_LATERAL_MOVEMENT: "#9333ea",
  STAGE_6_EXFILTRATION: "#7f1d1d",
};

const DEFAULT_FALLBACK: ForecastData = {
  host_ip: "172.28.0.101",
  current_stage: "STAGE_2_INITIAL_ACCESS",
  current_stage_confidence: 0.88,
  overall_threat_score: 74,
  time_to_compromise_min: 45.5,
  forecast_15m: { stage: "STAGE_4_C2_PERSISTENCE", confidence: 0.85, label: "C2 Beaconing", time_min: 15, confidence_cone: [0.70, 0.93] },
  forecast_30m: { stage: "STAGE_5_LATERAL_MOVEMENT", confidence: 0.72, label: "Lateral Movement", time_min: 30, confidence_cone: [0.55, 0.85] },
  forecast_60m: { stage: "STAGE_6_EXFILTRATION", confidence: 0.65, label: "Exfiltration", time_min: 60, confidence_cone: [0.45, 0.80] },
  shap_explanations: [
    { feature: "Port Sweep Diversity", value: "14 ports", shap_value: 0.32 },
    { feature: "C2 Heartbeat Periodicity", value: "0.91 regularity", shap_value: 0.41 },
    { feature: "DNS Tunneling Markers", value: "3 tags", shap_value: 0.48 },
    { feature: "SYN Flood Ratio", value: "45.0%", shap_value: 0.25 },
  ],
  all_stages: {
    STAGE_1_RECONNAISSANCE: { label: "Network & DNS Reconnaissance", description: "Port sweeps and aggressive DNS enumeration.", severity: "LOW-MEDIUM", color: "#f59e0b", mitre_tactics: ["TA0043", "T1595"] },
    STAGE_2_INITIAL_ACCESS: { label: "Initial Access & DGA Contact", description: "Malicious DGA seed queries and homoglyphs.", severity: "MEDIUM", color: "#f97316", mitre_tactics: ["TA0001", "T1568"] },
    STAGE_3_DISCOVERY: { label: "Internal Subnet Discovery", description: "Internal lateral port sweeps and LDAP probes.", severity: "MEDIUM-HIGH", color: "#e11d48", mitre_tactics: ["TA0007"] },
    STAGE_4_C2_PERSISTENCE: { label: "Command & Control (C2) Beaconing", description: "Periodic heartbeat pulses and Cobalt Strike sync.", severity: "HIGH", color: "#dc2626", mitre_tactics: ["TA0011"] },
    STAGE_5_LATERAL_MOVEMENT: { label: "Lateral Movement", description: "Pivoting towards Core Financial Database.", severity: "CRITICAL", color: "#9333ea", mitre_tactics: ["TA0008"] },
    STAGE_6_EXFILTRATION: { label: "Data Exfiltration & Impact", description: "Bulk Base64 encoded egress attempt.", severity: "EMERGENCY", color: "#7f1d1d", mitre_tactics: ["TA0010"] },
  },
  hardware_relay_required: false,
  blast_radius_nodes: ["192.168.1.44", "192.168.1.50", "192.168.1.89"],
  preemptive_actions: [],
};

// ─── Utilities ────────────────────────────────────────────────────────────────

function threatBadgeClass(score: number) {
  if (score >= 85) return "bg-red-100 text-red-900";
  if (score >= 60) return "bg-orange-100 text-orange-900";
  if (score >= 35) return "bg-amber-100 text-amber-900";
  return "bg-emerald-100 text-emerald-900";
}

function threatLabel(score: number) {
  if (score >= 85) return "CRITICAL";
  if (score >= 60) return "HIGH RISK";
  if (score >= 35) return "MODERATE";
  return "LOW";
}

function severityBorder(severity?: string) {
  if (severity === "EMERGENCY") return "border-l-4 border-l-red-900";
  if (severity === "CRITICAL") return "border-l-4 border-l-purple-600";
  if (severity === "HIGH") return "border-l-4 border-l-red-600";
  if (severity === "MEDIUM-HIGH") return "border-l-4 border-l-rose-500";
  if (severity === "MEDIUM") return "border-l-4 border-l-orange-500";
  return "border-l-4 border-l-amber-400";
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function ForecastPage() {
  const [data, setData] = useState<ForecastData>(DEFAULT_FALLBACK);
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [serviceOffline, setServiceOffline] = useState(false);
  const [relayTripped, setRelayTripped] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [simStage, setSimStage] = useState<string | null>(null);
  const [pcapUploading, setPcapUploading] = useState(false);
  const [pcapResult, setPcapResult] = useState<PcapResult | null>(null);
  const [pcapError, setPcapError] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const SIM_HOST = "172.28.0.101";

  // ─── Data Fetching ──────────────────────────────────────────────────────────

  const fetchForecast = useCallback(async () => {
    try {
      const url = selectedHost
        ? `/api/v1/forecast/${selectedHost}`
        : "/api/v1/forecast/timeline";
      const res = await fetch(url, { cache: "no-store" });
      if (res.ok) {
        const json = await res.json();
        if (!json.error) {
          setData(json);
          setServiceOffline(false);
        } else {
          setServiceOffline(true);
        }
      } else {
        setServiceOffline(true);
      }
    } catch {
      setServiceOffline(true);
    } finally {
      setLoading(false);
    }
  }, [selectedHost]);

  const fetchHosts = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/forecast/hosts", { cache: "no-store" });
      if (res.ok) {
        const json = await res.json();
        setHosts(json.hosts || []);
      }
    } catch {
      setHosts([]);
    }
  }, []);

  async function handleManualRefresh() {
    setRefreshing(true);
    try {
      await Promise.all([fetchForecast(), fetchHosts()]);
    } finally {
      setTimeout(() => setRefreshing(false), 500);
    }
  }

  useEffect(() => {
    fetchForecast();
    fetchHosts();
  }, [fetchForecast, fetchHosts]);

  useEffect(() => {
    if (!isLive) return;
    const iv = setInterval(() => {
      fetchForecast();
      fetchHosts();
    }, 3000);
    return () => clearInterval(iv);
  }, [fetchForecast, fetchHosts, isLive]);

  // ─── Actions ────────────────────────────────────────────────────────────────

  async function handleToggleRelay() {
    const nextState = !relayTripped;
    try {
      const res = await fetch(`/api/v1/hardware/trip-relay?action=${nextState ? "ENGAGE" : "RELEASE"}`, { method: "POST" });
      if (res.ok) {
        setRelayTripped(nextState);
      } else {
        const stateRes = await fetch("/api/v1/hardware/trip-relay");
        if (stateRes.ok) {
          const stateJson = await stateRes.json();
          setRelayTripped(stateJson.relay_tripped ?? false);
        }
      }
    } catch {
      try {
        const stateRes = await fetch("/api/v1/hardware/trip-relay");
        if (stateRes.ok) {
          const stateJson = await stateRes.json();
          setRelayTripped(stateJson.relay_tripped ?? false);
        }
      } catch {
        // preserve current state on complete offline
      }
    }
  }

  async function handleSimulate() {
    if (simulating) return;
    setSimulating(true);
    setSimStage(null);
    try {
      const target = selectedHost || SIM_HOST;
      const res = await fetch(`/api/v1/flow/simulate/${target}`, { method: "POST" });
      if (res.ok) {
        const json = await res.json();
        setSimStage(json.simulated_stage || null);
      } else {
        const errJson = await res.json().catch(() => ({}));
        setSimStage(`Simulation Error: ${errJson.message || res.statusText || "Service Unreachable"}`);
      }
    } catch (err: any) {
      setSimStage(`Simulation Failed: ${err.message || "Network Error"}`);
    } finally {
      await new Promise((r) => setTimeout(r, 400));
      await Promise.all([fetchForecast(), fetchHosts()]);
      setSimulating(false);
    }
  }

  async function handleFullSimulate() {
    setSimulating(true);
    setSimStage(null);
    try {
      const target = selectedHost || SIM_HOST;
      const res = await fetch(`/api/v1/flow/simulate/${target}/full`, { method: "POST" });
      if (res.ok) {
        setSimStage("ALL_STAGES (Stage 1 to 6)");
      } else {
        const errJson = await res.json().catch(() => ({}));
        setSimStage(`Full Simulation Error: ${errJson.message || res.statusText || "Service Unreachable"}`);
      }
    } catch (err: any) {
      setSimStage(`Full Simulation Failed: ${err.message || "Network Error"}`);
    } finally {
      await new Promise((r) => setTimeout(r, 600));
      await Promise.all([fetchForecast(), fetchHosts()]);
      setSimulating(false);
    }
  }

  async function handleResetSimulation() {
    const target = selectedHost || SIM_HOST;
    try {
      const res = await fetch(`/api/v1/flow/hosts/${target}`, { method: "DELETE" });
      if (res.ok) {
        setSimStage("RESET_TO_BENIGN");
      } else {
        setSimStage("Reset failed (Host unreachable)");
      }
      await Promise.all([fetchForecast(), fetchHosts()]);
    } catch (err: any) {
      setSimStage(`Reset Failed: ${err.message || "Network Error"}`);
    }
  }

  async function handlePcapUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setPcapUploading(true);
    setPcapResult(null);
    setPcapError(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const res = await fetch("/api/v1/flow/ingest/pcap", { method: "POST", body: form });
      const json = await res.json();
      if (!res.ok) throw new Error(json.detail || "Upload failed");
      setPcapResult(json);
      fetchHosts();
    } catch (err: any) {
      setPcapError(err.message || "Upload failed");
    } finally {
      setPcapUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  }

  async function handleResetHost(hostIp: string) {
    try {
      await fetch(`/api/v1/flow/hosts/${hostIp}`, { method: "DELETE" });
      fetchHosts();
      if (selectedHost === hostIp) {
        setSelectedHost(null);
        fetchForecast();
      }
    } catch { /* silent */ }
  }

  // ─── Derived State ───────────────────────────────────────────────────────────

  const currentStage = data.current_stage || "STAGE_0_BENIGN";
  const currentIdx = STAGE_ORDER.indexOf(currentStage);
  const ttcMin = data.time_to_compromise_min ?? 0;

  const threatScore = data.overall_threat_score ?? 0;
  const conf = Math.round((data.current_stage_confidence ?? 0.88) * 100);

  // ─── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-5 md:p-7 space-y-5 max-w-[1700px] mx-auto">

      {/* ── Page Header ─────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 pb-4 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
              AI Network Attack Forecasting
            </h1>
            <span className="text-[10px] font-mono font-bold bg-blue-100 text-blue-800 px-2 py-0.5 rounded-full">
              SIH 2026 — PS2
            </span>
            <span className="text-[10px] font-mono font-bold bg-violet-100 text-violet-800 px-2 py-0.5 rounded-full">
              MITRE ATT&CK
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Sequential kill-chain projection from 5-tuple NetFlow, DNS sessions & PCAP ingestion. TTC = Time-to-Compromise.
          </p>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {/* Live toggle */}
          <button
            onClick={() => setIsLive((p) => !p)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all",
              isLive
                ? "bg-emerald-50 border-emerald-300 text-emerald-800"
                : "bg-slate-100 border-slate-300 text-slate-600"
            )}
          >
            <Radio className={cn("w-3 h-3", isLive && "animate-pulse")} />
            {isLive ? "LIVE" : "PAUSED"}
          </button>

          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold rounded-lg transition-all shadow-2xs active:scale-95"
          >
            <RefreshCw className={cn("w-3 h-3 text-slate-600", refreshing && "animate-spin text-blue-600")} />
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>

          {/* Reset simulation */}
          <button
            onClick={handleResetSimulation}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold rounded-lg border border-slate-200 transition-all shadow-2xs active:scale-95"
            title="Reset simulation back to clean baseline"
          >
            <RotateCcw className="w-3 h-3" />
            Reset State
          </button>

          {/* Step simulate */}
          <button
            onClick={handleSimulate}
            disabled={simulating}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold rounded-lg shadow-sm transition-all disabled:opacity-50 active:scale-95"
          >
            <Play className="w-3 h-3 fill-current" />
            {simulating ? "Advancing…" : "Simulate Next Stage"}
          </button>

          {/* Full APT */}
          <button
            onClick={handleFullSimulate}
            disabled={simulating}
            className="flex items-center gap-2 px-3.5 py-1.5 bg-red-600 hover:bg-red-700 text-white text-xs font-semibold rounded-lg shadow-sm transition-all disabled:opacity-50 active:scale-95"
          >
            <Crosshair className="w-3 h-3" />
            Full Kill-Chain
          </button>
        </div>
      </div>

      {/* ── Degraded State Warning (Honest UX) ─────────────────────────────────── */}
      {serviceOffline && (
        <div className="bg-amber-50 border border-amber-300 rounded-xl p-4 flex items-center justify-between gap-4 text-amber-900 shadow-sm">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0" />
            <div>
              <div className="font-bold text-sm">Forecasting Engine Offline / Degraded State</div>
              <div className="text-xs text-amber-700 mt-0.5">
                Could not connect to <span className="font-mono">forecasting-engine</span> (port 8007). Showing cached baseline profile. Start the backend with <code className="bg-amber-100 px-1 py-0.5 rounded font-mono text-[11px]">python run_backend.py</code> to view live predictions.
              </div>
            </div>
          </div>
          <button
            onClick={fetchForecast}
            className="px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white text-xs font-semibold rounded-lg shrink-0 transition-colors"
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* ── Sim Notification ─────────────────────────────────────────────────── */}
      {simStage && (
        <div className="bg-blue-50 border border-blue-200 rounded-xl px-4 py-3 flex items-center gap-3 text-sm">
          <Activity className="w-4 h-4 text-blue-600 shrink-0" />
          <span className="text-blue-900 font-semibold">
            Injected: <span className="font-mono">{simStage}</span>
          </span>
          <span className="text-blue-600 text-xs">{simStage === "ALL_STAGES" ? "All 6 kill-chain stages loaded" : "Flow telemetry ingested — forecasting updated"}</span>
          <button onClick={() => setSimStage(null)} className="ml-auto text-blue-400 hover:text-blue-700 text-xs">✕</button>
        </div>
      )}


      {/* ── KPI Row ──────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">

        {/* Active Stage */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-amber-400" />
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex justify-between">
            <span>Active Kill Phase</span>
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="text-base font-bold text-slate-900 leading-tight">
            {data.all_stages?.[currentStage]?.label?.split("&")[0]?.trim() || "Initial Access"}
          </div>
          <div className="mt-1.5 text-[10px] font-mono text-amber-800 bg-amber-100 inline-flex px-2 py-0.5 rounded font-bold">
            {conf}% confidence
          </div>
        </div>

        {/* Threat Score */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-red-600" />
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex justify-between">
            <span>Threat Index</span>
            <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900">{threatScore}<span className="text-sm text-slate-400">/100</span></div>
          <span className={cn("mt-1.5 text-[10px] font-mono font-bold inline-flex px-2 py-0.5 rounded", threatBadgeClass(threatScore))}>
            {threatLabel(threatScore)}
          </span>
        </div>

        {/* ⏱️ TTC — Time-to-Compromise (PS2 core requirement) */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-purple-600" />
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex justify-between">
            <span>TTC — Time-to-Compromise</span>
            <Clock className="w-3.5 h-3.5 text-purple-600" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-900">
            {ttcMin > 0 ? `~${ttcMin}m` : "—"}
          </div>
          <div className="mt-1.5 text-[10px] text-purple-800 bg-purple-100 inline-flex px-2 py-0.5 rounded font-mono font-bold">
            {ttcMin > 0 ? "Until STAGE 6" : "Already At Impact"}
          </div>
        </div>

        {/* Next Stage Forecast */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-blue-600" />
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex justify-between">
            <span>Predicted Next</span>
            <TrendingUp className="w-3.5 h-3.5 text-blue-600" />
          </div>
          <div className="text-base font-bold text-slate-900 leading-tight">
            {data.forecast_15m?.label || "C2 Beaconing"}
          </div>
          <div className="mt-1.5 text-[10px] font-mono text-blue-800 bg-blue-100 inline-flex px-2 py-0.5 rounded font-bold">
            +{data.forecast_15m?.time_min ?? 15}m / {Math.round((data.forecast_15m?.confidence ?? 0.85) * 100)}%
          </div>
        </div>

        {/* Zephyr Relay */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm relative overflow-hidden">
          <div className={cn("absolute top-0 left-0 right-0 h-0.5", relayTripped ? "bg-red-600" : "bg-emerald-500")} />
          <div className="text-[10px] font-bold text-slate-400 uppercase tracking-wider mb-2 flex justify-between">
            <span>Zephyr RTOS Relay</span>
            <Cpu className={cn("w-3.5 h-3.5", relayTripped ? "text-red-600" : "text-emerald-500")} />
          </div>
          <div className={cn("text-base font-bold", relayTripped ? "text-red-700" : "text-emerald-700")}>
            {relayTripped ? "AIR-GAP ISOLATED" : "ARMED / SECURE"}
          </div>
          <div className="mt-1.5 flex items-center gap-1.5">
            <div className={cn("w-2 h-2 rounded-full animate-pulse", relayTripped ? "bg-red-600" : "bg-emerald-500")} />
            <span className="text-[10px] font-mono text-slate-400">GPIO 18</span>
          </div>
        </div>
      </div>

      {/* ── Main Grid ────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">

        {/* LEFT: Host Monitor Panel (3 cols) */}
        <div className="lg:col-span-3 space-y-4">
          
          {/* Active Host List */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm">
            <div className="p-4 border-b border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Users className="w-4 h-4 text-slate-600" />
                <h2 className="text-sm font-bold text-slate-900">Monitored Hosts</h2>
              </div>
              <span className="text-[10px] font-mono bg-slate-100 text-slate-600 px-2 py-0.5 rounded">
                {hosts.length} active
              </span>
            </div>
            <div className="divide-y divide-slate-100 max-h-64 overflow-y-auto">
              {hosts.length === 0 ? (
                <div className="p-4 text-center text-xs text-slate-400">
                  No hosts monitored.<br />Run a simulation or upload PCAP.
                </div>
              ) : (
                hosts.map((h) => (
                  <button
                    key={h.host_ip}
                    onClick={() => setSelectedHost(h.host_ip === selectedHost ? null : h.host_ip)}
                    className={cn(
                      "w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-slate-50 transition-colors",
                      selectedHost === h.host_ip && "bg-blue-50"
                    )}
                  >
                    <div
                      className="w-2.5 h-2.5 rounded-full shrink-0"
                      style={{ background: h.stage_color || "#10b981" }}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs font-mono font-bold text-slate-900 truncate">{h.host_ip}</div>
                      <div className="text-[10px] text-slate-400 truncate">{h.stage_label}</div>
                    </div>
                    <span className={cn("text-[10px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0", threatBadgeClass(h.overall_threat_score))}>
                      {h.overall_threat_score}
                    </span>
                  </button>
                ))
              )}
            </div>
            {selectedHost && (
              <div className="p-3 border-t border-slate-100 flex gap-2">
                <button
                  onClick={() => setSelectedHost(null)}
                  className="flex-1 text-[11px] py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold transition-colors"
                >
                  Show Top Threat
                </button>
                <button
                  onClick={() => handleResetHost(selectedHost)}
                  className="text-[11px] py-1.5 px-3 rounded-lg bg-red-50 hover:bg-red-100 text-red-700 font-semibold transition-colors"
                >
                  Reset Host
                </button>
              </div>
            )}
          </div>

          {/* PCAP Upload */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-4 space-y-3">
            <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
              <FileUp className="w-4 h-4 text-slate-600" />
              <h2 className="text-sm font-bold text-slate-900">PCAP Ingestion</h2>
            </div>
            <p className="text-[11px] text-slate-500">
              Upload a .pcap file to extract real 5-tuple flow data and run kill-chain forecasting.
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handlePcapUpload}
              className="hidden"
              id="pcap-upload-input"
            />
            <label
              htmlFor="pcap-upload-input"
              className={cn(
                "flex flex-col items-center justify-center gap-2 w-full h-20 border-2 border-dashed rounded-xl cursor-pointer transition-colors",
                pcapUploading
                  ? "border-blue-300 bg-blue-50"
                  : "border-slate-200 hover:border-blue-300 hover:bg-slate-50"
              )}
            >
              {pcapUploading ? (
                <>
                  <RefreshCw className="w-5 h-5 text-blue-500 animate-spin" />
                  <span className="text-xs text-blue-600 font-semibold">Parsing PCAP…</span>
                </>
              ) : (
                <>
                  <FileUp className="w-5 h-5 text-slate-400" />
                  <span className="text-xs text-slate-500">Click or drag .pcap file</span>
                </>
              )}
            </label>
            {pcapResult && (
              <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3 text-xs space-y-1">
                <div className="font-bold text-emerald-900">✓ {pcapResult.filename}</div>
                <div className="font-mono text-emerald-700">{pcapResult.packets_parsed} packets parsed</div>
                <div className="text-emerald-600">{pcapResult.source_hosts.slice(0, 3).join(", ")} detected</div>
              </div>
            )}
            {pcapError && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-xs text-red-800">
                ✗ {pcapError}
              </div>
            )}
          </div>

          {/* Zephyr Hardware Sentinel (Emulated Signal) */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-4 space-y-3">
            <div className="flex items-center gap-2 pb-2 border-b border-slate-100">
              <Cpu className="w-4 h-4 text-blue-600" />
              <h2 className="text-sm font-bold text-slate-900">Zephyr RTOS Sentinel</h2>
              <span className="text-[10px] font-mono bg-blue-100 text-blue-800 px-1.5 py-0.5 rounded ml-auto">Emulation</span>
            </div>
            <div className="bg-slate-950 rounded-lg p-3 font-mono text-[11px] text-sky-400 space-y-1 border border-slate-800">
              <div className="flex justify-between text-sky-300 font-bold border-b border-sky-900/50 pb-1">
                <span>PROBE TELEMETRY</span>
                <span>{typeof data.observed_qps === "number" ? `${data.observed_qps.toFixed(1)} QPS` : `${selectedHost ? (selectedHost.active_flows / 10).toFixed(1) : "0.0"} QPS`}</span>
              </div>
              <div className="text-slate-200 font-bold">SIGNAL: {relayTripped ? "AIR-GAP ENGAGED (EMULATED)" : "ARMED / SECURE (EMULATED)"}</div>
              <div className="text-slate-400">THREAT: {threatScore} / 100</div>
              <div className="text-amber-400">TTC: ~{ttcMin > 0 ? ttcMin : "0"}m to STAGE_6</div>
              <div className="text-slate-500 text-[10px] pt-1 border-t border-slate-800">
                Mode: Software Air-Gap Signal (GPIO 18 Mock)
              </div>
              {data.hardware_relay_required && (
                <div className="text-red-400 font-bold animate-pulse">⚡ RELAY TRIP RECOMMENDED</div>
              )}
            </div>
            <button
              onClick={handleToggleRelay}
              className={cn(
                "w-full py-2 rounded-lg text-xs font-bold flex items-center justify-center gap-2 transition-all shadow-sm",
                relayTripped
                  ? "bg-emerald-600 hover:bg-emerald-700 text-white"
                  : "bg-red-600 hover:bg-red-700 text-white"
              )}
            >
              {relayTripped ? <RotateCcw className="w-3.5 h-3.5" /> : <Zap className="w-3.5 h-3.5" />}
              {relayTripped ? "RESTORE NETWORK TRUNK" : "⚡ TRIP AIR-GAP RELAY SIGNAL"}
            </button>
          </div>

        </div>

        {/* CENTER: Kill-Chain Timeline (6 cols) */}
        <div className="lg:col-span-6 space-y-4">

          {/* Timeline Card */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
            <div className="flex items-start justify-between pb-4 mb-4 border-b border-slate-100">
              <div>
                <h2 className="text-sm font-bold text-slate-900">MITRE ATT&CK Kill-Chain Trajectory</h2>
                <p className="text-[11px] text-slate-500 mt-0.5">
                  Monitoring: <span className="font-mono font-semibold">{data.host_ip}</span>
                </p>
              </div>
              <span className="text-[10px] font-mono bg-blue-50 text-blue-700 border border-blue-200 px-2 py-0.5 rounded shrink-0 font-semibold">
                Neural GRU + Markov Rollout
              </span>
            </div>

            <div className="space-y-2">
              {STAGE_ORDER.map((stageKey, idx) => {
                const meta = data.all_stages?.[stageKey] || { label: stageKey, description: "", severity: "LOW" };
                const isCurrent = stageKey === currentStage;
                const isPast = idx < currentIdx;
                const isFuture = idx > currentIdx;
                const forecastConf =
                  idx === currentIdx + 1 ? data.forecast_15m?.confidence
                  : idx === currentIdx + 2 ? data.forecast_30m?.confidence
                  : idx === currentIdx + 3 ? data.forecast_60m?.confidence
                  : undefined;

                return (
                  <div
                    key={stageKey}
                    className={cn(
                      "p-3 rounded-xl border transition-all flex items-center gap-3",
                      isCurrent && "bg-amber-50 border-amber-300 shadow-sm",
                      isPast && "bg-emerald-50/40 border-emerald-200",
                      isFuture && "bg-slate-50/50 border-slate-200 border-dashed opacity-80"
                    )}
                  >
                    {/* Stage badge */}
                    <div
                      className={cn(
                        "w-8 h-8 rounded-lg flex items-center justify-center text-xs font-bold font-mono border shrink-0",
                        isCurrent && "text-white border-amber-600",
                        isPast && "text-white border-emerald-700",
                        isFuture && "bg-white text-slate-400 border-slate-300"
                      )}
                      style={
                        isCurrent ? { background: meta.color || "#f59e0b" }
                        : isPast ? { background: "#059669" }
                        : undefined
                      }
                    >
                      {isPast ? "✓" : idx + 1}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-bold text-slate-900">{meta.label}</span>
                        {isCurrent && (
                          <span className="text-[9px] bg-amber-500 text-white font-mono px-1.5 py-0.5 rounded font-bold">
                            ACTIVE {conf}%
                          </span>
                        )}
                        {isPast && (
                          <span className="text-[9px] bg-emerald-100 text-emerald-800 font-mono px-1.5 py-0.5 rounded font-semibold">
                            RESOLVED
                          </span>
                        )}
                        {isFuture && forecastConf !== undefined && (
                          <span className="text-[9px] bg-blue-100 text-blue-800 font-mono px-1.5 py-0.5 rounded font-semibold">
                            {Math.round(forecastConf * 100)}% likely
                          </span>
                        )}
                      </div>
                      <p className="text-[10px] text-slate-400 mt-0.5 truncate">{meta.description}</p>
                      {meta.mitre_tactics && meta.mitre_tactics.length > 0 && (
                        <div className="flex gap-1 mt-1 flex-wrap">
                          {meta.mitre_tactics.slice(0, 2).map((t) => (
                            <span key={t} className="text-[9px] bg-slate-100 text-slate-500 px-1.5 rounded font-mono">
                              {t}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>

                    <div className="text-[10px] font-mono font-bold text-slate-500 shrink-0 text-right">
                      {isCurrent ? (
                        <span className="text-blue-600 font-extrabold">Active (t = 0m)</span>
                      ) : isPast ? (
                        <span className="text-slate-400 font-normal">Traversed</span>
                      ) : stageKey === "STAGE_6_EXFILTRATION" && data.time_to_compromise_min > 0 ? (
                        <span className="text-amber-600 font-bold">TTC ~{data.time_to_compromise_min}m</span>
                      ) : data.forecast_15m?.stage === stageKey ? (
                        <span className="text-indigo-600 font-semibold">~+15m model projection</span>
                      ) : data.forecast_30m?.stage === stageKey ? (
                        <span className="text-orange-600 font-semibold">~+30m model projection</span>
                      ) : data.forecast_60m?.stage === stageKey ? (
                        <span className="text-rose-600 font-semibold">~+60m model projection</span>
                      ) : (
                        <span className="text-slate-400 font-normal">Approx. ~+{(idx - currentIdx) * 15}m</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Forecast Horizon Cards */}
          <div className="grid grid-cols-3 gap-3">
            {([
              { h: data.forecast_15m, label: "+15 min", color: "blue" },
              { h: data.forecast_30m, label: "+30 min", color: "orange" },
              { h: data.forecast_60m, label: "+60 min", color: "red" },
            ] as const).map(({ h, label, color }) => (
              <div key={label} className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
                <div className="text-[10px] font-mono font-bold text-slate-400 uppercase mb-2">{label} Horizon</div>
                <div className="text-xs font-bold text-slate-900 leading-tight mb-1">{h?.label || "—"}</div>
                {h?.confidence_cone ? (
                  <div className="mt-2">
                    <div className="relative h-1.5 bg-slate-100 rounded-full overflow-hidden">
                      <div
                        className="absolute h-full bg-current rounded-full opacity-30"
                        style={{
                          left: `${(h.confidence_cone[0] ?? 0) * 100}%`,
                          width: `${((h.confidence_cone[1] ?? 1) - (h.confidence_cone[0] ?? 0)) * 100}%`,
                          background: STAGE_COLORS[h.stage] || "#6366f1",
                        }}
                      />
                      <div
                        className="absolute h-full rounded-full"
                        style={{
                          left: 0,
                          width: `${(h.confidence ?? 0.5) * 100}%`,
                          background: STAGE_COLORS[h.stage] || "#6366f1",
                        }}
                      />
                    </div>
                    <div className="text-[9px] font-mono text-slate-400 mt-1">
                      {Math.round((h.confidence_cone[0] ?? 0) * 100)}%–{Math.round((h.confidence_cone[1] ?? 1) * 100)}% cone
                    </div>
                  </div>
                ) : (
                  <div className="text-[11px] font-mono text-slate-500">{Math.round((h?.confidence ?? 0) * 100)}%</div>
                )}
              </div>
            ))}
          </div>

          {/* AI Provenance & Methodology Transparency (Task 1 Requirement) */}
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 shadow-2xs">
            <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-200">
              <div className="flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-blue-600" />
                <span className="text-xs font-bold text-slate-800">AI Provenance &amp; Calibration Transparency</span>
              </div>
              <span className="text-[9px] font-mono font-bold bg-white text-slate-600 border border-slate-200 px-2 py-0.5 rounded">
                HONEST METHODOLOGY
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[10px]">
              <div className="bg-white p-2 rounded-lg border border-slate-200/80">
                <span className="text-slate-400 block font-bold uppercase">Current Stage</span>
                <span className="text-blue-700 font-extrabold block mt-0.5">Trained GRU</span>
                <span className="text-slate-500 text-[9px] block">Neural inference (seq=10)</span>
              </div>

              <div className="bg-white p-2 rounded-lg border border-slate-200/80">
                <span className="text-slate-400 block font-bold uppercase">Markov Horizons</span>
                <span className="text-indigo-700 font-extrabold block mt-0.5">CTU-13 Calibrated</span>
                <span className="text-slate-500 text-[9px] block">N=60,273 transitions</span>
              </div>

              <div className="bg-white p-2 rounded-lg border border-slate-200/80">
                <span className="text-slate-400 block font-bold uppercase">TTC Velocity</span>
                <span className="text-amber-700 font-extrabold block mt-0.5">Empirical Priors</span>
                <span className="text-slate-500 text-[9px] block">Blended dwell times</span>
              </div>

              <div className="bg-white p-2 rounded-lg border border-slate-200/80">
                <span className="text-slate-400 block font-bold uppercase">Feature XAI</span>
                <span className="text-emerald-700 font-extrabold block mt-0.5">Perturbation</span>
                <span className="text-slate-500 text-[9px] block">Input sensitivity analysis</span>
              </div>
            </div>

            <p className="text-[10px] text-slate-500 mt-2.5 font-sans leading-tight">
              {data.provenance?.priors_source 
                ? `Priors active: ${data.provenance.priors_source}. Calibrated transitions seed the Markov rollout from neural GRU state.`
                : "Explicitly distinguishes trained PyTorch neural GRU inference from empirical Markov state transitions and published APT dwell-time priors."}
            </p>
          </div>
        </div>

        {/* RIGHT: SHAP + Blast Radius + Actions (3 cols) */}
        <div className="lg:col-span-3 space-y-4">

          {/* Feature Attributions (Kill-Chain Indicator Weights) */}
          <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
            <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
              <div>
                <h2 className="text-sm font-bold text-slate-900">Feature Attributions & Evidence</h2>
                <p className="text-[10px] text-slate-400 mt-0.5">Additive indicator weights (TreeSHAP in ML Lexical Engine)</p>
              </div>
              <span className="text-[9px] font-mono bg-emerald-100 text-emerald-800 px-1.5 py-0.5 rounded font-bold">
                XAI Signals
              </span>
            </div>
            <div className="space-y-2">
              {data.shap_explanations?.map((item, i) => (
                <div key={i} className="flex flex-col gap-0.5">
                  <div className="flex justify-between text-[11px]">
                    <span className="font-semibold text-slate-700 truncate">{item.feature}</span>
                    <span className={cn("font-mono font-bold ml-2 shrink-0", item.shap_value > 0 ? "text-red-600" : "text-emerald-600")}>
                      {item.shap_value > 0 ? "+" : ""}{item.shap_value.toFixed(2)}
                    </span>
                  </div>
                  <div className="relative h-1.5 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className={cn("absolute h-full rounded-full", item.shap_value > 0 ? "bg-red-500" : "bg-emerald-500")}
                      style={{ width: `${Math.min(100, Math.abs(item.shap_value) * 100)}%` }}
                    />
                  </div>
                  <div className="text-[9px] text-slate-400 font-mono">{item.value}</div>
                </div>
              ))}
            </div>
          </div>


          {/* Blast Radius */}
          {(data.blast_radius_nodes && data.blast_radius_nodes.length > 0) ? (
            <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
              <div className="flex items-center gap-2 pb-3 mb-3 border-b border-slate-100">
                <Target className="w-4 h-4 text-red-600" />
                <h2 className="text-sm font-bold text-slate-900">Blast-Radius Nodes</h2>
                <span className="text-[9px] font-mono bg-red-100 text-red-800 px-1.5 py-0.5 rounded ml-auto font-bold">
                  Lateral Risk
                </span>
              </div>
              <div className="space-y-2 font-mono text-xs">
                <div className="p-2.5 bg-red-50 border border-red-200 rounded-lg flex justify-between text-red-900">
                  <span>{data.host_ip}</span>
                  <span className="font-bold">Patient Zero</span>
                </div>
                {data.blast_radius_nodes.map((n, i) => (
                  <div key={n} className="p-2.5 bg-amber-50 border border-amber-200 rounded-lg flex justify-between text-amber-900">
                    <span>{n}</span>
                    <span className="font-bold">+{(i + 1) * 15}m Target</span>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          {/* Preemptive Actions */}
          {data.preemptive_actions && data.preemptive_actions.length > 0 && (
            <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5">
              <div className="flex items-center gap-2 pb-3 mb-3 border-b border-slate-100">
                <Shield className="w-4 h-4 text-blue-600" />
                <h2 className="text-sm font-bold text-slate-900">Preemptive Actions</h2>
              </div>
              <div className="space-y-2">
                {data.preemptive_actions.map((a, i) => (
                  <div key={i} className={cn("p-3 rounded-lg border text-xs", severityBorder(a.priority))}>
                    <div className="font-bold text-slate-900 font-mono">{a.action}</div>
                    <div className="text-slate-500 mt-0.5">{a.description}</div>
                    <div className="text-[10px] font-mono text-slate-400 mt-1">Target: {a.target}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
