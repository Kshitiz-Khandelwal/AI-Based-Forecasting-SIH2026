"use client";

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  Database, 
  ShieldAlert, 
  FileCheck2, 
  BrainCircuit, 
  Activity, 
  Globe2, 
  ZapOff, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle,
  Info,
  RotateCcw
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface StageDetail {
  id: string;
  name: string;
  shortName: string;
  category: "pre-filter" | "intelligence" | "rules" | "inference" | "behavior" | "enrichment" | "response";
  icon: React.ComponentType<{ className?: string }>;
  contribution: number;
  status: "clean" | "flagged" | "hit" | "normal" | "bypassed" | "quarantined" | "sinkholed" | "degraded";
  reason: string;
  latencyMs: number;
  details?: Record<string, string | number>;
}

export interface PipelineRailProps {
  stages?: StageDetail[];
  verdict?: "ALLOW" | "FLAG" | "BLOCK";
  domain?: string;
  riskScore?: number;
  autoPlay?: boolean;
  onStageSelect?: (stage: StageDetail) => void;
  className?: string;
}

const DEFAULT_STAGES: StageDetail[] = [
  {
    id: "redis-cache",
    name: "Redis Hot Cache / Allowlist",
    shortName: "Hot Cache",
    category: "pre-filter",
    icon: Database,
    contribution: 0,
    status: "clean",
    reason: "No cached verdict; sovereign allowlist check passed in 0.08ms",
    latencyMs: 0.1,
    details: { "Cache Hit": "false", "Sovereign Root": "evaluating", "TTL": "300s" }
  },
  {
    id: "threat-intel",
    name: "Threat Intel / STIX Feed",
    shortName: "Threat Intel",
    category: "intelligence",
    icon: ShieldAlert,
    contribution: 0,
    status: "clean",
    reason: "Zero match across 14,200 active URLhaus/STIX indicators",
    latencyMs: 0.4,
    details: { "Feed Sync": "Active", "IOC Matches": 0, "Confidence": "99.8%" }
  },
  {
    id: "local-rules",
    name: "Local Deterministic Rules",
    shortName: "Local Rules",
    category: "rules",
    icon: FileCheck2,
    contribution: 0,
    status: "clean",
    reason: "No emergency block rules triggered; structure valid",
    latencyMs: 0.2,
    details: { "Syntax Check": "Valid RFC 1035", "Strict TLD": "Allowed", "Punycode": "Decoded" }
  },
  {
    id: "ml-lexical",
    name: "ML Lexical (TreeSHAP)",
    shortName: "ML Lexical",
    category: "inference",
    icon: BrainCircuit,
    contribution: 75,
    status: "hit",
    reason: "High Shannon entropy (4.21) + consonant cluster run (8 chars) -> DGA Generic",
    latencyMs: 31.2,
    details: { "Entropy": 4.21, "Longest Consonant Run": 8, "TreeSHAP Attribution": "+0.48", "Model": "RF-150" }
  },
  {
    id: "behavioral",
    name: "Behavioral Sliding Window",
    shortName: "Behavioral",
    category: "behavior",
    icon: Activity,
    contribution: 25,
    status: "hit",
    reason: "Host 172.28.0.99 exceeded 28 NXDOMAIN queries in 60s window",
    latencyMs: 1.8,
    details: { "60s Burst Rate": "32 QPS", "NXDOMAIN Ratio": "87.5%", "Device Risk Score": 85 }
  },
  {
    id: "geo-intel",
    name: "GeoIP & ASN Context",
    shortName: "Geo Context",
    category: "enrichment",
    icon: Globe2,
    contribution: 0,
    status: "normal",
    reason: "Destination resolved to AS13335 (Cloudflare Inc, US)",
    latencyMs: 0.9,
    details: { "ASN": "AS13335", "Country": "US", "Anycast": "True" }
  },
  {
    id: "active-response",
    name: "Zero-Trust Active Response",
    shortName: "Response",
    category: "response",
    icon: ZapOff,
    contribution: 0,
    status: "quarantined",
    reason: "Device risk (85 >= 80) -> Automated VLAN quarantine & DNS sinkhole (0.0.0.0)",
    latencyMs: 0.6,
    details: { "Action": "Quarantine", "Sinkhole Address": "0.0.0.0", "SOC Alert": "Dispatched" }
  }
];

export function PipelineRail({
  stages = DEFAULT_STAGES,
  verdict = "BLOCK",
  domain = "xq9m2kz7v4naplq.top",
  riskScore,
  autoPlay = true,
  onStageSelect,
  className
}: PipelineRailProps) {
  const [activeStep, setActiveStep] = useState(0);
  const [selectedStageId, setSelectedStageId] = useState<string>(stages[0]?.id || "redis-cache");
  const [isTraversing, setIsTraversing] = useState(true);

  // Restart discrete traversal animation whenever domain or stages change
  useEffect(() => {
    setActiveStep(0);
    setIsTraversing(true);
    
    // Select first stage initially
    if (stages.length > 0) {
      setSelectedStageId(stages[0].id);
    }

    if (!autoPlay) {
      setActiveStep(stages.length - 1);
      setIsTraversing(false);
      return;
    }

    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step < stages.length) {
        setActiveStep(step);
        // Automatically highlight the stage currently being evaluated
        if (stages[step]) {
          setSelectedStageId(stages[step].id);
        }
      } else {
        setIsTraversing(false);
        // Pick the most interesting deciding stage (the one with the highest contribution or the last one)
        const highestRiskStage = [...stages].sort((a, b) => b.contribution - a.contribution)[0];
        if (highestRiskStage && highestRiskStage.contribution > 0) {
          setSelectedStageId(highestRiskStage.id);
        }
        clearInterval(interval);
      }
    }, 450);

    return () => clearInterval(interval);
  }, [domain, stages, autoPlay]);

  // Compute total and target risk
  const totalStageContribution = stages.reduce((sum, s) => sum + (s.contribution || 0), 0);
  const targetTotal = riskScore !== undefined ? riskScore : totalStageContribution;

  // Compute running accumulated score up to active step
  const rawRunningScore = stages
    .slice(0, activeStep + 1)
    .reduce((sum, s) => sum + (s.contribution || 0), 0);

  // Reconciled score: accumulates across stages and locks to targetTotal at the final step
  const runningScore = (activeStep === stages.length - 1 && targetTotal >= 0)
    ? targetTotal
    : (totalStageContribution > 0
        ? Math.min(rawRunningScore, targetTotal || 100)
        : Math.round((targetTotal * (activeStep + 1)) / Math.max(stages.length, 1)));

  const selectedStage = stages.find((s) => s.id === selectedStageId) || stages[0];

  const getVerdictStyle = (v: "ALLOW" | "FLAG" | "BLOCK") => {
    switch (v) {
      case "ALLOW":
        return {
          badge: "bg-emerald-50 text-emerald-700 border-emerald-200",
          icon: CheckCircle2,
          color: "#059669",
          label: "ALLOW (Clean)"
        };
      case "FLAG":
        return {
          badge: "bg-amber-50 text-amber-700 border-amber-200",
          icon: AlertTriangle,
          color: "#d97706",
          label: "FLAG (Suspicious)"
        };
      case "BLOCK":
        return {
          badge: "bg-rose-50 text-rose-700 border-rose-200",
          icon: XCircle,
          color: "#e11d48",
          label: "BLOCK (Malicious)"
        };
    }
  };

  const currentVerdict = runningScore >= 71 ? "BLOCK" : runningScore >= 41 ? "FLAG" : "ALLOW";
  const finalVerdictStyle = getVerdictStyle(activeStep === stages.length - 1 ? verdict : currentVerdict);
  const VerdictIcon = finalVerdictStyle.icon;

  function handleReplay() {
    setActiveStep(0);
    setIsTraversing(true);
    setSelectedStageId(stages[0]?.id || "redis-cache");
    let step = 0;
    const interval = setInterval(() => {
      step++;
      if (step < stages.length) {
        setActiveStep(step);
        if (stages[step]) setSelectedStageId(stages[step].id);
      } else {
        setIsTraversing(false);
        clearInterval(interval);
      }
    }, 450);
  }

  return (
    <div className={cn("rounded-2xl border border-slate-200 bg-white p-6 shadow-sm", className)}>
      {/* Top Meta Bar */}
      <div className="flex flex-col gap-3 pb-6 sm:flex-row sm:items-center sm:justify-between border-b border-slate-100">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700">
            <Database className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-400">Inspecting Query</span>
              <span className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-mono text-slate-600">UDP/53</span>
              {isTraversing && (
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-800 animate-pulse">
                  Evaluating Stage {activeStep + 1}/7…
                </span>
              )}
            </div>
            <p className="font-mono text-base font-bold text-slate-900">{domain}</p>
          </div>
        </div>

        {/* Live Cumulative Score & Status */}
        <div className="flex items-center gap-4">
          <div className="text-right">
            <span className="font-mono text-[11px] uppercase tracking-wider text-slate-400">Cumulative Risk</span>
            <div className="flex items-baseline gap-1 justify-end font-mono">
              <motion.span 
                key={runningScore}
                initial={{ scale: 1.2 }}
                animate={{ scale: 1 }}
                className={cn(
                  "text-xl font-bold transition-colors duration-300",
                  runningScore >= 71 ? "text-rose-600" : runningScore >= 41 ? "text-amber-600" : "text-emerald-600"
                )}
              >
                {Math.min(runningScore, 100)}
              </motion.span>
              <span className="text-xs text-slate-400">/100</span>
            </div>
          </div>

          <div className={cn(
            "flex items-center gap-2 rounded-xl border px-3.5 py-2 font-mono text-xs font-bold transition-all duration-300",
            finalVerdictStyle.badge
          )}>
            <VerdictIcon className="h-4 w-4 shrink-0" />
            <span>{finalVerdictStyle.label}</span>
          </div>

          <button
            type="button"
            onClick={handleReplay}
            title="Replay Traversal Animation"
            className="p-2 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-600 transition-colors cursor-pointer"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Horizontal / Vertical Pipeline Rail */}
      <div className="relative my-8">
        {/* Rail Background Line */}
        <div className="absolute left-6 right-6 top-6 hidden h-1 -translate-y-1/2 bg-slate-100 md:block rounded-full overflow-hidden">
          <motion.div
            className="h-full bg-emerald-500 rounded-full"
            initial={{ width: "0%" }}
            animate={{ width: `${(activeStep / (stages.length - 1)) * 100}%` }}
            transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
          />
        </div>

        {/* Stage Nodes Grid */}
        <div className="grid grid-cols-1 gap-3 md:grid-cols-7 md:gap-2">
          {stages.map((stage, idx) => {
            const Icon = stage.icon;
            const isCompleted = idx < activeStep;
            const isCurrent = idx === activeStep;
            const isReached = idx <= activeStep;
            const isSelected = stage.id === selectedStageId;
            const hasRisk = stage.contribution > 0;

            return (
              <motion.button
                key={stage.id}
                type="button"
                onClick={() => {
                  setSelectedStageId(stage.id);
                  onStageSelect?.(stage);
                }}
                className={cn(
                  "relative flex flex-col items-center rounded-xl p-3 text-center transition-all text-left md:text-center",
                  "border bg-white hover:border-slate-300 cursor-pointer focus:outline-none focus:ring-2 focus:ring-emerald-500/20",
                  isSelected ? "border-emerald-500 ring-2 ring-emerald-500/20 shadow-sm" : "border-slate-200",
                  isCurrent && "bg-slate-50/80 shadow-xs"
                )}
                whileHover={{ y: -2 }}
                whileTap={{ scale: 0.98 }}
              >
                {/* Node Number & Icon Badge */}
                <div className="relative mb-2 flex items-center justify-center">
                  <div
                    className={cn(
                      "flex h-10 w-10 items-center justify-center rounded-xl border transition-all duration-300",
                      isCurrent && "scale-110 shadow-md",
                      // Only show risk color if the packet has actually reached or passed this stage!
                      isReached && hasRisk
                        ? "border-rose-300 bg-rose-50 text-rose-600"
                        : isCompleted
                        ? "border-emerald-300 bg-emerald-50 text-emerald-600"
                        : isCurrent
                        ? "border-emerald-500 bg-emerald-500 text-white shadow-emerald-500/20"
                        : "border-slate-200 bg-slate-50 text-slate-300"
                    )}
                  >
                    <Icon className="h-4 w-4" />
                  </div>

                  {/* Score Delta Pill — ONLY visible once the evaluation has actually reached this stage! */}
                  <AnimatePresence>
                    {isReached && stage.contribution > 0 && (
                      <motion.span
                        initial={{ opacity: 0, scale: 0.5, y: 5 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="absolute -top-1.5 -right-2 rounded-full bg-rose-600 px-1.5 py-0.2 font-mono text-[10px] font-bold text-white shadow-xs"
                      >
                        +{stage.contribution}
                      </motion.span>
                    )}
                  </AnimatePresence>
                </div>

                {/* Stage Title */}
                <div className="w-full">
                  <div className="flex items-center justify-between md:justify-center gap-1">
                    <span className={cn(
                      "font-mono text-[10px] font-bold uppercase tracking-wider",
                      isReached ? "text-slate-700" : "text-slate-300"
                    )}>
                      S{idx + 1}
                    </span>
                    <span className="font-mono text-[10px] text-slate-400 hidden md:inline">· {stage.latencyMs}ms</span>
                  </div>
                  <p className={cn(
                    "truncate text-xs font-semibold mt-0.5",
                    isReached ? "text-slate-900" : "text-slate-400"
                  )}>
                    {stage.shortName}
                  </p>
                </div>

                {/* Active Pulse Indicator */}
                {isCurrent && (
                  <motion.div
                    className="absolute -bottom-1 h-1 w-6 rounded-full bg-emerald-500"
                    layoutId="activeIndicator"
                  />
                )}
              </motion.button>
            );
          })}
        </div>
      </div>

      {/* Selected Stage Detail Drawer (Explainable XAI Panel) */}
      <AnimatePresence mode="wait">
        <motion.div
          key={selectedStage.id}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.2 }}
          className="rounded-xl border border-slate-100 bg-slate-50/70 p-4"
        >
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-3 border-b border-slate-200/60">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-emerald-600 shrink-0" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-700">
                Stage {stages.findIndex((s) => s.id === selectedStage.id) + 1}: {selectedStage.name}
              </span>
              <span className={cn(
                "rounded-md px-2 py-0.5 font-mono text-[10px] font-semibold uppercase",
                selectedStage.contribution > 0 ? "bg-rose-100 text-rose-700" : "bg-emerald-100 text-emerald-700"
              )}>
                {selectedStage.contribution > 0 ? `Risk Delta +${selectedStage.contribution}` : "Pass (0 Delta)"}
              </span>
            </div>
            <div className="font-mono text-xs text-slate-500">
              Evaluation latency: <span className="font-bold text-slate-800">{selectedStage.latencyMs} ms</span>
            </div>
          </div>

          <p className="mt-3 text-sm text-slate-700 leading-relaxed font-sans">
            <strong className="font-semibold text-slate-900 font-mono text-xs mr-2">VERDICT REASON:</strong>
            {selectedStage.reason}
          </p>

          {/* Structured Key-Value Parameters */}
          {selectedStage.details && (
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4 font-mono text-xs pt-3 border-t border-slate-200/40">
              {Object.entries(selectedStage.details).map(([key, val]) => (
                <div key={key} className="rounded-lg bg-white p-2 border border-slate-200/60 shadow-2xs">
                  <span className="text-[10px] uppercase text-slate-400 block">{key}</span>
                  <span className="font-semibold text-slate-800">{String(val)}</span>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
