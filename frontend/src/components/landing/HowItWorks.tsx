"use client";

import React, { useState } from "react";
import { motion } from "framer-motion";
import { 
  Database, 
  ShieldAlert, 
  FileCheck2, 
  BrainCircuit, 
  Activity, 
  Globe2, 
  ZapOff, 
  BarChart3,
  Microscope,
  SplitSquareVertical,
  Compass
} from "lucide-react";
import { cn } from "@/lib/utils";
import { RiskWaterfall } from "./RiskWaterfall";
import { DomainMicroscope } from "./DomainMicroscope";
import { VerdictComparison } from "./VerdictComparison";
import { GeoContextStrip } from "./GeoContextStrip";

const PIPELINE_PILLARS = [
  {
    stage: 1,
    title: "Ingest Flow & PCAP Telemetry",
    latency: "Sₜ input",
    badge: "Step 1",
    description: "NetFlow/IPFIX and PCAP-derived flow records form the 16-feature state vector for each observed time step. DNS is one supporting telemetry source.",
    icon: Database,
    accent: "text-emerald-700 bg-emerald-50 border-emerald-200"
  },
  {
    stage: 2,
    title: "Learn Transition Dynamics",
    latency: "GRU",
    badge: "Step 2",
    description: "A trained two-layer GRU reads a 10-step window and estimates the current seven-stage MITRE-aligned attack-state distribution.",
    icon: ShieldAlert,
    accent: "text-rose-700 bg-rose-50 border-rose-200"
  },
  {
    stage: 3,
    title: "Project K Steps Forward",
    latency: "+15–60 min",
    badge: "Step 3",
    description: "A CTU-13-calibrated Markov transition matrix rolls the stage distribution forward at 15, 30, and 60-minute horizons.",
    icon: FileCheck2,
    accent: "text-blue-700 bg-blue-50 border-blue-200"
  },
  {
    stage: 4,
    title: "Map to MITRE ATT&CK",
    latency: "7 stages",
    badge: "Step 4",
    description: "Forecasts are expressed as reconnaissance, initial access, discovery, C2, lateral movement, and exfiltration/impact stages for SOC action.",
    icon: BrainCircuit,
    accent: "text-purple-700 bg-purple-50 border-purple-200"
  },
  {
    stage: 5,
    title: "Explain & Respond",
    latency: "Attribution",
    badge: "Step 5",
    description: "Perturbation-based feature attribution shows which observed flow signals changed the forecast; response and DNS controls can then support containment.",
    icon: Activity,
    accent: "text-amber-700 bg-amber-50 border-amber-200"
  },
  {
    stage: 6,
    title: "Supporting DNS Defense",
    latency: "Secondary",
    badge: "Ingestion & response",
    description: "The existing DNS filtering pipeline supplies additional telemetry and can enforce a response, but it is not the forecasting model’s primary claim.",
    icon: ZapOff,
    accent: "text-slate-700 bg-slate-100 border-slate-300"
  }
];

export function HowItWorks() {
  const [activeInteractiveTab, setActiveInteractiveTab] = useState<"waterfall" | "microscope" | "comparison" | "geo">("waterfall");

  return (
    <section className="border-b border-slate-200 bg-slate-50/60 py-16 md:py-24">
      <div className="mx-auto max-w-[1160px] px-6">
        
        {/* Section Header */}
        <div className="max-w-2xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 font-mono text-[11px] font-bold uppercase tracking-wider text-slate-500 mb-3 shadow-2xs">
            Forecasting Architecture
          </div>
          <h2 className="font-display text-3xl font-extrabold tracking-tight text-slate-900 md:text-4xl">
            Observe the present. <span className="text-emerald-600">Forecast the next attack state.</span>
          </h2>
          <p className="mt-3 text-base text-slate-600 font-sans leading-relaxed">
            The core path learns network-state transitions from temporal telemetry, then makes an auditable
            multi-horizon forecast. DNS filtering remains visible below as a supporting capability.
          </p>
        </div>

        {/* 6 Grid Architecture Cards */}
        <div className="mt-10 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {PIPELINE_PILLARS.map((pillar) => {
            const Icon = pillar.icon;
            return (
              <div
                key={pillar.title}
                className="rounded-2xl border border-slate-200 bg-white p-5 shadow-2xs hover:border-slate-300 transition-all"
              >
                <div className="flex items-center justify-between gap-2 pb-3 border-b border-slate-100">
                  <div className={cn("flex h-8 w-8 items-center justify-center rounded-lg border", pillar.accent)}>
                    <Icon className="h-4 w-4" />
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-slate-100 px-2 py-0.5 font-mono text-[10px] font-bold text-slate-600 border border-slate-200">
                      {pillar.badge}
                    </span>
                    <span className="font-mono text-[11px] font-semibold text-emerald-700">
                      {pillar.latency}
                    </span>
                  </div>
                </div>

                <h3 className="font-display text-base font-bold text-slate-900 mt-3">
                  {pillar.title}
                </h3>
                <p className="mt-2 text-xs leading-relaxed text-slate-600 font-sans">
                  {pillar.description}
                </p>
              </div>
            );
          })}
        </div>

        {/* Interactive Lab Tabs */}
        <div className="mt-16 pt-12 border-t border-slate-200">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
            <div>
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-400">Interactive Forensic Lab</span>
              <h3 className="text-2xl font-bold text-slate-900 mt-1">Explore Detection Primitives Live</h3>
            </div>

            {/* Tab Buttons */}
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => setActiveInteractiveTab("waterfall")}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-xl px-3.5 py-2 font-mono text-xs font-bold transition-all cursor-pointer border",
                  activeInteractiveTab === "waterfall"
                    ? "bg-slate-900 text-white border-slate-900 shadow-xs"
                    : "bg-white text-slate-600 border-slate-200 hover:bg-slate-100"
                )}
              >
                <BarChart3 className="h-3.5 w-3.5" /> Risk Waterfall (#5)
              </button>

              <button
                type="button"
                onClick={() => setActiveInteractiveTab("microscope")}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-xl px-3.5 py-2 font-mono text-xs font-bold transition-all cursor-pointer border",
                  activeInteractiveTab === "microscope"
                    ? "bg-slate-900 text-white border-slate-900 shadow-xs"
                    : "bg-white text-slate-600 border-slate-200 hover:bg-slate-100"
                )}
              >
                <Microscope className="h-3.5 w-3.5" /> String Microscope (#6)
              </button>

              <button
                type="button"
                onClick={() => setActiveInteractiveTab("comparison")}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-xl px-3.5 py-2 font-mono text-xs font-bold transition-all cursor-pointer border",
                  activeInteractiveTab === "comparison"
                    ? "bg-slate-900 text-white border-slate-900 shadow-xs"
                    : "bg-white text-slate-600 border-slate-200 hover:bg-slate-100"
                )}
              >
                <SplitSquareVertical className="h-3.5 w-3.5" /> Dual-Lane Trace (#11)
              </button>

              <button
                type="button"
                onClick={() => setActiveInteractiveTab("geo")}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-xl px-3.5 py-2 font-mono text-xs font-bold transition-all cursor-pointer border",
                  activeInteractiveTab === "geo"
                    ? "bg-slate-900 text-white border-slate-900 shadow-xs"
                    : "bg-white text-slate-600 border-slate-200 hover:bg-slate-100"
                )}
              >
                <Compass className="h-3.5 w-3.5" /> Geo / ASN Context (#12)
              </button>
            </div>
          </div>

          {/* Active Lab Component */}
          {activeInteractiveTab === "waterfall" && <RiskWaterfall />}
          {activeInteractiveTab === "microscope" && <DomainMicroscope />}
          {activeInteractiveTab === "comparison" && <VerdictComparison />}
          {activeInteractiveTab === "geo" && <GeoContextStrip />}
        </div>

      </div>
    </section>
  );
}
