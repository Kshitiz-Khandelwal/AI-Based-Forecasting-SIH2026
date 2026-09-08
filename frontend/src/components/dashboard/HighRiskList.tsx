"use client";

import React from "react";
import { ShieldAlert, ArrowRight, AlertOctagon } from "lucide-react";
import { VerdictBadge } from "@/components/VerdictBadge";
import type { QueryResult } from "@/lib/types";
import Link from "next/link";
import { cn } from "@/lib/utils";

export function HighRiskList({ events }: { events: QueryResult[] }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-2xs flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between border-b border-slate-100 pb-3 mb-3">
          <div className="flex items-center gap-2">
            <AlertOctagon className="h-4 w-4 text-rose-600" />
            <h3 className="text-xs font-bold text-slate-900 font-sans uppercase tracking-wider">
              Priority Threat Queue
            </h3>
          </div>
          {events.length > 0 && (
            <span className="text-[10px] font-mono text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-200 font-bold">
              {events.length} Pending Review
            </span>
          )}
        </div>

        <div className="divide-y divide-slate-100 font-mono text-xs">
          {events.length === 0 ? (
            <div className="py-6 text-center">
              <p className="text-xs font-semibold text-slate-700">All recent lookups within nominal bounds</p>
              <p className="text-[11px] text-slate-400 font-mono mt-0.5">Zero active zero-day or C2 beacons in current buffer.</p>
            </div>
          ) : (
            events.map((ev) => (
              <div key={ev.id || ev.domain} className="flex items-center justify-between gap-3 py-2.5 hover:bg-slate-50/80 transition-colors">
                <div className="min-w-0 flex-1">
                  <p className="truncate font-bold text-slate-900 text-xs" title={ev.domain}>
                    {ev.domain}
                  </p>
                  <div className="flex items-center gap-2 mt-0.5 text-[10px] text-slate-500">
                    <span>Host: <strong className="text-slate-700">{ev.client_ip || "10.0.0.88"}</strong></span>
                    <span>&bull;</span>
                    <span className="text-rose-600 font-bold">Risk {ev.risk_score}/100</span>
                  </div>
                </div>
                <Link
                  href={`/app/domain/${encodeURIComponent(ev.domain || ev.id)}?id=${encodeURIComponent(ev.id || "ev-highrisk")}&domain=${encodeURIComponent(ev.domain || ev.id)}`}
                  className="rounded border border-slate-200 bg-slate-50 hover:bg-slate-100 px-2 py-1 text-[10px] font-bold text-slate-700 transition"
                >
                  Triage
                </Link>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="mt-3 pt-2.5 border-t border-slate-100 flex items-center justify-between text-[11px]">
        <span className="text-slate-400 font-mono text-[10px]">DHCP Quarantine Integration</span>
        <Link
          href="/app/quarantine"
          className="inline-flex items-center gap-1 font-semibold font-mono text-emerald-700 hover:text-emerald-900 hover:underline"
        >
          <span>Quarantine Queue</span>
          <ArrowRight className="h-3 w-3" />
        </Link>
      </div>
    </div>
  );
}
