"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { ChevronDown, ChevronRight, RefreshCw, Radio, Filter, Search } from "lucide-react";
import { getEndpoint, getEvents, getStats } from "@/lib/api";
import type { QueryResult, StatsResponse } from "@/lib/types";
import { formatTime } from "@/lib/utils";
import { cn } from "@/lib/utils";
import { DomainCell } from "@/components/DomainCell";
import { RiskScore } from "@/components/RiskScore";
import { VerdictBadge } from "@/components/VerdictBadge";
import { PipelineCascade } from "@/components/PipelineCascade";

const POLL_MS = 5000;

export default function QueuePage() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [events, setEvents] = useState<QueryResult[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [endpoint, setEndpoint] = useState("udp://127.0.0.1:53");
  const [filterVerdict, setFilterVerdict] = useState<"ALL" | "ALLOW" | "FLAG" | "BLOCK">("ALL");
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [s, e, cfg] = await Promise.all([getStats(), getEvents(), getEndpoint()]);
      setStats(s);
      setEvents((prev) => {
        let cached: QueryResult[] = [];
        if (typeof window !== "undefined") {
          try {
            const raw = sessionStorage.getItem("dns_shield_tested_queries");
            if (raw) cached = JSON.parse(raw);
          } catch {
            // ignore
          }
        }
        const customItems = [
          ...cached,
          ...prev.filter((item) => item.source === "simulator" || item.id?.startsWith("sim-") || item.id?.startsWith("eval-")),
        ];
        const seen = new Set<string>();
        const uniqueCustom: QueryResult[] = [];
        for (const item of customItems) {
          const key = item.domain || item.id;
          if (!seen.has(key)) {
            seen.add(key);
            uniqueCustom.push(item);
          }
        }
        const serverIds = new Set(e.map((item) => item.domain || item.id));
        const filteredCustom = uniqueCustom.filter((item) => !serverIds.has(item.domain || item.id));
        return [...filteredCustom, ...e];
      });
      setEndpoint(cfg.endpoint);
      setError(null);
    } catch {
      setError("Live stream connection lost. Retrying…");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLL_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  const filteredEvents = events.filter((ev) => {
    if (filterVerdict !== "ALL" && ev.verdict !== filterVerdict) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return ev.domain.toLowerCase().includes(q) || ev.client_ip.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="w-full space-y-6 pb-12">
      {/* Header */}
      <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between border-b border-slate-200 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 md:text-3xl font-sans">
              Live Query Queue
            </h1>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-blue-50 border border-blue-200 px-3 py-1 text-xs font-semibold font-mono text-blue-700">
              <span className="h-1.5 w-1.5 rounded-full bg-blue-500 animate-pulse" />
              Polling {POLL_MS / 1000}s
            </span>
          </div>
          <p className="mt-1.5 text-sm text-slate-600">
            Real-time intercept stream from local UDP/53 and encrypted DNS listeners.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={fetchData}
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-700 transition-all hover:bg-slate-50 hover:border-slate-300 shadow-2xs"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh Stream
          </button>
        </div>
      </div>

      {/* KPI Stats */}
      {stats && (
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block font-mono">
              ALLOWED (24H)
            </span>
            <div className="font-mono text-2xl font-bold text-emerald-700 mt-1">
              {stats.allowed_24h.toLocaleString()}
            </div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block font-mono">
              FLAGGED (24H)
            </span>
            <div className="font-mono text-2xl font-bold text-amber-700 mt-1">
              {stats.flagged_24h.toLocaleString()}
            </div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block font-mono">
              BLOCKED (24H)
            </span>
            <div className="font-mono text-2xl font-bold text-rose-700 mt-1">
              {stats.blocked_24h.toLocaleString()}
            </div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-xs">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 block font-mono">
              OPEN INCIDENTS
            </span>
            <div className="font-mono text-2xl font-bold text-slate-900 mt-1">
              {stats.open_incidents}
            </div>
          </div>
        </div>
      )}

      {/* Table Container */}
      <div className="rounded-xl border border-slate-200 bg-white overflow-hidden shadow-xs">
        {/* Filter Controls Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 border-b border-slate-100 bg-slate-50/50">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-blue-600 shrink-0" />
            <span className="font-mono text-xs font-bold text-slate-800 uppercase tracking-wider">
              Live Query Intercepts
            </span>
            <span className="font-mono text-xs text-slate-400">({filteredEvents.length} events)</span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {/* Search */}
            <div className="relative min-w-[220px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-slate-400 pointer-events-none" />
              <input
                type="text"
                placeholder="Filter domain or client IP…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full h-8 rounded-full border border-slate-200 bg-white pl-8 pr-3 text-xs text-slate-900 placeholder-slate-400 focus:border-blue-500 focus:outline-none shadow-2xs"
              />
            </div>

            {/* Verdict Filter Pills */}
            <div className="flex items-center gap-1">
              {(["ALL", "ALLOW", "FLAG", "BLOCK"] as const).map((v) => (
                <button
                  key={v}
                  onClick={() => setFilterVerdict(v)}
                  className={cn(
                    "px-2.5 py-1 rounded-full text-[10px] font-semibold font-mono border transition-all",
                    filterVerdict === v
                      ? "bg-slate-900 text-white border-slate-900"
                      : "text-slate-500 bg-white border-slate-200 hover:border-slate-300"
                  )}
                >
                  {v}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table Body */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-100 text-slate-400 font-mono bg-slate-50/70">
                <th className="w-8 px-3 py-2.5" />
                <th className="px-3 py-2.5 font-medium">Time</th>
                <th className="px-3 py-2.5 font-medium">Queried Domain</th>
                <th className="px-3 py-2.5 font-medium">Risk Score</th>
                <th className="px-3 py-2.5 font-medium">Verdict</th>
                <th className="px-3 py-2.5 text-right font-medium">Client Source IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredEvents.map((event) => {
                const isOpen = expanded === event.id;
                return (
                  <Fragment key={event.id}>
                    <tr className="hover:bg-slate-50/60 transition-colors">
                      <td className="px-3 py-2.5">
                        <button
                          type="button"
                          onClick={() => setExpanded(isOpen ? null : event.id)}
                          className="text-slate-400 hover:text-slate-700"
                          aria-label={isOpen ? "Collapse row" : "Expand row"}
                        >
                          {isOpen ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                        </button>
                      </td>
                      <td className="px-3 py-2.5 font-mono text-slate-500 whitespace-nowrap">
                        {formatTime(event.timestamp)}
                      </td>
                      <td className="px-3 py-2.5 font-mono font-semibold text-slate-900">
                        <Link href={`/app/domain/${encodeURIComponent(event.domain)}?id=${encodeURIComponent(event.id)}&domain=${encodeURIComponent(event.domain)}`} className="hover:text-blue-600">
                          {event.domain}
                        </Link>
                      </td>
                      <td className="px-3 py-2.5">
                        <RiskScore score={event.risk_score} />
                      </td>
                      <td className="px-3 py-2.5">
                        <VerdictBadge verdict={event.verdict} />
                      </td>
                      <td className="px-3 py-2.5 font-mono text-slate-600 text-right">
                        {event.client_ip}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="bg-slate-50/80 border-b border-slate-200">
                        <td colSpan={6} className="p-4">
                          <PipelineCascade
                            pipeline={event.pipeline}
                            lexicalChars={event.lexical_chars}
                            animate={false}
                            compact
                          />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
