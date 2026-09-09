"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { getModelMetadata, getStats } from "@/lib/api";
import type { ModelMetadata, StatsResponse } from "@/lib/types";
import { useInView } from "@/hooks/useInView";
import { TrendingDown, TrendingUp, Minus, Cpu, BrainCircuit, Database } from "lucide-react";

function AnimatedNumber({ target }: { target: number }) {
  const [val, setVal] = useState(0);
  const { ref, inView } = useInView(0.3);

  useEffect(() => {
    if (!inView) return;
    const duration = 900;
    const start = performance.now();
    const raf = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      const ease = 1 - Math.pow(1 - t, 3);
      setVal(Math.round(ease * target));
      if (t < 1) requestAnimationFrame(raf);
    };
    requestAnimationFrame(raf);
  }, [inView, target]);

  return <span ref={ref as React.RefObject<HTMLSpanElement>}>{val.toLocaleString()}</span>;
}

const dnsMetrics = [
  {
    key: "allowed_24h",
    label: "Allowed (24 h)",
    icon: TrendingDown,
    color: "text-trace",
    bg: "bg-emerald-50",
    border: "border-emerald-100",
    iconColor: "text-trace",
  },
  {
    key: "flagged_24h",
    label: "Flagged (24 h)",
    icon: Minus,
    color: "text-amber-600",
    bg: "bg-amber-50",
    border: "border-amber-100",
    iconColor: "text-amber-500",
  },
  {
    key: "blocked_24h",
    label: "Blocked (24 h)",
    icon: TrendingUp,
    color: "text-alert",
    bg: "bg-red-50",
    border: "border-red-100",
    iconColor: "text-alert",
  },
];

export function LiveMetrics() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [model, setModel] = useState<ModelMetadata | null>(null);
  const { ref, inView } = useInView();

  useEffect(() => {
    Promise.all([getStats(), getModelMetadata()])
      .then(([s, m]) => { setStats(s); setModel(m); })
      .catch(() => {});
  }, []);

  if (!stats || !model) return null;

  return (
    <section ref={ref as React.RefObject<HTMLElement>} className="border-b border-line bg-white py-10 md:py-16">
      <div className="mx-auto max-w-[1120px] px-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        >
          <p className="mb-2 font-mono text-[11px] font-medium uppercase tracking-wider text-muted">
            Forecasting telemetry
          </p>
          <h2 className="font-display text-[28px] font-bold tracking-tight text-text md:text-[36px]">
            From observed traffic to a projected attack path.
          </h2>
        </motion.div>

        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <motion.div className="rounded-xl border border-violet-100 bg-violet-50 p-5" initial={{ opacity: 0, y: 24 }} animate={inView ? { opacity: 1, y: 0 } : {}} transition={{ duration: 0.45 }}>
            <div className="mb-3 flex items-center justify-between"><span className="font-mono text-[10px] font-bold uppercase tracking-wider text-muted">State model</span><BrainCircuit className="h-4 w-4 text-violet-500" /></div>
            <p className="font-mono text-3xl font-bold tabular-nums text-violet-600">7 stages</p>
            <p className="mt-1 font-mono text-[10px] text-muted">GRU classification + Markov rollout</p>
          </motion.div>
          <motion.div className="rounded-xl border border-blue-100 bg-blue-50 p-5" initial={{ opacity: 0, y: 24 }} animate={inView ? { opacity: 1, y: 0 } : {}} transition={{ duration: 0.45, delay: 0.1 }}>
            <div className="mb-3 flex items-center justify-between"><span className="font-mono text-[10px] font-bold uppercase tracking-wider text-muted">Calibration corpus</span><Database className="h-4 w-4 text-blue-500" /></div>
            <p className="font-mono text-3xl font-bold tabular-nums text-blue-600">60,273</p>
            <p className="mt-1 font-mono text-[10px] text-muted">CTU-13 observed transitions</p>
          </motion.div>
          {dnsMetrics.slice(0, 2).map((m, i) => {
            const Icon = m.icon;
            const raw = (stats as unknown as Record<string, number>)[m.key] ?? 0;
            return (
              <motion.div
                key={m.label}
                className={`rounded-xl border ${m.border} ${m.bg} p-5`}
                initial={{ opacity: 0, y: 24 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.45, delay: i * 0.1, ease: [0.16, 1, 0.3, 1] }}
                whileHover={{ y: -3, transition: { type: "spring", stiffness: 400, damping: 20 } }}
              >
                <div className="mb-3 flex items-center justify-between">
                  <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-muted">
                    {m.label}
                  </span>
                  <Icon className={`h-4 w-4 ${m.iconColor}`} />
                </div>
                <p className={`font-mono text-3xl font-bold tabular-nums ${m.color}`}>
                  <AnimatedNumber target={raw} />
                </p>
              </motion.div>
            );
          })}

          {/* Secondary model card: DNS pipeline metadata */}
          <motion.div
            className="rounded-xl border border-violet-100 bg-violet-50 p-5"
            initial={{ opacity: 0, y: 24 }}
            animate={inView ? { opacity: 1, y: 0 } : {}}
            transition={{ duration: 0.45, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
            whileHover={{ y: -3, transition: { type: "spring", stiffness: 400, damping: 20 } }}
          >
            <div className="mb-3 flex items-center justify-between">
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider text-muted">
                Weighted F1
              </span>
              <Cpu className="h-4 w-4 text-violet-500" />
            </div>
            <p className="font-mono text-3xl font-bold tabular-nums text-violet-600">
              {(model?.weighted_f1 ?? 0.998).toFixed(3)}
            </p>
            <p className="mt-1 font-mono text-[10px] text-muted">
              holdout n={(model?.holdout_size ?? 50000).toLocaleString()}
            </p>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
