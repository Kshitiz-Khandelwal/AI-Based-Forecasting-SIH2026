"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Brain,
  Database,
  LayoutDashboard,
  FileText,
  Monitor,
  Radio,
  Settings,
  Shield,
  ShieldAlert,
  Zap,
  BookOpen,
  TrendingUp,
  LogOut,
  ArrowRight,
  Globe,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { logout } from "@/lib/auth";

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  badgeColor?: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    label: "MONITORING",
    items: [
      { href: "/app/forecast", label: "AI World Model", icon: TrendingUp, badge: "CORE", badgeColor: "bg-purple-100 text-purple-700 border-purple-200" },
      { href: "/app/dashboard", label: "Overview", icon: LayoutDashboard },
      { href: "/app/queue", label: "Live Traffic", icon: Radio },
      { href: "/app/analytics", label: "Analytics", icon: Activity },
    ],
  },
  {
    label: "DETECTION & ML",
    items: [
      { href: "/app/pipeline", label: "Pipeline Engine", icon: Zap },
      { href: "/app/threats", label: "Threat Intel", icon: Database },
      { href: "/app/xai", label: "XAI Telemetry", icon: Brain },
      { href: "/app/models", label: "Model Rationale", icon: BookOpen },
    ],
  },
  {
    label: "OPERATIONS",
    items: [
      { href: "/app/quarantine", label: "Quarantine Queue", icon: ShieldAlert, badge: "2 ACTIVE", badgeColor: "bg-rose-100 text-rose-700 border-rose-200" },
      { href: "/app/devices", label: "Device Fleet", icon: Monitor },
      { href: "/app/reports", label: "Reports & CERT-In", icon: FileText },
      { href: "/app/settings", label: "Settings", icon: Settings },
    ],
  },
];

export function AppSidebar() {
  const pathname = usePathname();
  const router = useRouter();

  function handleLogout() {
    logout();
    router.push("/login");
  }

  return (
    <aside className="hidden w-[240px] bg-white border-r border-slate-200 flex-col shrink-0 z-30 md:flex h-screen select-none sticky top-0 shadow-2xs">
      {/* Brand Header */}
      <div className="px-6 py-5 flex items-center gap-3 border-b border-slate-100">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-600 text-white shadow-sm shrink-0 font-bold">
          <Shield className="h-4 w-4" />
        </div>
        <div>
          <h1 className="font-bold text-sm text-slate-900 leading-tight tracking-tight font-display">DNS Shield</h1>
          <p className="font-mono text-[10px] text-slate-500">v3.2 · X-Forecast</p>
        </div>
      </div>

      {/* Operational status pill */}
      <div className="px-4 py-3 border-b border-slate-100 space-y-2">
        <Link
          href="/"
          className="flex items-center justify-between gap-2 bg-slate-900 text-white hover:bg-slate-800 rounded-xl px-3 py-2 text-xs font-mono font-semibold transition-all shadow-xs group"
        >
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Public Landing Page</span>
          </span>
          <ArrowRight className="h-3.5 w-3.5 text-slate-400 group-hover:translate-x-0.5 transition-transform" />
        </Link>

        <div className="flex items-center gap-2 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-lg px-2.5 py-1 w-full text-[10px] font-mono font-semibold">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 radar-beacon" />
          <span>NODE: DEL-EDGE-01 (ACTIVE)</span>
        </div>
      </div>

      {/* Nav groups */}
      <nav className="flex-1 px-3 py-4 space-y-5 overflow-y-auto">
        {navGroups.map((group) => (
          <div key={group.label}>
            <p className="px-3 pb-2 text-[9px] font-bold uppercase tracking-widest text-slate-400 font-mono">
              {group.label}
            </p>
            <div className="space-y-1">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = pathname === item.href;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={cn(
                      "flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-xs font-medium transition-all group relative",
                      isActive
                        ? "bg-emerald-50 text-emerald-800 border border-emerald-200 font-bold shadow-2xs"
                        : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                    )}
                  >
                    <Icon className={cn("h-4 w-4 shrink-0 transition-transform group-hover:scale-110", isActive ? "text-emerald-700" : "text-slate-400 group-hover:text-slate-700")} />
                    <span className="flex-1 truncate">{item.label}</span>
                    {item.badge && (
                      <span className={cn("text-[9px] font-mono px-1.5 py-0.5 rounded font-bold border", item.badgeColor || "bg-slate-100 text-slate-600 border-slate-200")}>
                        {item.badge}
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Footer Profile & Logout */}
      <div className="p-3 border-t border-slate-100">
        <button
          onClick={handleLogout}
          className="w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono text-slate-500 hover:bg-rose-50 hover:text-rose-600 transition-all"
        >
          <span className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            <span>OPERATOR</span>
          </span>
          <LogOut className="h-3.5 w-3.5" />
        </button>
      </div>
    </aside>
  );
}
