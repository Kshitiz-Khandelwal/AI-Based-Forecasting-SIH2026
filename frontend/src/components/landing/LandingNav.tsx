"use client";
import Link from "next/link";
import { motion } from "framer-motion";
import { Shield } from "lucide-react";

export function LandingNav() {
  return (
    <motion.header
      className="sticky top-0 z-50 border-b border-line bg-white/90 backdrop-blur-md"
      initial={{ opacity: 0, y: -16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
    >
      <div className="mx-auto flex max-w-[1120px] items-center justify-between px-6 py-3.5">
        <Link href="/" className="flex items-center gap-2 group">
          <motion.div
            whileHover={{ rotate: 8, scale: 1.1 }}
            transition={{ type: "spring", stiffness: 400, damping: 15 }}
          >
            <Shield className="h-5 w-5 text-trace" />
          </motion.div>
          <span className="font-display text-base font-bold tracking-tight text-text">
            X-FORECAST
          </span>
        </Link>

        <nav className="flex items-center gap-6">
          {[
            { href: "https://github.com/Kshitiz-Khandelwal/SIH-DNS-wala-proejct", label: "GitHub", external: true },
            { href: "#integration", label: "API Docs", external: false },
          ].map((item, i) => (
            <motion.a
              key={item.label}
              href={item.href}
              target={item.external ? "_blank" : undefined}
              rel={item.external ? "noopener noreferrer" : undefined}
              className="text-sm text-muted transition-colors duration-150 hover:text-text"
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 + i * 0.07, duration: 0.3 }}
            >
              {item.label}
            </motion.a>
          ))}

          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.25, duration: 0.3, type: "spring", stiffness: 300 }}
          >
            <Link
              href="/login"
              className="rounded-lg bg-trace px-4 py-2 text-sm font-medium text-ink transition-all duration-150 hover:bg-emerald-600 hover:shadow-md active:scale-95"
            >
              Forecast Console →
            </Link>
          </motion.div>
        </nav>
      </div>
    </motion.header>
  );
}
