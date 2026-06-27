"use client";

import Link from "next/link";
import { useQuery } from "convex/react";
import { motion } from "framer-motion";
import { signOut, useSession } from "next-auth/react";
import { ArrowLeft, ShieldAlert, ShieldCheck, ScanSearch, Sparkles, Link2, Activity, Moon, Sun } from "lucide-react";
import { api } from "@/convex/_generated/api";
import { useOwnerAuth } from "@/lib/useOwnerAuth";
import { useAppearance, useTheme, THEMES } from "@/lib/useTheme";
import { AuthRequired } from "@/components/AuthRequired";

const VERDICT_COLOR: Record<string, string> = {
  safe: "var(--accent)",
  suspicious: "#f5a623",
  scam: "#ef4060",
};

function ThemeSwitcher() {
  const [theme, setTheme] = useTheme();
  const [appearance, setAppearance] = useAppearance();
  return (
    <div className="flex items-center gap-2">
      {THEMES.map((t) => (
        <button
          key={t.id}
          onClick={() => setTheme(t.id)}
          aria-label={t.label}
          title={t.label}
          aria-pressed={theme === t.id}
          className={`hidden h-4 w-4 rounded-full border transition-transform hover:scale-110 sm:block ${
            theme === t.id ? "border-[var(--text-primary)]" : "border-transparent"
          }`}
          style={{
            backgroundColor: t.swatch,
            boxShadow: theme === t.id ? `0 0 0 2px var(--ink), 0 0 0 3px ${t.swatch}` : undefined,
          }}
        />
      ))}
      <button
        onClick={() => setAppearance(appearance === "dark" ? "light" : "dark")}
        aria-label={`Switch to ${appearance === "dark" ? "light" : "dark"} mode`}
        className="flex h-9 items-center gap-2 rounded-md border-[1.5px] border-[var(--line-strong)] bg-[var(--input)] px-2.5 text-[10px] font-bold uppercase text-zinc-300"
      >
        {appearance === "dark" ? <Sun className="h-3.5 w-3.5 text-[var(--warn)]" /> : <Moon className="h-3.5 w-3.5 text-[var(--info)]" />}
        {appearance === "dark" ? "Light" : "Dark"}
      </button>
    </div>
  );
}

function StatTile({
  label,
  value,
  sub,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>;
  accent?: string;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
      className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-4 py-3.5"
      style={{ boxShadow: "3px 3px 0 0 #00000060" }}
    >
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-500">{label}</span>
        <Icon className="h-3.5 w-3.5" style={{ color: accent ?? "var(--accent)" }} />
      </div>
      <span className="font-mono text-3xl font-bold tabular-nums tracking-tight text-zinc-50">{value}</span>
      {sub && <span className="text-[10px] text-zinc-600">{sub}</span>}
    </motion.div>
  );
}

export default function ProfilePage() {
  useTheme(); // apply persisted accent on this route too
  const { data: session, status } = useSession();
  const ownerAuth = useOwnerAuth();
  const ownerId = ownerAuth.ownerId;
  const a = useQuery(api.scanResults.analyticsForOwner, ownerAuth.args ?? "skip");

  const total = a?.total ?? 0;
  const maxVerdict = a ? Math.max(1, a.byVerdict.safe, a.byVerdict.suspicious, a.byVerdict.scam) : 1;

  if (status === "loading") {
    return (
      <main className="min-h-screen bg-[var(--ink)] px-5 py-10 text-zinc-500">
        <div className="mx-auto max-w-5xl text-sm">Loading secure session...</div>
      </main>
    );
  }

  if (!ownerId) {
    return <AuthRequired title="Sign in to view analytics" />;
  }

  return (
    <div className="bg-dot-grid min-h-screen w-full text-zinc-300">
      <header className="relative z-10 flex items-center justify-between border-b-[1.5px] border-[var(--line)] bg-[var(--panel)] px-5 py-3.5">
        <div className="flex items-center gap-3">
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 rounded-md border-[1.5px] border-[var(--line-strong)] bg-[var(--ink)] px-2.5 py-1.5 text-[11px] font-bold text-zinc-300 transition-transform hover:-translate-y-0.5 hover:border-[var(--accent)]"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Dashboard
          </Link>
          <div>
            <h1 className="text-[17px] tracking-tight text-zinc-50">
              <span className="font-bold">Ghost</span>
              <span className="font-light text-zinc-400">Filter</span>
              <span className="ml-1 align-top text-[10px] font-bold text-[var(--accent)]">AI</span>
            </h1>
            <p className="text-[11px] text-zinc-500">Your protection analytics</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <ThemeSwitcher />
          <button
            onClick={() => void signOut({ callbackUrl: "/" })}
            title={session?.user?.email ?? "Signed in"}
            className="flex h-9 items-center rounded-md border border-[var(--line-strong)] bg-[var(--input)] px-3 text-[11px] font-semibold text-zinc-400 hover:border-[var(--danger)] hover:text-[var(--danger)]"
          >
            Sign out
          </button>
        </div>
      </header>

      <main className="relative z-10 mx-auto max-w-5xl px-5 py-6">
        {total === 0 ? (
          <div className="flex min-h-[50vh] flex-col items-center justify-center gap-2 text-center">
            <ScanSearch className="h-7 w-7 text-zinc-700" />
            <p className="text-sm text-zinc-500">No scans yet.</p>
            <Link href="/dashboard" className="text-[12px] font-bold text-[var(--accent-bright)] hover:underline">
              Go analyze your first message →
            </Link>
          </div>
        ) : (
          <div className="flex flex-col gap-5">
            {/* Stat tiles */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <StatTile label="Total Scans" value={total} icon={Activity} sub="messages analyzed" />
              <StatTile
                label="Threats Caught"
                value={(a?.byVerdict.scam ?? 0) + (a?.byVerdict.suspicious ?? 0)}
                icon={ShieldAlert}
                accent="#ef4060"
                sub={`${a?.byVerdict.scam ?? 0} scams · ${a?.byVerdict.suspicious ?? 0} suspicious`}
              />
              <StatTile label="AI Deep-Reviews" value={a?.aiReviewed ?? 0} icon={Sparkles} sub="escalated to Gemini" />
              <StatTile
                label="Links Checked"
                value={a?.linkChecks ?? 0}
                icon={Link2}
                sub={`${a?.flaggedLinks ?? 0} flagged by threat intel`}
              />
            </div>

            <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
              {/* Verdict distribution */}
              <div className="rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-4 py-4">
                <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-500">
                  Verdict Distribution
                </span>
                <div className="mt-3 flex flex-col gap-3">
                  {(["scam", "suspicious", "safe"] as const).map((vk) => {
                    const count = a?.byVerdict[vk] ?? 0;
                    return (
                      <div key={vk}>
                        <div className="mb-1 flex items-center justify-between text-[11px]">
                          <span className="font-bold uppercase tracking-wide" style={{ color: VERDICT_COLOR[vk] }}>
                            {vk}
                          </span>
                          <span className="font-mono text-zinc-400">{count}</span>
                        </div>
                        <div className="h-2 overflow-hidden rounded-sm border border-[var(--line)] bg-[var(--input)]">
                          <motion.div
                            className="h-full rounded-sm"
                            style={{ backgroundColor: VERDICT_COLOR[vk] }}
                            initial={{ width: 0 }}
                            animate={{ width: `${(count / maxVerdict) * 100}%` }}
                            transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
                <p className="mt-3 text-[10px] text-zinc-600">
                  Average analysis confidence:{" "}
                  <span className="font-mono text-zinc-400">{a?.avgConfidence ?? 0}%</span>
                </p>
              </div>

              {/* Top signals */}
              <div className="rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-4 py-4">
                <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-500">
                  Most Common Threat Signals
                </span>
                <div className="mt-3 flex flex-col gap-2.5">
                  {a?.topSignals.slice(0, 6).map((s) => {
                    const color = s.avg >= 70 ? "#ef4060" : s.avg >= 35 ? "#f5a623" : "var(--accent)";
                    return (
                      <div key={s.label}>
                        <div className="mb-1 flex items-center justify-between text-[11px]">
                          <span className="text-zinc-400">{s.label}</span>
                          <span className="font-mono text-zinc-500">{Math.round(s.avg)}%</span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-sm bg-[var(--input)]">
                          <motion.div
                            className="h-full"
                            style={{ backgroundColor: color }}
                            initial={{ width: 0 }}
                            animate={{ width: `${Math.min(100, s.avg)}%` }}
                            transition={{ duration: 0.6 }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* By source + recent */}
            <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
              <div className="rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-4 py-4">
                <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-500">By Source</span>
                <div className="mt-3 flex flex-col gap-2">
                  {Object.entries(a?.bySource ?? {}).map(([src, n]) => (
                    <div key={src} className="flex items-center justify-between text-[12px]">
                      <span className="capitalize text-zinc-400">{src}</span>
                      <span className="font-mono font-bold text-zinc-200">{n}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-4 py-4">
                <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-500">
                  Recent Activity
                </span>
                <div className="mt-3 flex flex-col gap-1.5">
                  {a?.recent.map((r) => (
                    <div key={r._id} className="flex items-start gap-2 text-[11px]">
                      <span
                        className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full"
                        style={{ backgroundColor: VERDICT_COLOR[r.verdict] }}
                      />
                      <span className="truncate font-mono text-zinc-400">{r.subject || r.snippet}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-2 px-1 text-[10px] text-zinc-600">
              <ShieldCheck className="h-3 w-3" />
              Analytics are computed from your most recent 500 scans, stored under your authenticated GhostFilter session.
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
