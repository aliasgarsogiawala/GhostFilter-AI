"use client";

import { useEffect, useRef, useState } from "react";
import { useAction, useMutation, useQuery } from "convex/react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Mail,
  Code2,
  MessageSquare,
  Cloud,
  Plug,
  Unlink,
  Scan,
  Inbox,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  Sparkles,
  LoaderCircle,
  ChevronRight,
  Crosshair,
} from "lucide-react";
import { api } from "@/convex/_generated/api";
import { useOwnerId } from "@/lib/useOwnerId";
import { buildHighlightSegments } from "@/lib/highlight";

type Verdict = "safe" | "suspicious" | "scam";
type Tone = "clear" | "warn" | "critical";

interface ScanResultDoc {
  _id: string;
  _creationTime: number;
  provider: "gmail" | "github" | "manual";
  subject?: string;
  snippet: string;
  verdict: Verdict;
  mlScore: number;
  confidence: number;
  summary: string;
  recommendation: string;
  flaggedPhrases: { phrase: string; reason: string; severity: "amber" | "red" }[];
  signals: { label: string; value: number }[];
  aiReviewed: boolean;
}

function verdictTone(verdict: Verdict): Tone {
  if (verdict === "scam") return "critical";
  if (verdict === "suspicious") return "warn";
  return "clear";
}

function scamLikelihood(result: ScanResultDoc): number {
  return result.verdict === "safe" ? Math.max(0, 100 - result.confidence) : result.confidence;
}

const TONE_DOT: Record<Tone, string> = {
  clear: "bg-zinc-500",
  warn: "bg-amber-500",
  critical: "bg-red-500",
};

const TONE_TEXT: Record<Tone, string> = {
  clear: "text-zinc-300",
  warn: "text-amber-400",
  critical: "text-red-400",
};

const EXAMPLES = [
  {
    label: "Fake account suspension",
    text: "URGENT! Your Apple ID has been suspended. Verify your account immediately at http://apple-id-secure-verify.com or it will be permanently locked. Enter your password to confirm.",
  },
  {
    label: "Fake delivery fee",
    text: "USPS: Your package could not be delivered due to an unpaid customs fee of $2.99. Pay now to reschedule delivery: http://usps-redeliver.info/track",
  },
  {
    label: "Fake prize/lottery",
    text: "CONGRATULATIONS! You've been selected to receive a $750 Walmart gift card. Claim your prize now before it expires: bit.ly/claim-prize-750",
  },
  {
    label: "A normal text",
    text: "Hey! Are we still on for lunch tomorrow at noon? Let me know if that still works for you.",
  },
];

const PROVIDERS = [
  { id: "gmail", label: "Gmail", icon: Mail, live: true },
  { id: "outlook", label: "Outlook", icon: Mail, live: false },
  { id: "github", label: "GitHub", icon: Code2, live: false },
  { id: "slack", label: "Slack", icon: MessageSquare, live: false },
  { id: "drive", label: "Google Drive", icon: Cloud, live: false },
] as const;

// ----------------------------------------------------------------------------
// Threat gauge (270° arc instrument), reused styling from the v1 prototype
// ----------------------------------------------------------------------------

function useAnimatedNumber(target: number, durationMs = 700) {
  const [value, setValue] = useState(target);
  const fromRef = useRef(target);
  const startRef = useRef<number | null>(null);

  useEffect(() => {
    const from = fromRef.current;
    const to = target;
    let raf = 0;
    startRef.current = null;
    const step = (t: number) => {
      if (startRef.current === null) startRef.current = t;
      const elapsed = t - startRef.current;
      const p = Math.min(1, elapsed / durationMs);
      const eased = 1 - Math.pow(1 - p, 3);
      setValue(from + (to - from) * eased);
      if (p < 1) raf = requestAnimationFrame(step);
      else fromRef.current = to;
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, durationMs]);

  return value;
}

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
  const a = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
}

function describeArc(cx: number, cy: number, r: number, startAngle: number, endAngle: number) {
  const start = polarToCartesian(cx, cy, r, endAngle);
  const end = polarToCartesian(cx, cy, r, startAngle);
  const largeArcFlag = endAngle - startAngle <= 180 ? "0" : "1";
  return ["M", start.x, start.y, "A", r, r, 0, largeArcFlag, 0, end.x, end.y].join(" ");
}

const GAUGE_START = -135;
const GAUGE_END = 135;
const GAUGE_SWEEP = GAUGE_END - GAUGE_START;

function ThreatGauge({ value, tone }: { value: number; tone: Tone }) {
  const animated = useAnimatedNumber(value, 900);
  const cx = 120;
  const cy = 116;
  const r = 92;

  const track = describeArc(cx, cy, r, GAUGE_START, GAUGE_END);
  const needleAngle = GAUGE_START + (Math.min(100, animated) / 100) * GAUGE_SWEEP;
  const toneColor = tone === "critical" ? "#ef4444" : tone === "warn" ? "#f59e0b" : "#e4e4e7";

  return (
    <div className="relative flex flex-col items-center">
      <svg viewBox="0 0 240 170" className="w-full max-w-[260px]">
        <path d={track} fill="none" stroke="#ffffff0d" strokeWidth={10} strokeLinecap="round" />
        <path
          d={describeArc(cx, cy, r, GAUGE_START, needleAngle)}
          fill="none"
          stroke={toneColor}
          strokeWidth={10}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${toneColor}55)` }}
        />
        <circle cx={cx} cy={cy} r={3} fill="#52525b" />
      </svg>
      <div className="absolute top-[56%] flex flex-col items-center">
        <span
          className="font-mono text-3xl font-semibold tabular-nums tracking-tight"
          style={{ color: toneColor }}
        >
          {animated.toFixed(1)}
          <span className="text-base text-zinc-500">%</span>
        </span>
        <span className="mt-1 text-[10px] font-medium uppercase tracking-[0.2em] text-zinc-500">
          Scam Likelihood
        </span>
      </div>
    </div>
  );
}

function SignalBar({ label, value }: { label: string; value: number }) {
  const barColor = value >= 70 ? "bg-red-500" : value >= 35 ? "bg-amber-500" : "bg-zinc-500";
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between text-[11px]">
        <span className="text-zinc-400">{label}</span>
        <span className="font-mono text-zinc-300">{Math.round(value)}%</span>
      </div>
      <div className="h-1 w-full overflow-hidden rounded-full bg-white/[0.06]">
        <motion.div
          className={`h-full rounded-full ${barColor}`}
          initial={false}
          animate={{ width: `${Math.min(100, Math.max(0, value))}%` }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        />
      </div>
    </div>
  );
}

function SectionLabel({
  icon: Icon,
  children,
  trailing,
}: {
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  trailing?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-3">
      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 text-zinc-500" />
        <span className="text-[11px] font-semibold uppercase tracking-[0.18em] text-zinc-400">
          {children}
        </span>
      </div>
      {trailing}
    </div>
  );
}

// ----------------------------------------------------------------------------
// Main dashboard
// ----------------------------------------------------------------------------

export default function GhostFilterDashboard() {
  const ownerId = useOwnerId();
  const connections = useQuery(api.connections.listForOwner, ownerId ? { ownerId } : "skip");
  const scans = useQuery(api.scanResults.listForOwner, ownerId ? { ownerId } : "skip") as
    | ScanResultDoc[]
    | undefined;

  const analyzeMessage = useAction(api.pipeline.analyzeMessage);
  const scanInbox = useAction(api.gmail.scanInbox);
  const disconnect = useMutation(api.connections.disconnect);

  const [messageText, setMessageText] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [banner] = useState<"success" | "error" | null>(() => {
    if (typeof window === "undefined") return null;
    const connect = new URLSearchParams(window.location.search).get("connect");
    return connect === "success" || connect === "error" ? connect : null;
  });

  useEffect(() => {
    if (banner) window.history.replaceState({}, "", window.location.pathname);
  }, [banner]);

  const gmailConnection = connections?.find((c) => c.provider === "gmail" && c.status === "connected");
  const selected = scans?.find((s) => s._id === selectedId) ?? scans?.[0];

  const handleAnalyze = async () => {
    if (!ownerId || !messageText.trim() || analyzing) return;
    setAnalyzing(true);
    try {
      const result = await analyzeMessage({ text: messageText, ownerId });
      setSelectedId(result.id);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleScanNow = async () => {
    if (!ownerId || scanning) return;
    setScanning(true);
    setScanError(null);
    try {
      await scanInbox({ ownerId });
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const handleDisconnect = async () => {
    if (!ownerId || !gmailConnection) return;
    await disconnect({ connectionId: gmailConnection._id as never, ownerId });
  };

  const tone = selected ? verdictTone(selected.verdict) : "clear";
  const gaugeValue = selected ? scamLikelihood(selected) : 0;
  const statusColors =
    tone === "critical"
      ? { text: "text-red-400", dot: "bg-red-500" }
      : tone === "warn"
      ? { text: "text-amber-400", dot: "bg-amber-500" }
      : { text: "text-zinc-200", dot: "bg-zinc-400" };

  const segments = selected ? buildHighlightSegments(selected.snippet, selected.flaggedPhrases) : [];

  return (
    <div className="min-h-screen w-full bg-[#090a0c] text-zinc-300">
      <div className="pointer-events-none fixed inset-0 bg-[radial-gradient(ellipse_at_top,_rgba(255,255,255,0.04),_transparent_55%)]" />

      <header className="relative z-10 flex flex-col gap-2 border-b border-white/[0.06] bg-[#0b0c0f]/80 px-5 py-3.5 backdrop-blur sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-md border border-white/[0.08] bg-white/[0.03]">
            <Crosshair className="h-4 w-4 text-zinc-300" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold tracking-[0.08em] text-zinc-100">
                GHOSTFILTER AI
              </h1>
              <span className="rounded border border-white/[0.08] px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wider text-zinc-500">
                Scam &amp; Phishing Shield
              </span>
            </div>
            <p className="text-[11px] text-zinc-500">
              Read-only access · we never send, delete, or modify your messages.
            </p>
          </div>
        </div>
        <AnimatePresence>
          {banner && (
            <motion.div
              initial={{ opacity: 0, y: -6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className={`rounded-md border px-3 py-1.5 text-[11px] ${
                banner === "success"
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                  : "border-red-500/30 bg-red-500/10 text-red-300"
              }`}
            >
              {banner === "success" ? "Gmail connected successfully." : "Connection failed — please try again."}
            </motion.div>
          )}
        </AnimatePresence>
      </header>

      <main className="relative z-10 grid grid-cols-1 lg:grid-cols-12">
        {/* ZONE A — Recent Scans */}
        <section className="order-2 col-span-1 flex h-[360px] flex-col border-b border-white/[0.06] lg:order-1 lg:col-span-3 lg:h-[calc(100vh-65px)] lg:border-b-0 lg:border-r">
          <SectionLabel
            icon={Inbox}
            trailing={
              <span className="text-[10px] text-zinc-500">{scans?.length ?? 0} scanned</span>
            }
          >
            Recent Scans
          </SectionLabel>
          <div className="flex-1 overflow-y-auto px-2 py-2">
            {!scans?.length && (
              <p className="px-2 py-4 text-[11px] text-zinc-600">
                No scans yet — analyze a message or connect Gmail to get started.
              </p>
            )}
            <AnimatePresence initial={false}>
              {scans?.map((s) => {
                const t = verdictTone(s.verdict);
                return (
                  <motion.button
                    key={s._id}
                    layout
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    onClick={() => setSelectedId(s._id)}
                    className={`mb-1 flex w-full items-start gap-2 rounded px-2 py-1.5 text-left text-[11px] hover:bg-white/[0.04] ${
                      selected?._id === s._id ? "bg-white/[0.06]" : ""
                    }`}
                  >
                    <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${TONE_DOT[t]}`} />
                    <div className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate font-mono text-zinc-300">
                        {s.subject || s.snippet}
                      </span>
                      <span className="font-mono text-[10px] text-zinc-600">
                        {s.provider} · {new Date(s._creationTime).toLocaleTimeString()}
                      </span>
                    </div>
                    <span className={`shrink-0 font-mono text-[10px] ${TONE_TEXT[t]}`}>
                      {s.verdict.toUpperCase()}
                    </span>
                  </motion.button>
                );
              })}
            </AnimatePresence>
          </div>
        </section>

        {/* ZONE B — Analyzer */}
        <section className="order-1 col-span-1 flex flex-col border-b border-white/[0.06] lg:order-2 lg:col-span-6 lg:h-[calc(100vh-65px)] lg:border-b-0 lg:border-r lg:overflow-y-auto">
          <SectionLabel icon={Plug}>Connect Accounts</SectionLabel>
          <div className="flex flex-wrap gap-2 border-b border-white/[0.06] px-5 py-4">
            {PROVIDERS.map((p) => {
              const Icon = p.icon;
              if (p.id === "gmail" && gmailConnection) {
                return (
                  <div
                    key={p.id}
                    className="flex items-center gap-2 rounded-md border border-emerald-500/30 bg-emerald-500/[0.08] px-3 py-2 text-[11px] text-emerald-300"
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span className="font-medium">{gmailConnection.accountEmail ?? "Gmail connected"}</span>
                    <button
                      onClick={handleScanNow}
                      disabled={scanning}
                      className="ml-2 flex items-center gap-1 rounded border border-emerald-500/30 px-1.5 py-0.5 text-[10px] uppercase tracking-wide hover:bg-emerald-500/10 disabled:opacity-50"
                    >
                      {scanning ? <LoaderCircle className="h-3 w-3 animate-spin" /> : <Scan className="h-3 w-3" />}
                      Scan Now
                    </button>
                    <button
                      onClick={handleDisconnect}
                      className="ml-1 flex items-center gap-1 rounded border border-white/[0.1] px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-zinc-400 hover:bg-white/[0.06]"
                    >
                      <Unlink className="h-3 w-3" />
                      Disconnect
                    </button>
                  </div>
                );
              }
              if (p.id === "gmail" && ownerId) {
                return (
                  <a
                    key={p.id}
                    href={`/api/auth/google?ownerId=${ownerId}`}
                    className="flex items-center gap-2 rounded-md border border-white/[0.1] bg-white/[0.03] px-3 py-2 text-[11px] text-zinc-300 hover:border-white/[0.2] hover:bg-white/[0.06]"
                  >
                    <Icon className="h-3.5 w-3.5" />
                    Connect {p.label}
                  </a>
                );
              }
              return (
                <div
                  key={p.id}
                  className="flex cursor-not-allowed items-center gap-2 rounded-md border border-white/[0.04] bg-white/[0.01] px-3 py-2 text-[11px] text-zinc-600"
                >
                  <Icon className="h-3.5 w-3.5" />
                  {p.label}
                  <span className="text-[9px] uppercase tracking-wide text-zinc-700">Soon</span>
                </div>
              );
            })}
          </div>
          {scanError && (
            <p className="border-b border-white/[0.06] px-5 py-2 text-[11px] text-red-400">{scanError}</p>
          )}

          <SectionLabel icon={Sparkles}>Paste a Message to Analyze</SectionLabel>
          <div className="flex flex-col gap-2.5 border-b border-white/[0.06] px-5 py-4">
            <textarea
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              placeholder="Paste a suspicious email, text message, or DM here..."
              rows={4}
              className="w-full resize-none rounded-md border border-white/[0.08] bg-[#0c0d11] px-3 py-2.5 text-[13px] text-zinc-200 placeholder:text-zinc-600 focus:border-white/[0.2] focus:outline-none"
            />
            <div className="flex flex-wrap items-center gap-1.5">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.label}
                  onClick={() => setMessageText(ex.text)}
                  className="rounded-full border border-white/[0.08] px-2.5 py-1 text-[10px] text-zinc-500 hover:border-white/[0.16] hover:text-zinc-300"
                >
                  {ex.label}
                </button>
              ))}
              <button
                onClick={handleAnalyze}
                disabled={!messageText.trim() || analyzing}
                className="ml-auto flex items-center gap-1.5 rounded-md border border-zinc-200/20 bg-white/[0.08] px-3 py-1.5 text-[11px] font-medium text-zinc-100 hover:bg-white/[0.14] disabled:opacity-40"
              >
                {analyzing ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
                Analyze
              </button>
            </div>
          </div>

          <div className="flex flex-col items-center border-b border-white/[0.06] px-6 py-6">
            <ThreatGauge value={gaugeValue} tone={tone} />
          </div>

          <div className="flex flex-1 flex-col px-5 py-4">
            <span className="pb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
              Analyzed Message
            </span>
            <div className="min-h-[120px] rounded-md border border-white/[0.06] bg-[#0c0d11] p-4 font-mono text-[12.5px] leading-[1.8] text-zinc-400">
              {selected ? (
                <p className="whitespace-pre-wrap">
                  {segments.map((seg, i) => (
                    <span
                      key={i}
                      className={
                        seg.severity === "red"
                          ? "rounded bg-red-500/[0.15] text-red-300"
                          : seg.severity === "amber"
                          ? "rounded bg-amber-500/[0.15] text-amber-300"
                          : ""
                      }
                    >
                      {seg.text}
                    </span>
                  ))}
                </p>
              ) : (
                <p className="text-zinc-600">No message analyzed yet.</p>
              )}
            </div>
          </div>
        </section>

        {/* ZONE C — Result detail */}
        <section className="order-3 col-span-1 flex flex-col lg:col-span-3 lg:h-[calc(100vh-65px)] lg:overflow-y-auto">
          <SectionLabel icon={ShieldAlert}>Verdict</SectionLabel>
          <div className="flex flex-col gap-4 px-4 py-4">
            <div
              className={`rounded-lg border bg-white/[0.02] px-4 py-4 ${
                tone === "critical" ? "border-red-500/30" : "border-white/[0.06]"
              }`}
            >
              <div className="flex items-center gap-2">
                {tone === "clear" ? (
                  <ShieldCheck className="h-4 w-4 text-zinc-400" />
                ) : (
                  <ShieldAlert className={`h-4 w-4 ${statusColors.text}`} />
                )}
                <span className="text-[10px] uppercase tracking-[0.2em] text-zinc-500">Verdict</span>
              </div>
              <div className={`mt-1.5 flex items-center gap-2 text-lg font-bold tracking-tight ${statusColors.text}`}>
                <span className={`h-2 w-2 rounded-full ${statusColors.dot}`} />
                {selected ? selected.verdict.toUpperCase() : "—"}
              </div>
              {selected && <p className="mt-2 text-[11px] leading-relaxed text-zinc-400">{selected.summary}</p>}
            </div>

            {selected && (
              <div className="rounded-lg border border-white/[0.06] bg-white/[0.02] px-3.5 py-3.5">
                <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                  What to do
                </span>
                <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-300">{selected.recommendation}</p>
              </div>
            )}

            <div className="flex flex-col gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3.5 py-3.5">
              <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                Signal Breakdown
              </span>
              {selected ? (
                selected.signals.map((s) => <SignalBar key={s.label} label={s.label} value={s.value} />)
              ) : (
                <p className="text-[11px] text-zinc-600">Analyze a message to see signal scores.</p>
              )}
              {selected && !selected.aiReviewed && (
                <p className="text-[10px] text-zinc-600">
                  Fast triage only — this message didn&apos;t cross the threshold for a full AI review.
                </p>
              )}
            </div>

            {selected && selected.flaggedPhrases.length > 0 && (
              <div className="flex flex-col gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3.5 py-3.5">
                <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-zinc-500">
                  Flagged Phrases
                </span>
                {selected.flaggedPhrases.map((f, i) => (
                  <div key={i} className="text-[11px]">
                    <span className={f.severity === "red" ? "text-red-400" : "text-amber-400"}>
                      &ldquo;{f.phrase}&rdquo;
                    </span>
                    <p className="text-zinc-500">{f.reason}</p>
                  </div>
                ))}
              </div>
            )}

            <div className="flex items-center gap-2 px-1 text-[10px] text-zinc-600">
              <ChevronRight className="h-3 w-3" />
              <span>
                Triage: hand-trained classifier · Deep review: Gemini
                {selected && !selected.aiReviewed && " (not invoked)"}
              </span>
            </div>

            {gmailConnection && (
              <button
                onClick={handleDisconnect}
                className="flex items-center justify-center gap-1.5 rounded-md border border-white/[0.06] px-3 py-2 text-[10px] uppercase tracking-wide text-zinc-500 hover:border-red-500/30 hover:text-red-400"
              >
                <Trash2 className="h-3 w-3" />
                Revoke Gmail Access
              </button>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
