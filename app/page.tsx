"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAction, useMutation, useQuery } from "convex/react";
import { AnimatePresence, motion, useMotionValue, useSpring } from "framer-motion";
import {
  Mail,
  Code2,
  Cloud,
  Plug,
  Unlink,
  Scan,
  Inbox,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  FileSearch,
  ScanSearch,
  LoaderCircle,
  ChevronRight,
  Crosshair,
  ExternalLink,
  Image as ImageIcon,
  Paperclip,
  Database,
  Hash,
  MessagesSquare,
  MessageCircle,
  Send,
  Camera,
  Smartphone,
  Briefcase,
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
  linkIntel?: { url: string; domain: string; vtMalicious: number; vtSuspicious: number }[];
  screenshot?: { url: string; resultUrl: string; screenshotUrl: string; uuid: string; ready: boolean };
  attachmentIntel?: { filename: string; sha256: string; found: boolean; vtMalicious: number; vtSuspicious: number }[];
}

function verdictTone(verdict: Verdict): Tone {
  if (verdict === "scam") return "critical";
  if (verdict === "suspicious") return "warn";
  return "clear";
}

function scamLikelihood(result: ScanResultDoc): number {
  return result.verdict === "safe" ? Math.max(0, 100 - result.confidence) : result.confidence;
}

const TONE_HEX: Record<Tone, string> = {
  clear: "#1fe3ad",
  warn: "#f5a623",
  critical: "#ef4060",
};

const TONE_BORDER: Record<Tone, string> = {
  clear: "border-[#1fe3ad]",
  warn: "border-[#f5a623]",
  critical: "border-[#ef4060]",
};

const TONE_TEXT: Record<Tone, string> = {
  clear: "text-[#3eeec0]",
  warn: "text-[#f5a623]",
  critical: "text-[#ef4060]",
};

const STAMP_CONFIG: Record<Verdict, { label: string; hex: string }> = {
  safe: { label: "VERIFIED SAFE", hex: "#1fe3ad" },
  suspicious: { label: "SUSPICIOUS", hex: "#f5a623" },
  scam: { label: "CONFIRMED SCAM", hex: "#ef4060" },
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
  { id: "slack", label: "Slack", icon: Hash, live: false },
  { id: "discord", label: "Discord", icon: MessagesSquare, live: false },
  { id: "whatsapp", label: "WhatsApp", icon: MessageCircle, live: false },
  { id: "telegram", label: "Telegram", icon: Send, live: false },
  { id: "instagram", label: "Instagram DMs", icon: Camera, live: false },
  { id: "sms", label: "SMS / Texts", icon: Smartphone, live: false },
  { id: "linkedin", label: "LinkedIn", icon: Briefcase, live: false },
  { id: "drive", label: "Google Drive", icon: Cloud, live: false },
] as const;

// ----------------------------------------------------------------------------
// Threat gauge — 270° arc instrument with tick marks and a hard bezel ring.
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
const TICK_COUNT = 11;

function ThreatGauge({ value, tone }: { value: number; tone: Tone }) {
  const animated = useAnimatedNumber(value, 900);
  const cx = 120;
  const cy = 116;
  const r = 92;
  const toneColor = TONE_HEX[tone];

  const track = describeArc(cx, cy, r, GAUGE_START, GAUGE_END);
  const needleAngle = GAUGE_START + (Math.min(100, animated) / 100) * GAUGE_SWEEP;

  const ticks = Array.from({ length: TICK_COUNT }, (_, i) => {
    const angle = GAUGE_START + (i / (TICK_COUNT - 1)) * GAUGE_SWEEP;
    const inner = polarToCartesian(cx, cy, r - 10, angle);
    const outer = polarToCartesian(cx, cy, r - 2, angle);
    return { inner, outer };
  });

  return (
    <div
      className="relative flex flex-col items-center rounded-full border-[3px] border-[#27272f] bg-[#101015] p-3"
      style={{ boxShadow: "inset 0 0 0 1px #000, 0 10px 0 0 #00000080, 0 1px 0 0 #34343e" }}
    >
      <svg viewBox="0 0 240 170" className="w-full max-w-[250px]">
        <path d={track} fill="none" stroke="#23232b" strokeWidth={12} strokeLinecap="round" />
        {ticks.map((t, i) => (
          <line
            key={i}
            x1={t.inner.x}
            y1={t.inner.y}
            x2={t.outer.x}
            y2={t.outer.y}
            stroke="#3a3a45"
            strokeWidth={2}
          />
        ))}
        <path
          d={describeArc(cx, cy, r, GAUGE_START, needleAngle)}
          fill="none"
          stroke={toneColor}
          strokeWidth={10}
          strokeLinecap="round"
        />
        <circle cx={cx} cy={cy} r={4} fill="#3a3a45" stroke="#000" strokeWidth={1} />
      </svg>
      <div className="absolute top-[54%] flex flex-col items-center">
        <span
          className="font-mono text-3xl font-bold tabular-nums tracking-tight"
          style={{ color: toneColor }}
        >
          {animated.toFixed(1)}
          <span className="text-base text-zinc-500">%</span>
        </span>
        <span className="mt-1 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">
          Scam Likelihood
        </span>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Mouse-tracking 3D tilt wrapper — subtle, no gradients, just perspective.
// ----------------------------------------------------------------------------

function TiltCard({ children, className }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const rawX = useMotionValue(0);
  const rawY = useMotionValue(0);
  const rotateX = useSpring(rawX, { stiffness: 200, damping: 20 });
  const rotateY = useSpring(rawY, { stiffness: 200, damping: 20 });

  function onMouseMove(e: React.MouseEvent<HTMLDivElement>) {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect) return;
    const px = (e.clientX - rect.left) / rect.width - 0.5;
    const py = (e.clientY - rect.top) / rect.height - 0.5;
    rawY.set(px * 8);
    rawX.set(py * -8);
  }
  function onMouseLeave() {
    rawX.set(0);
    rawY.set(0);
  }

  return (
    <motion.div
      ref={ref}
      onMouseMove={onMouseMove}
      onMouseLeave={onMouseLeave}
      style={{ rotateX, rotateY, transformPerspective: 900 }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

function SignalBar({ label, value }: { label: string; value: number }) {
  const barColor = value >= 70 ? "#ef4060" : value >= 35 ? "#f5a623" : "#52525b";
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between text-[11px]">
        <span className="text-zinc-400">{label}</span>
        <span className="font-mono font-bold text-zinc-300">{Math.round(value)}%</span>
      </div>
      <div className="h-[7px] w-full overflow-hidden rounded-sm border border-[#27272f] bg-[#0e0e12]">
        <motion.div
          className="h-full rounded-sm"
          style={{ backgroundColor: barColor }}
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
    <div className="flex items-center justify-between border-b-[1.5px] border-[#27272f] bg-[#121217] px-4 py-3">
      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 text-[#1fe3ad]" />
        <span className="text-[11px] font-bold uppercase tracking-[0.18em] text-zinc-400">
          {children}
        </span>
      </div>
      {trailing}
    </div>
  );
}

/** Reads ?connect=success|error via the Next.js router (hydration-safe — no window access)
 *  and clears it from the URL once shown. */
function ConnectBanner() {
  const params = useSearchParams();
  const router = useRouter();
  const connect = params.get("connect");
  const banner = connect === "success" || connect === "error" ? connect : null;

  useEffect(() => {
    if (banner) router.replace("/", { scroll: false });
  }, [banner, router]);

  return (
    <AnimatePresence>
      {banner && (
        <motion.div
          initial={{ opacity: 0, y: -6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
          className={`rounded-md border-[1.5px] px-3 py-1.5 text-[11px] font-semibold ${
            banner === "success"
              ? "border-[#1fe3ad] bg-[#0c1a16] text-[#3eeec0]"
              : "border-[#ef4060] bg-[#1a0c10] text-[#ef4060]"
          }`}
        >
          {banner === "success" ? "Gmail connected successfully." : "Connection failed — please try again."}
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/** Rotated ink-stamp badge over the analyzed message — the verdict, made tangible. */
function VerdictStamp({ verdict }: { verdict: Verdict }) {
  const cfg = STAMP_CONFIG[verdict];
  return (
    <motion.div
      initial={{ opacity: 0, scale: 1.4, rotate: -18 }}
      animate={{ opacity: 1, scale: 1, rotate: -9 }}
      transition={{ type: "spring", stiffness: 260, damping: 16 }}
      className="float-right -mr-1 -mt-1 mb-2 ml-3 select-none"
    >
      <div
        className="rounded-md border-[3px] bg-[#0c0c10] px-3 py-1 font-mono text-[12px] font-extrabold uppercase tracking-[0.1em]"
        style={{
          borderColor: cfg.hex,
          color: cfg.hex,
          boxShadow: `2px 2px 0 0 ${cfg.hex}, 0 0 0 1px #000`,
        }}
      >
        {cfg.label}
      </div>
    </motion.div>
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
  const segments = selected ? buildHighlightSegments(selected.snippet, selected.flaggedPhrases) : [];

  return (
    <div className="bg-dot-grid min-h-screen w-full text-zinc-300">
      <header className="relative z-10 flex flex-col gap-2 border-b-[1.5px] border-[#27272f] bg-[#121217] px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div
            className="flex h-9 w-9 items-center justify-center rounded-md border-[1.5px] border-[#1fe3ad] bg-[#0c0c10]"
            style={{ boxShadow: "2px 2px 0 0 #1fe3ad" }}
          >
            <Crosshair className="h-4.5 w-4.5 text-[#1fe3ad]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-extrabold tracking-tight text-zinc-50">
                GHOSTFILTER AI
              </h1>
              <span className="rounded border-[1.5px] border-[#34343e] px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-zinc-500">
                Scam &amp; Phishing Shield
              </span>
              <span className="rounded border-[1.5px] border-[#f5a623] bg-[#1a140a] px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-[#f5a623]">
                Beta
              </span>
            </div>
            <p className="text-[11px] text-zinc-500">
              Read-only access · we never send, delete, or modify your messages.
            </p>
          </div>
        </div>
        <Suspense fallback={null}>
          <ConnectBanner />
        </Suspense>
      </header>

      <main className="relative z-10 grid grid-cols-1 lg:grid-cols-12">
        {/* ZONE A — Recent Scans */}
        <section className="order-2 col-span-1 flex h-[360px] flex-col border-b-[1.5px] border-[#27272f] lg:order-1 lg:col-span-3 lg:h-[calc(100vh-73px)] lg:border-b-0 lg:border-r-[1.5px]">
          <SectionLabel
            icon={Inbox}
            trailing={
              <span className="text-[10px] font-bold text-zinc-500">{scans?.length ?? 0} scanned</span>
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
                const isSelected = selected?._id === s._id;
                return (
                  <motion.button
                    key={s._id}
                    layout
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    onClick={() => setSelectedId(s._id)}
                    className={`mb-1.5 flex w-full items-start gap-2.5 rounded-md border-l-[3px] bg-[#121217] px-2.5 py-2 text-left text-[11px] hover:bg-[#181820] ${
                      TONE_BORDER[t]
                    } ${isSelected ? "ring-1 ring-[#34343e]" : ""}`}
                  >
                    <div className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate font-mono text-zinc-300">
                        {s.subject || s.snippet}
                      </span>
                      <span className="font-mono text-[10px] text-zinc-600">
                        {s.provider} · {new Date(s._creationTime).toLocaleTimeString()}
                      </span>
                    </div>
                    <span className={`shrink-0 font-mono text-[10px] font-bold ${TONE_TEXT[t]}`}>
                      {s.verdict.toUpperCase()}
                    </span>
                  </motion.button>
                );
              })}
            </AnimatePresence>
          </div>
        </section>

        {/* ZONE B — Analyzer */}
        <section className="order-1 col-span-1 flex flex-col border-b-[1.5px] border-[#27272f] lg:order-2 lg:col-span-6 lg:h-[calc(100vh-73px)] lg:overflow-y-auto lg:border-b-0 lg:border-r-[1.5px]">
          <SectionLabel icon={Plug}>Connect Accounts</SectionLabel>
          <div className="flex flex-wrap gap-2 border-b-[1.5px] border-[#27272f] px-5 py-4">
            {PROVIDERS.map((p) => {
              const Icon = p.icon;
              if (p.id === "gmail" && gmailConnection) {
                return (
                  <div
                    key={p.id}
                    className="flex items-center gap-2 rounded-md border-[1.5px] border-[#1fe3ad] bg-[#0c1a16] px-3 py-2 text-[11px] text-[#3eeec0]"
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span className="font-bold">{gmailConnection.accountEmail ?? "Gmail connected"}</span>
                    <button
                      onClick={handleScanNow}
                      disabled={scanning}
                      className="ml-2 flex items-center gap-1 rounded border-[1.5px] border-[#1fe3ad] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide hover:bg-[#1fe3ad] hover:text-[#06231c] disabled:opacity-50"
                    >
                      {scanning ? <LoaderCircle className="h-3 w-3 animate-spin" /> : <Scan className="h-3 w-3" />}
                      Scan Now
                    </button>
                    <button
                      onClick={handleDisconnect}
                      className="ml-1 flex items-center gap-1 rounded border-[1.5px] border-[#34343e] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-zinc-400 hover:border-[#ef4060] hover:text-[#ef4060]"
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
                    className="flex items-center gap-2 rounded-md border-[1.5px] border-[#34343e] bg-[#121217] px-3 py-2 text-[11px] font-semibold text-zinc-200 transition-transform hover:-translate-y-0.5 hover:border-[#1fe3ad]"
                    style={{ boxShadow: "2px 2px 0 0 #000" }}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    Connect {p.label}
                  </a>
                );
              }
              return (
                <div
                  key={p.id}
                  className="flex cursor-not-allowed items-center gap-2 rounded-md border-[1.5px] border-dashed border-[#27272f] px-3 py-2 text-[11px] text-zinc-600"
                >
                  <Icon className="h-3.5 w-3.5" />
                  {p.label}
                  <span className="text-[9px] font-bold uppercase tracking-wide text-zinc-700">Soon</span>
                </div>
              );
            })}
          </div>
          {scanError && (
            <p className="border-b-[1.5px] border-[#27272f] bg-[#1a0c10] px-5 py-2 text-[11px] font-semibold text-[#ef4060]">
              {scanError}
            </p>
          )}

          <SectionLabel icon={FileSearch}>Paste a Message to Analyze</SectionLabel>
          <div className="flex flex-col gap-2.5 border-b-[1.5px] border-[#27272f] px-5 py-4">
            <textarea
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              placeholder="Paste a suspicious email, text message, or DM here..."
              rows={4}
              className="w-full resize-none rounded-md border-[1.5px] border-[#27272f] bg-[#0e0e12] px-3 py-2.5 text-[13px] text-zinc-200 placeholder:text-zinc-600 focus:border-[#1fe3ad] focus:outline-none"
            />
            <div className="flex flex-wrap items-center gap-1.5">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.label}
                  onClick={() => setMessageText(ex.text)}
                  className="rounded-full border-[1.5px] border-[#27272f] px-2.5 py-1 text-[10px] font-semibold text-zinc-500 hover:border-[#34343e] hover:text-zinc-300"
                >
                  {ex.label}
                </button>
              ))}
              <button
                onClick={handleAnalyze}
                disabled={!messageText.trim() || analyzing}
                className="ml-auto flex items-center gap-1.5 rounded-md border-[1.5px] border-[#1fe3ad] bg-[#1fe3ad] px-3.5 py-1.5 text-[11px] font-extrabold uppercase tracking-wide text-[#06231c] transition-all hover:bg-[#3eeec0] active:translate-x-[1.5px] active:translate-y-[1.5px] active:shadow-none disabled:cursor-not-allowed disabled:border-[#27272f] disabled:bg-[#1a1a22] disabled:text-zinc-600"
                style={!messageText.trim() || analyzing ? undefined : { boxShadow: "2.5px 2.5px 0 0 #0a4a3a" }}
              >
                {analyzing ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}
                Analyze
              </button>
            </div>
          </div>

          <div className="flex flex-col items-center border-b-[1.5px] border-[#27272f] px-6 py-7">
            <TiltCard className="[transform-style:preserve-3d]">
              <ThreatGauge value={gaugeValue} tone={tone} />
            </TiltCard>
          </div>

          <div className="relative flex flex-1 flex-col px-5 py-4">
            <span className="pb-2 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
              Analyzed Message
            </span>
            <div className="relative min-h-[120px] rounded-md border-[1.5px] border-[#27272f] bg-[#0e0e12] p-4 font-mono text-[12.5px] leading-[1.8] text-zinc-400">
              {selected && <VerdictStamp verdict={selected.verdict} />}
              {selected ? (
                <p className="whitespace-pre-wrap">
                  {segments.map((seg, i) => (
                    <span
                      key={i}
                      className={
                        seg.severity === "red"
                          ? "rounded-sm bg-[#ef4060] px-0.5 text-[#0c0c10]"
                          : seg.severity === "amber"
                          ? "rounded-sm bg-[#f5a623] px-0.5 text-[#0c0c10]"
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
        <section className="order-3 col-span-1 flex flex-col lg:col-span-3 lg:h-[calc(100vh-73px)] lg:overflow-y-auto">
          <SectionLabel icon={ShieldAlert}>Verdict</SectionLabel>
          <div className="flex flex-col gap-4 px-4 py-4">
            <div
              className={`rounded-lg border-[1.5px] bg-[#121217] px-4 py-4 ${
                tone === "critical" ? "border-[#ef4060]" : "border-[#27272f]"
              }`}
              style={tone === "critical" ? { boxShadow: "3px 3px 0 0 #4a0a18" } : undefined}
            >
              <div className="flex items-center gap-2">
                {tone === "clear" ? (
                  <ShieldCheck className="h-4 w-4 text-[#1fe3ad]" />
                ) : (
                  <ShieldAlert className={`h-4 w-4 ${TONE_TEXT[tone]}`} />
                )}
                <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">Verdict</span>
              </div>
              <div className={`mt-1.5 flex items-center gap-2 text-xl font-extrabold tracking-tight ${TONE_TEXT[tone]}`}>
                <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: TONE_HEX[tone] }} />
                {selected ? selected.verdict.toUpperCase() : "—"}
              </div>
              {selected && <p className="mt-2 text-[11px] leading-relaxed text-zinc-400">{selected.summary}</p>}
            </div>

            {selected && (
              <div className="rounded-lg border-[1.5px] border-[#27272f] bg-[#121217] px-3.5 py-3.5">
                <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  What to do
                </span>
                <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-300">{selected.recommendation}</p>
              </div>
            )}

            <div className="flex flex-col gap-3 rounded-lg border-[1.5px] border-[#27272f] bg-[#121217] px-3.5 py-3.5">
              <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
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
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[#27272f] bg-[#121217] px-3.5 py-3.5">
                <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  Flagged Phrases
                </span>
                {selected.flaggedPhrases.map((f, i) => (
                  <div key={i} className="text-[11px]">
                    <span className={f.severity === "red" ? "font-bold text-[#ef4060]" : "font-bold text-[#f5a623]"}>
                      &ldquo;{f.phrase}&rdquo;
                    </span>
                    <p className="text-zinc-500">{f.reason}</p>
                  </div>
                ))}
              </div>
            )}

            {selected && selected.linkIntel && selected.linkIntel.length > 0 && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[#27272f] bg-[#121217] px-3.5 py-3.5">
                <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  <Database className="h-3 w-3" />
                  Threat Intelligence
                </span>
                {selected.linkIntel.map((li, i) => {
                  const flagged = li.vtMalicious > 0 || li.vtSuspicious > 0;
                  return (
                    <div key={i} className="flex items-center justify-between text-[11px]">
                      <span className="truncate font-mono text-zinc-400">{li.domain}</span>
                      <span className={`shrink-0 font-mono font-bold ${flagged ? "text-[#ef4060]" : "text-[#3eeec0]"}`}>
                        {flagged ? `${li.vtMalicious + li.vtSuspicious} engines flagged` : "clean on VirusTotal"}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}

            {selected && selected.screenshot && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[#27272f] bg-[#121217] px-3.5 py-3.5">
                <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  <ImageIcon className="h-3 w-3" />
                  Sandboxed Page Preview
                </span>
                {selected.screenshot.ready ? (
                  // eslint-disable-next-line @next/next/no-img-element -- external, unpredictable urlscan.io image
                  <img
                    src={selected.screenshot.screenshotUrl}
                    alt="Sandboxed screenshot of the linked page"
                    className="w-full rounded border-[1.5px] border-[#27272f]"
                  />
                ) : (
                  <p className="text-[11px] text-zinc-600">Still rendering on urlscan.io — check the full report shortly.</p>
                )}
                <a
                  href={selected.screenshot.resultUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[10px] font-semibold text-zinc-500 hover:text-[#3eeec0]"
                >
                  <ExternalLink className="h-3 w-3" />
                  Full urlscan.io report
                </a>
              </div>
            )}

            {selected && selected.attachmentIntel && selected.attachmentIntel.length > 0 && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[#27272f] bg-[#121217] px-3.5 py-3.5">
                <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  <Paperclip className="h-3 w-3" />
                  Attachment Scan
                </span>
                {selected.attachmentIntel.map((a, i) => {
                  const malicious = a.vtMalicious > 0;
                  return (
                    <div key={i} className="flex items-center justify-between text-[11px]">
                      <span className="truncate font-mono text-zinc-400">{a.filename}</span>
                      <span className={`shrink-0 font-mono font-bold ${malicious ? "text-[#ef4060]" : "text-[#3eeec0]"}`}>
                        {!a.found ? "unknown file" : malicious ? `${a.vtMalicious} engines flagged` : "clean on VirusTotal"}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}

            <div className="flex items-center gap-2 px-1 text-[10px] text-zinc-600">
              <ChevronRight className="h-3 w-3" />
              <span>
                Triage: hand-trained classifier · Deep review: Gemini
                {selected && !selected.aiReviewed && " (not invoked)"}
              </span>
            </div>

            <p className="rounded-md border-[1.5px] border-[#f5a623]/40 bg-[#1a140a] px-3 py-2 text-[10px] leading-relaxed text-[#f5a623]">
              GhostFilter AI is in beta and can make mistakes. Treat results as guidance, not a
              final ruling — always use your own judgment before acting on any message.
            </p>

            {gmailConnection && (
              <button
                onClick={handleDisconnect}
                className="flex items-center justify-center gap-1.5 rounded-md border-[1.5px] border-[#27272f] px-3 py-2 text-[10px] font-bold uppercase tracking-wide text-zinc-500 hover:border-[#ef4060] hover:text-[#ef4060]"
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
