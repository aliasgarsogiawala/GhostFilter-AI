"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useAction, useMutation, useQuery } from "convex/react";
import { AnimatePresence, motion, useMotionValue, useSpring } from "framer-motion";
import {
  Mail,
  Code2,
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
  ExternalLink,
  Image as ImageIcon,
  Paperclip,
  Database,
  MessagesSquare,
  MessageCircle,
  Send,
  Camera,
  Smartphone,
} from "lucide-react";
import { BarChart3 } from "lucide-react";
import { api } from "@/convex/_generated/api";
import { useOwnerId } from "@/lib/useOwnerId";
import { useTheme, THEMES } from "@/lib/useTheme";
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
  forensics?: {
    fields: { label: string; value: string; status?: "ok" | "warn" | "bad" }[];
    indicators: { label: string; detail: string; severity: "amber" | "red" }[];
  };
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
  clear: "var(--accent)",
  warn: "#f5a623",
  critical: "#ef4060",
};

const TONE_BORDER: Record<Tone, string> = {
  clear: "border-[var(--accent)]",
  warn: "border-[#f5a623]",
  critical: "border-[#ef4060]",
};

const TONE_TEXT: Record<Tone, string> = {
  clear: "text-[var(--accent-bright)]",
  warn: "text-[#f5a623]",
  critical: "text-[#ef4060]",
};

const STAMP_CONFIG: Record<Verdict, { label: string; hex: string }> = {
  safe: { label: "VERIFIED SAFE", hex: "var(--accent)" },
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
    label: "Live link scan",
    text: "Your account needs verification. Please review your details at https://example.com/login to keep your account active.",
  },
  {
    label: "A normal text",
    text: "Hey! Are we still on for lunch tomorrow at noon? Let me know if that still works for you.",
  },
];

// Channels where personal messages CAN'T be read by a web app (platform restriction) —
// users paste these in manually instead. Honest, and still genuinely useful.
const MANUAL_CHANNELS = [
  { id: "sms", label: "SMS / Text", icon: Smartphone },
  { id: "whatsapp", label: "WhatsApp", icon: MessageCircle },
  { id: "discord", label: "Discord", icon: MessagesSquare },
  { id: "instagram", label: "Instagram DM", icon: Camera },
  { id: "telegram", label: "Telegram", icon: Send },
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

function ThreatGauge({ value, tone, scanning }: { value: number; tone: Tone; scanning?: boolean }) {
  const animated = useAnimatedNumber(value, 900);
  const cx = 120;
  const cy = 116;
  const r = 92;
  const toneColor = TONE_HEX[tone];
  // Glow intensifies with the displayed value — subtle at low risk, strong at high.
  const glow = Math.min(0.55, 0.12 + (animated / 100) * 0.5);

  const track = describeArc(cx, cy, r, GAUGE_START, GAUGE_END);
  const needleAngle = GAUGE_START + (Math.min(100, animated) / 100) * GAUGE_SWEEP;

  const ticks = Array.from({ length: TICK_COUNT }, (_, i) => {
    const angle = GAUGE_START + (i / (TICK_COUNT - 1)) * GAUGE_SWEEP;
    const inner = polarToCartesian(cx, cy, r - 10, angle);
    const outer = polarToCartesian(cx, cy, r - 2, angle);
    const frac = i / (TICK_COUNT - 1);
    const lit = frac <= Math.min(100, animated) / 100;
    return { inner, outer, lit };
  });

  return (
    <motion.div
      className="relative flex flex-col items-center rounded-full border-[3px] border-[var(--line)] bg-[var(--panel)] p-3"
      animate={{ boxShadow: `inset 0 0 0 1px #000, 0 10px 0 0 #00000080, 0 0 36px -8px color-mix(in srgb, ${toneColor} ${Math.round(glow * 100)}%, transparent)` }}
      transition={{ duration: 0.6 }}
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
            stroke={t.lit ? toneColor : "#3a3a45"}
            strokeWidth={2}
            opacity={t.lit ? 0.9 : 1}
          />
        ))}
        {!scanning && (
          <path
            d={describeArc(cx, cy, r, GAUGE_START, needleAngle)}
            fill="none"
            stroke={toneColor}
            strokeWidth={10}
            strokeLinecap="round"
          />
        )}
        {scanning && (
          <motion.path
            d={describeArc(cx, cy, r, GAUGE_START, GAUGE_START + GAUGE_SWEEP * 0.25)}
            fill="none"
            stroke={toneColor}
            strokeWidth={10}
            strokeLinecap="round"
            style={{ originX: `${cx}px`, originY: `${cy}px` }}
            animate={{ rotate: [0, 360] }}
            transition={{ duration: 1.1, repeat: Infinity, ease: "linear" }}
          />
        )}
        <circle cx={cx} cy={cy} r={4} fill="#3a3a45" stroke="#000" strokeWidth={1} />
      </svg>
      <div className="absolute top-[54%] flex flex-col items-center">
        {scanning ? (
          <motion.span
            className="font-mono text-2xl font-bold tracking-tight"
            style={{ color: toneColor }}
            animate={{ opacity: [0.4, 1, 0.4] }}
            transition={{ duration: 1.1, repeat: Infinity }}
          >
            SCANNING
          </motion.span>
        ) : (
          <span
            className="font-mono text-3xl font-bold tabular-nums tracking-tight"
            style={{ color: toneColor }}
          >
            {animated.toFixed(1)}
            <span className="text-base text-zinc-500">%</span>
          </span>
        )}
        <span className="mt-1 text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">
          Scam Likelihood
        </span>
      </div>
    </motion.div>
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
      <div className="h-[7px] w-full overflow-hidden rounded-sm border border-[var(--line)] bg-[var(--input)]">
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

/** Custom brand mark: a protective shield crossed by a scan-line with a center node —
 *  "scanning shield". Animated scan sweep on the line for a subtle bit of life. */
function GhostMark() {
  return (
    <div
      className="relative flex h-9 w-9 items-center justify-center rounded-md border-[1.5px] border-[var(--accent)] bg-[var(--ink)]"
      style={{ boxShadow: "2px 2px 0 0 var(--accent)" }}
    >
      <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none">
        <path
          d="M12 2.5 L19.5 5.5 V11 C19.5 15.8 16.2 19.2 12 21.5 C7.8 19.2 4.5 15.8 4.5 11 V5.5 Z"
          stroke="var(--accent)"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <circle cx="12" cy="11" r="1.5" fill="var(--accent)" />
        <motion.line
          x1="6.6"
          x2="17.4"
          y1={7}
          y2={7}
          stroke="var(--accent)"
          strokeWidth="1.4"
          strokeLinecap="round"
          initial={{ y1: 7, y2: 7, opacity: 0.35 }}
          animate={{ y1: [7, 15, 7], y2: [7, 15, 7], opacity: [0.35, 1, 0.35] }}
          transition={{ duration: 2.6, repeat: Infinity, ease: "easeInOut" }}
        />
      </svg>
    </div>
  );
}

function ThemeSwitcher() {
  const [theme, setTheme] = useTheme();
  return (
    <div className="flex items-center gap-1.5" title="Accent theme">
      {THEMES.map((t) => (
        <button
          key={t.id}
          onClick={() => setTheme(t.id)}
          aria-label={t.label}
          title={t.label}
          className={`h-3.5 w-3.5 rounded-full border transition-transform hover:scale-110 ${
            theme === t.id ? "border-white/70" : "border-transparent"
          }`}
          style={{
            backgroundColor: t.swatch,
            boxShadow: theme === t.id ? `0 0 0 2px var(--ink), 0 0 0 3px ${t.swatch}` : undefined,
          }}
        />
      ))}
    </div>
  );
}

function ScanButton({
  label,
  busy,
  disabled,
  onClick,
}: {
  label: string;
  busy: boolean;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="flex items-center gap-1 rounded border-[1.5px] border-[var(--accent)] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide hover:bg-[var(--accent)] hover:text-[var(--accent-ink)] disabled:opacity-50"
    >
      {busy ? <LoaderCircle className="h-3 w-3 animate-spin" /> : <Scan className="h-3 w-3" />}
      {label}
    </button>
  );
}

function ConnectButton({
  href,
  icon: Icon,
  label,
  sub,
}: {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  sub?: string;
}) {
  return (
    <a
      href={href}
      className="group flex items-center gap-2 rounded-md border-[1.5px] border-[var(--line-strong)] bg-[var(--panel)] px-3 py-2 text-[11px] font-semibold text-zinc-200 transition-transform hover:-translate-y-0.5 hover:border-[var(--accent)]"
      style={{ boxShadow: "2px 2px 0 0 #000" }}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
      {sub && <span className="text-[9px] font-bold uppercase tracking-wide text-zinc-600 group-hover:text-[var(--accent-bright)]">{sub}</span>}
    </a>
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
    <div className="flex items-center justify-between border-b-[1.5px] border-[var(--line)] bg-[var(--panel)] px-4 py-3">
      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 text-[var(--accent)]" />
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
              ? "border-[var(--accent)] bg-[var(--accent-dim)] text-[var(--accent-bright)]"
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
        className="rounded-md border-[3px] bg-[var(--ink)] px-3 py-1 font-mono text-[12px] font-extrabold uppercase tracking-[0.1em]"
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
  const scanDrive = useAction(api.drive.scanDrive);
  const scanGithub = useAction(api.github.scanNotifications);
  const disconnect = useMutation(api.connections.disconnect);

  const [messageText, setMessageText] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [scanningKind, setScanningKind] = useState<"inbox" | "drive" | "github" | null>(null);
  const [scanDepth, setScanDepth] = useState(25);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sourceHint, setSourceHint] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const gmailConnection = connections?.find((c) => c.provider === "gmail" && c.status === "connected");
  const githubConnection = connections?.find((c) => c.provider === "github" && c.status === "connected");
  const selected = scans?.find((s) => s._id === selectedId) ?? scans?.[0];

  const analyzeText = async (text: string) => {
    if (!ownerId || !text.trim() || analyzing) return;
    setAnalyzing(true);
    try {
      const result = await analyzeMessage({ text, ownerId });
      setSelectedId(result.id);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleAnalyze = () => analyzeText(messageText);

  const pickChannel = (label: string) => {
    setSourceHint(label);
    textareaRef.current?.focus();
    textareaRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const runScan = async (kind: "inbox" | "drive" | "github") => {
    if (!ownerId || scanningKind) return;
    setScanningKind(kind);
    setScanError(null);
    try {
      if (kind === "inbox") await scanInbox({ ownerId, limit: scanDepth });
      else if (kind === "drive") await scanDrive({ ownerId, limit: scanDepth });
      else await scanGithub({ ownerId, limit: scanDepth });
    } catch (err) {
      setScanError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setScanningKind(null);
    }
  };

  const handleDisconnect = async (id?: string, providerLabel = "this account") => {
    const target = id ?? gmailConnection?._id;
    if (!ownerId || !target) return;
    const ok = window.confirm(
      `Disconnect ${providerLabel}?\n\nGhostFilter will lose access and stop scanning it. You'll need to reconnect (and re-authorize) before you can scan again.`
    );
    if (!ok) return;
    await disconnect({ connectionId: target as never, ownerId });
  };

  const tone = selected ? verdictTone(selected.verdict) : "clear";
  const gaugeValue = selected ? scamLikelihood(selected) : 0;
  const segments = selected ? buildHighlightSegments(selected.snippet, selected.flaggedPhrases) : [];

  return (
    <div className="bg-dot-grid min-h-screen w-full text-zinc-300">
      <header className="relative z-10 flex flex-col gap-2 border-b-[1.5px] border-[var(--line)] bg-[var(--panel)] px-5 py-3.5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <GhostMark />
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-[17px] tracking-tight text-zinc-50">
                <span className="font-bold">Ghost</span>
                <span className="font-light text-zinc-400">Filter</span>
                <span className="ml-1 align-top text-[10px] font-bold text-[var(--accent)]">AI</span>
              </h1>
              <span className="rounded border-[1.5px] border-[var(--line-strong)] px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider text-zinc-500">
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
        <div className="flex items-center gap-4">
          <Suspense fallback={null}>
            <ConnectBanner />
          </Suspense>
          <ThemeSwitcher />
          <Link
            href="/profile"
            className="flex items-center gap-1.5 rounded-md border-[1.5px] border-[var(--line-strong)] bg-[var(--panel)] px-2.5 py-1.5 text-[11px] font-bold text-zinc-300 transition-transform hover:-translate-y-0.5 hover:border-[var(--accent)] hover:text-[var(--accent-bright)]"
          >
            <BarChart3 className="h-3.5 w-3.5" />
            Analytics
          </Link>
        </div>
      </header>

      <main className="relative z-10 grid grid-cols-1 lg:grid-cols-12">
        {/* ZONE A — Recent Scans */}
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
          className="order-2 col-span-1 flex h-[360px] flex-col border-b-[1.5px] border-[var(--line)] lg:order-1 lg:col-span-3 lg:h-[calc(100vh-73px)] lg:border-b-0 lg:border-r-[1.5px]"
        >
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
                    className={`mb-1.5 flex w-full items-start gap-2.5 rounded-md border-l-[3px] bg-[var(--panel)] px-2.5 py-2 text-left text-[11px] hover:bg-[#181820] ${
                      TONE_BORDER[t]
                    } ${isSelected ? "ring-1 ring-[var(--line-strong)]" : ""}`}
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
        </motion.section>

        {/* ZONE B — Analyzer */}
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1], delay: 0.08 }}
          className="order-1 col-span-1 flex flex-col border-b-[1.5px] border-[var(--line)] lg:order-2 lg:col-span-6 lg:h-[calc(100vh-73px)] lg:overflow-y-auto lg:border-b-0 lg:border-r-[1.5px]"
        >
          <SectionLabel icon={Plug}>Connect Accounts</SectionLabel>
          <div className="flex flex-wrap gap-2 border-b-[1.5px] border-[var(--line)] px-5 py-4">
            {/* Google (Gmail + Drive share one connection) */}
            {gmailConnection ? (
              <div className="flex flex-wrap items-center gap-2 rounded-md border-[1.5px] border-[var(--accent)] bg-[var(--accent-dim)] px-3 py-2 text-[11px] text-[var(--accent-bright)]">
                <Mail className="h-3.5 w-3.5" />
                <span className="font-bold">{gmailConnection.accountEmail ?? "Google connected"}</span>
                <ScanButton
                  label="Scan Inbox"
                  busy={scanningKind === "inbox"}
                  disabled={!!scanningKind}
                  onClick={() => runScan("inbox")}
                />
                <ScanButton
                  label="Scan Drive"
                  busy={scanningKind === "drive"}
                  disabled={!!scanningKind}
                  onClick={() => runScan("drive")}
                />
                <button
                  onClick={() => handleDisconnect(gmailConnection._id, "Google (Gmail + Drive)")}
                  className="flex items-center gap-1 rounded border-[1.5px] border-[var(--line-strong)] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-zinc-400 hover:border-[#ef4060] hover:text-[#ef4060]"
                >
                  <Unlink className="h-3 w-3" />
                  Disconnect
                </button>
              </div>
            ) : (
              ownerId && (
                <ConnectButton href={`/api/auth/google?ownerId=${ownerId}`} icon={Mail} label="Connect Google" sub="Gmail + Drive" />
              )
            )}

            {/* GitHub */}
            {githubConnection ? (
              <div className="flex flex-wrap items-center gap-2 rounded-md border-[1.5px] border-[var(--accent)] bg-[var(--accent-dim)] px-3 py-2 text-[11px] text-[var(--accent-bright)]">
                <Code2 className="h-3.5 w-3.5" />
                <span className="font-bold">{githubConnection.accountName ? `@${githubConnection.accountName}` : "GitHub connected"}</span>
                <ScanButton
                  label="Scan"
                  busy={scanningKind === "github"}
                  disabled={!!scanningKind}
                  onClick={() => runScan("github")}
                />
                <button
                  onClick={() => handleDisconnect(githubConnection._id, "GitHub")}
                  className="flex items-center gap-1 rounded border-[1.5px] border-[var(--line-strong)] px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-zinc-400 hover:border-[#ef4060] hover:text-[#ef4060]"
                >
                  <Unlink className="h-3 w-3" />
                  Disconnect
                </button>
              </div>
            ) : (
              ownerId && (
                <ConnectButton href={`/api/auth/github?ownerId=${ownerId}`} icon={Code2} label="Connect GitHub" sub="Notifications" />
              )
            )}

            {/* Outlook — not built yet */}
            <div className="flex cursor-not-allowed items-center gap-2 rounded-md border-[1.5px] border-dashed border-[var(--line)] px-3 py-2 text-[11px] text-zinc-600">
              <Mail className="h-3.5 w-3.5" />
              Outlook
              <span className="text-[9px] font-bold uppercase tracking-wide text-zinc-700">Soon</span>
            </div>
          </div>

          {(gmailConnection || githubConnection) && (
            <div className="flex flex-wrap items-center gap-2 border-b-[1.5px] border-[var(--line)] px-5 py-2.5">
              <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-zinc-500">
                Scan depth
              </span>
              <div className="flex overflow-hidden rounded-md border-[1.5px] border-[var(--line)]">
                {[10, 25, 50].map((n) => (
                  <button
                    key={n}
                    onClick={() => setScanDepth(n)}
                    className={`px-2.5 py-1 text-[11px] font-bold tabular-nums transition-colors ${
                      scanDepth === n
                        ? "bg-[var(--accent)] text-[var(--accent-ink)]"
                        : "bg-[var(--panel)] text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    {n}
                  </button>
                ))}
              </div>
              <span className="text-[10px] text-zinc-600">most recent items per scan</span>
            </div>
          )}
          {scanError && (
            <p className="border-b-[1.5px] border-[var(--line)] bg-[#1a0c10] px-5 py-2 text-[11px] font-semibold text-[#ef4060]">
              {scanError}
            </p>
          )}

          {/* Channels that can't be auto-connected (no API to read personal messages) —
              honest manual-paste path instead of fake "connect" buttons. */}
          <div className="border-b-[1.5px] border-[var(--line)] px-5 py-3">
            <p className="mb-2 text-[10px] leading-relaxed text-zinc-500">
              <span className="font-bold text-zinc-400">Can&apos;t be auto-connected.</span> Apps like these
              don&apos;t let outside tools read your private chats — tap one and paste the message in.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {MANUAL_CHANNELS.map((c) => {
                const Icon = c.icon;
                const active = sourceHint === c.label;
                return (
                  <button
                    key={c.id}
                    onClick={() => pickChannel(c.label)}
                    className={`flex items-center gap-1.5 rounded-md border-[1.5px] px-2.5 py-1.5 text-[10px] font-semibold transition-transform hover:-translate-y-0.5 ${
                      active
                        ? "border-[var(--accent)] bg-[var(--accent-dim)] text-[var(--accent-bright)]"
                        : "border-[var(--line)] bg-[var(--panel)] text-zinc-400 hover:border-[var(--line-strong)]"
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    {c.label}
                  </button>
                );
              })}
            </div>
          </div>

          <SectionLabel icon={FileSearch}>
            {sourceHint ? `Paste the ${sourceHint} message` : "Paste a Message to Analyze"}
          </SectionLabel>
          <div className="flex flex-col gap-2.5 border-b-[1.5px] border-[var(--line)] px-5 py-4">
            <textarea
              ref={textareaRef}
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              onKeyDown={(e) => {
                if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                  e.preventDefault();
                  handleAnalyze();
                }
              }}
              placeholder={
                sourceHint
                  ? `Paste the suspicious ${sourceHint} message here...`
                  : "Paste a suspicious email, text message, or DM here..."
              }
              rows={4}
              className="w-full resize-none rounded-md border-[1.5px] border-[var(--line)] bg-[var(--input)] px-3 py-2.5 text-[13px] text-zinc-200 placeholder:text-zinc-600 focus:border-[var(--accent)] focus:outline-none"
            />
            <p className="text-[10px] text-zinc-600">
              Tip: paste a full email <span className="text-zinc-500">with headers</span> (Gmail → ⋮ → &ldquo;Show original&rdquo;) for deep header forensics — sender spoofing, Reply-To mismatches, SPF/DKIM/DMARC. Press{" "}
              <span className="font-mono text-zinc-500">⌘/Ctrl + Enter</span> to analyze.
            </p>
            <div className="flex flex-wrap items-center gap-1.5">
              {EXAMPLES.map((ex) => (
                <button
                  key={ex.label}
                  onClick={() => {
                    setSourceHint(null);
                    setMessageText(ex.text);
                    analyzeText(ex.text);
                  }}
                  disabled={analyzing}
                  className="rounded-full border-[1.5px] border-[var(--line)] px-2.5 py-1 text-[10px] font-semibold text-zinc-500 transition-colors hover:border-[var(--accent)] hover:text-[var(--accent-bright)] disabled:opacity-50"
                >
                  {ex.label}
                </button>
              ))}
              <button
                onClick={handleAnalyze}
                disabled={!messageText.trim() || analyzing}
                className="ml-auto flex items-center gap-1.5 rounded-md border-[1.5px] border-[var(--accent)] bg-[var(--accent)] px-3.5 py-1.5 text-[11px] font-extrabold uppercase tracking-wide text-[var(--accent-ink)] transition-all hover:bg-[var(--accent-bright)] active:translate-x-[1.5px] active:translate-y-[1.5px] active:shadow-none disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[#1a1a22] disabled:text-zinc-600"
                style={!messageText.trim() || analyzing ? undefined : { boxShadow: "2.5px 2.5px 0 0 #0a4a3a" }}
              >
                {analyzing ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}
                {analyzing ? "Analyzing" : "Analyze"}
              </button>
            </div>
          </div>

          <div className="flex flex-col items-center border-b-[1.5px] border-[var(--line)] px-6 py-7">
            <TiltCard className="[transform-style:preserve-3d]">
              <ThreatGauge value={gaugeValue} tone={tone} scanning={analyzing} />
            </TiltCard>
          </div>

          <div className="relative flex flex-1 flex-col px-5 py-4">
            <span className="pb-2 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
              Analyzed Message
            </span>
            <div className="relative min-h-[120px] rounded-md border-[1.5px] border-[var(--line)] bg-[var(--input)] p-4 font-mono text-[12.5px] leading-[1.8] text-zinc-400">
              {selected && <VerdictStamp verdict={selected.verdict} />}
              {selected ? (
                <p className="whitespace-pre-wrap">
                  {segments.map((seg, i) => (
                    <span
                      key={i}
                      className={
                        seg.severity === "red"
                          ? "rounded-sm bg-[#ef4060] px-0.5 text-[var(--ink)]"
                          : seg.severity === "amber"
                          ? "rounded-sm bg-[#f5a623] px-0.5 text-[var(--ink)]"
                          : ""
                      }
                    >
                      {seg.text}
                    </span>
                  ))}
                </p>
              ) : (
                <div className="flex min-h-[88px] flex-col items-center justify-center gap-1 text-center">
                  <ScanSearch className="h-5 w-5 text-zinc-700" />
                  <p className="text-zinc-600">
                    Paste a message or tap an example — your verdict appears here.
                  </p>
                </div>
              )}
            </div>

            {/* PhishTool-style header forensics — shown when the analyzed item is a real email
                (Gmail scan, or a pasted raw email with headers). */}
            {selected?.forensics && (
              <div className="mt-4 rounded-md border-[1.5px] border-[var(--line)] bg-[var(--input)]">
                <div className="flex items-center gap-2 border-b-[1.5px] border-[var(--line)] px-4 py-2.5">
                  <FileSearch className="h-3.5 w-3.5 text-[var(--accent)]" />
                  <span className="text-[11px] font-bold uppercase tracking-[0.16em] text-zinc-400">
                    Email Header Forensics
                  </span>
                </div>

                {selected.forensics.indicators.length > 0 && (
                  <div className="flex flex-col gap-2 border-b-[1.5px] border-[var(--line)] px-4 py-3">
                    {selected.forensics.indicators.map((ind, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <ShieldAlert
                          className="mt-0.5 h-3.5 w-3.5 shrink-0"
                          style={{ color: ind.severity === "red" ? "#ef4060" : "#f5a623" }}
                        />
                        <div>
                          <span
                            className="text-[11px] font-bold"
                            style={{ color: ind.severity === "red" ? "#ef4060" : "#f5a623" }}
                          >
                            {ind.label}
                          </span>
                          <p className="text-[11px] leading-relaxed text-zinc-500">{ind.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="divide-y divide-[var(--line)]">
                  {selected.forensics.fields.map((f, i) => {
                    const dot =
                      f.status === "bad" ? "#ef4060" : f.status === "warn" ? "#f5a623" : f.status === "ok" ? "var(--accent)" : "#52525b";
                    return (
                      <div key={i} className="flex items-start gap-3 px-4 py-2 text-[11px]">
                        {f.status ? (
                          <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" style={{ backgroundColor: dot }} />
                        ) : (
                          <span className="mt-1.5 h-1.5 w-1.5 shrink-0" />
                        )}
                        <span className="w-28 shrink-0 font-semibold text-zinc-500">{f.label}</span>
                        <span
                          className="min-w-0 flex-1 break-all font-mono"
                          style={{ color: f.status === "bad" ? "#ef4060" : f.status === "warn" ? "#f5a623" : "#a1a1aa" }}
                        >
                          {f.value}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </motion.section>

        {/* ZONE C — Result detail */}
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1], delay: 0.16 }}
          className="order-3 col-span-1 flex flex-col lg:col-span-3 lg:h-[calc(100vh-73px)] lg:overflow-y-auto"
        >
          <SectionLabel icon={ShieldAlert}>Verdict</SectionLabel>
          <div className="flex flex-col gap-4 px-4 py-4">
            <div
              className={`rounded-lg border-[1.5px] bg-[var(--panel)] px-4 py-4 ${
                tone === "critical" ? "border-[#ef4060]" : "border-[var(--line)]"
              }`}
              style={tone === "critical" ? { boxShadow: "3px 3px 0 0 #4a0a18" } : undefined}
            >
              <div className="flex items-center gap-2">
                {tone === "clear" ? (
                  <ShieldCheck className="h-4 w-4 text-[var(--accent)]" />
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
              <div className="rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
                <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  What to do
                </span>
                <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-300">{selected.recommendation}</p>
              </div>
            )}

            <div className="flex flex-col gap-3 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
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
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
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

            {selected && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
                <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  <Database className="h-3 w-3" />
                  Threat Intelligence
                  <span className="ml-auto font-mono text-[9px] font-normal normal-case tracking-normal text-zinc-600">
                    VirusTotal · urlscan.io
                  </span>
                </span>
                {selected.linkIntel && selected.linkIntel.length > 0 ? (
                  selected.linkIntel.map((li, i) => {
                    const flagged = li.vtMalicious > 0 || li.vtSuspicious > 0;
                    return (
                      <div key={i} className="flex items-center justify-between text-[11px]">
                        <span className="truncate font-mono text-zinc-400">{li.domain}</span>
                        <span className={`shrink-0 font-mono font-bold ${flagged ? "text-[#ef4060]" : "text-[var(--accent-bright)]"}`}>
                          {flagged ? `${li.vtMalicious + li.vtSuspicious} engines flagged` : "clean on VirusTotal"}
                        </span>
                      </div>
                    );
                  })
                ) : (
                  <p className="text-[11px] text-zinc-600">
                    No links found in this message to cross-check against threat databases.
                  </p>
                )}
              </div>
            )}

            {selected && selected.screenshot && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
                <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  <ImageIcon className="h-3 w-3" />
                  Sandboxed Page Preview
                </span>
                {/* Always attempt the image — urlscan renders it within ~15-20s, so it may not
                    be ready the instant the scan returns, but resolves shortly after (and on any
                    later view of this result). If it isn't up yet, show a fallback note. */}
                <img
                  // eslint-disable-next-line @next/next/no-img-element -- external, unpredictable urlscan.io image
                  src={selected.screenshot.screenshotUrl}
                  alt="Sandboxed screenshot of the linked page"
                  className="w-full rounded border-[1.5px] border-[var(--line)]"
                  onError={(e) => {
                    const img = e.currentTarget;
                    img.style.display = "none";
                    const note = img.nextElementSibling as HTMLElement | null;
                    if (note) note.style.display = "block";
                  }}
                />
                <p className="hidden text-[11px] text-zinc-600">
                  Still rendering on urlscan.io — open the full report below, it&apos;ll be ready in a few seconds.
                </p>
                <a
                  href={selected.screenshot.resultUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[10px] font-semibold text-zinc-500 hover:text-[var(--accent-bright)]"
                >
                  <ExternalLink className="h-3 w-3" />
                  Full urlscan.io report
                </a>
              </div>
            )}

            {selected && selected.attachmentIntel && selected.attachmentIntel.length > 0 && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
                <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  <Paperclip className="h-3 w-3" />
                  Attachment Scan
                </span>
                {selected.attachmentIntel.map((a, i) => {
                  const malicious = a.vtMalicious > 0;
                  return (
                    <div key={i} className="flex items-center justify-between text-[11px]">
                      <span className="truncate font-mono text-zinc-400">{a.filename}</span>
                      <span className={`shrink-0 font-mono font-bold ${malicious ? "text-[#ef4060]" : "text-[var(--accent-bright)]"}`}>
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
                onClick={() => handleDisconnect(gmailConnection._id, "Google (Gmail + Drive)")}
                className="flex items-center justify-center gap-1.5 rounded-md border-[1.5px] border-[var(--line)] px-3 py-2 text-[10px] font-bold uppercase tracking-wide text-zinc-500 hover:border-[#ef4060] hover:text-[#ef4060]"
              >
                <Trash2 className="h-3 w-3" />
                Revoke Gmail Access
              </button>
            )}
          </div>
        </motion.section>
      </main>
    </div>
  );
}
