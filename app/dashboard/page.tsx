"use client";

import { Suspense, useEffect, useRef, useState, useSyncExternalStore } from "react";
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
  ExternalLink,
  Image as ImageIcon,
  Paperclip,
  Database,
  MessagesSquare,
  MessageCircle,
  Send,
  Camera,
  Smartphone,
  CheckCircle2,
  LockKeyhole,
  WandSparkles,
  X,
  Moon,
  Sun,
  PanelLeftClose,
  PanelLeftOpen,
  Search,
  Plus,
  ArrowDownUp,
  Sparkles,
  Zap,
  ChevronDown,
  Home,
  Settings2,
  FileText,
  Link2,
  Upload,
  Copy,
  Download,
  Share2,
  RotateCcw,
  ThumbsDown,
  Check,
} from "lucide-react";
import { BarChart3 } from "lucide-react";
import { api } from "@/convex/_generated/api";
import { useOwnerId } from "@/lib/useOwnerId";
import { useAppearance } from "@/lib/useTheme";
import { buildHighlightSegments } from "@/lib/highlight";

type Verdict = "safe" | "suspicious" | "scam";
type Tone = "clear" | "warn" | "critical";
type ScanFilter = "all" | Verdict;
type SourceFilter = "all" | ScanResultDoc["provider"];
type ScanSort = "newest" | "risk" | "confidence";
type InputMode = "message" | "email" | "link" | "file";

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

function friendlyVerdict(verdict: Verdict): string {
  if (verdict === "scam") return "Likely scam";
  if (verdict === "suspicious") return "Be careful";
  return "Looks safe";
}

function scamLikelihood(result: ScanResultDoc): number {
  return result.verdict === "safe" ? Math.max(0, 100 - result.confidence) : result.confidence;
}

function scanDayLabel(timestamp: number): string {
  const date = new Date(timestamp);
  const today = new Date();
  const yesterday = new Date();
  yesterday.setDate(today.getDate() - 1);

  if (date.toDateString() === today.toDateString()) return "Today";
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday";
  return date.toLocaleDateString([], { month: "short", day: "numeric", year: date.getFullYear() === today.getFullYear() ? undefined : "numeric" });
}

const SOURCE_LABELS: Record<ScanResultDoc["provider"], string> = {
  manual: "Manual",
  gmail: "Google",
  github: "GitHub",
};

const HISTORY_OPEN_KEY = "gf_history_open";
const HISTORY_OPEN_EVENT = "ghostfilter-history-open";

function subscribeHistoryOpen(callback: () => void) {
  window.addEventListener(HISTORY_OPEN_EVENT, callback);
  return () => window.removeEventListener(HISTORY_OPEN_EVENT, callback);
}

function getHistoryOpenSnapshot() {
  return localStorage.getItem(HISTORY_OPEN_KEY) !== "false";
}

function setStoredHistoryOpen(open: boolean) {
  localStorage.setItem(HISTORY_OPEN_KEY, String(open));
  window.dispatchEvent(new Event(HISTORY_OPEN_EVENT));
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

const INPUT_MODES = [
  { id: "message", label: "Message", icon: MessageCircle },
  { id: "email", label: "Email", icon: Mail },
  { id: "link", label: "Link", icon: Link2 },
  { id: "file", label: "File", icon: FileText },
] as const;

const MODE_COPY: Record<InputMode, { title: string; helper: string; placeholder: string }> = {
  message: {
    title: "Paste a message",
    helper: "Include the sender and any links if possible.",
    placeholder: "Paste an SMS, WhatsApp message, or direct message here…",
  },
  email: {
    title: "Paste an email",
    helper: "For the strongest check, include the sender, subject, body, and raw headers.",
    placeholder: "Paste the email here, including its subject and sender…",
  },
  link: {
    title: "Check a link",
    helper: "Paste the full address. GhostFilter checks it without opening it in your browser.",
    placeholder: "https://example.com/account-check",
  },
  file: {
    title: "Upload a file",
    helper: "Upload a screenshot, PDF, text file, or saved email. Maximum size: 8 MB.",
    placeholder: "",
  },
};

function detectInputMode(text: string): InputMode {
  const trimmed = text.trim();
  if (/^https?:\/\/\S+$/i.test(trimmed)) return "link";
  if (/^(from|to|subject|reply-to|return-path):/im.test(trimmed)) return "email";
  return "message";
}

function reportText(result: ScanResultDoc): string {
  const reasons = result.flaggedPhrases.length
    ? result.flaggedPhrases.map((item) => `- "${item.phrase}": ${item.reason}`).join("\n")
    : "- No specific phrases were highlighted.";
  return `GhostFilter scan report

Result: ${friendlyVerdict(result.verdict)}
Scam likelihood: ${Math.round(scamLikelihood(result))}%

Why:
${result.summary}

What to do:
${result.recommendation}

Phrases to notice:
${reasons}

Checked content:
${result.snippet}

Generated ${new Date().toLocaleString()}
GhostFilter results are guidance, not a guarantee.`;
}

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

function ThreatGauge({
  value,
  tone,
  scanning,
  hasResult,
}: {
  value: number;
  tone: Tone;
  scanning?: boolean;
  hasResult: boolean;
}) {
  const animated = useAnimatedNumber(value, 900);
  const toneColor = TONE_HEX[tone];
  const displayColor = hasResult || scanning ? toneColor : "var(--line-strong)";
  const riskLabel = !hasResult ? "Awaiting scan" : animated >= 70 ? "High risk" : animated >= 35 ? "Needs caution" : "Low risk";
  const riskCopy = !hasResult
    ? "Run a scan to see a clear risk score."
    : animated >= 70
      ? "Strong scam or phishing signals detected."
      : animated >= 35
        ? "Some patterns deserve a closer look."
        : "Few scam patterns were detected.";
  const boundedValue = Math.min(100, Math.max(0, animated));

  return (
    <motion.div
      className="risk-meter w-full overflow-hidden rounded-xl border border-[var(--line-strong)] bg-[var(--panel)]"
      animate={{ borderColor: displayColor }}
      transition={{ duration: 0.6 }}
    >
      <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-3">
        <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-zinc-500">
          Risk level
        </span>
        <span
          className="rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-wide"
          style={{ borderColor: displayColor, color: displayColor }}
        >
          {scanning ? "Checking" : riskLabel}
        </span>
      </div>
      <div className="grid gap-5 px-5 py-5 sm:grid-cols-[1fr_auto] sm:items-end">
        <div>
        {scanning ? (
          <motion.div
            className="flex h-[72px] items-center gap-3 font-mono text-2xl font-bold tracking-tight"
            style={{ color: displayColor }}
            animate={{ opacity: [0.4, 1, 0.4] }}
            transition={{ duration: 1.1, repeat: Infinity }}
          >
            <LoaderCircle className="h-7 w-7 animate-spin" />
            CHECKING
          </motion.div>
        ) : (
          <div
            className="font-mono text-[64px] font-bold leading-none tabular-nums tracking-[-0.08em] sm:text-[76px]"
            style={{ color: displayColor }}
          >
            {hasResult ? Math.round(animated) : "—"}
            {hasResult && <span className="ml-2 text-2xl tracking-normal text-zinc-500">%</span>}
          </div>
        )}
          <p className="mt-2 text-[12px] text-zinc-400">{scanning ? "Looking for pressure tactics, unsafe links, and identity clues…" : riskCopy}</p>
        </div>
        {tone === "clear" ? (
          <ShieldCheck className="hidden h-12 w-12 sm:block" style={{ color: displayColor }} />
        ) : (
          <ShieldAlert className="hidden h-12 w-12 sm:block" style={{ color: displayColor }} />
        )}
      </div>
      <div className="px-5 pb-5">
        <div className="relative h-3 overflow-hidden rounded-full bg-[var(--input)]">
          <div className="absolute inset-y-0 left-0 w-[35%] bg-[var(--safe)]" />
          <div className="absolute inset-y-0 left-[35%] w-[35%] bg-[var(--warn)]" />
          <div className="absolute inset-y-0 left-[70%] right-0 bg-[var(--danger)]" />
          {!scanning && hasResult && (
            <motion.span
              className="absolute top-1/2 h-5 w-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full border border-[var(--panel)] bg-[var(--text-primary)]"
              animate={{ left: `${boundedValue}%` }}
              transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            />
          )}
        </div>
        <div className="mt-2 flex justify-between font-mono text-[9px] font-bold uppercase tracking-wider text-zinc-500">
          <span>Low</span>
          <span>Caution</span>
          <span>High</span>
        </div>
      </div>
    </motion.div>
  );
}

// Mouse-tracking 3D tilt wrapper — subtle perspective without visual noise.
function TiltCard({ children, className }: { children: React.ReactNode; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const rawX = useMotionValue(0);
  const rawY = useMotionValue(0);
  const rotateX = useSpring(rawX, { stiffness: 200, damping: 20 });
  const rotateY = useSpring(rawY, { stiffness: 200, damping: 20 });

  function onMouseMove(event: React.MouseEvent<HTMLDivElement>) {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect) return;

    const pointerX = (event.clientX - rect.left) / rect.width - 0.5;
    const pointerY = (event.clientY - rect.top) / rect.height - 0.5;
    rawY.set(pointerX * 8);
    rawX.set(pointerY * -8);
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
  const [appearance, setAppearance] = useAppearance();
  return (
    <div>
      <button
        onClick={() => setAppearance(appearance === "dark" ? "light" : "dark")}
        aria-label={`Switch to ${appearance === "dark" ? "light" : "dark"} mode`}
        title={`Switch to ${appearance === "dark" ? "light" : "dark"} mode`}
        className="flex h-9 w-9 items-center justify-center rounded-md border border-[var(--line-strong)] bg-[var(--panel)] text-zinc-500 hover:border-[var(--accent)] hover:text-[var(--accent)]"
      >
        {appearance === "dark" ? <Sun className="h-3.5 w-3.5 text-[var(--warn)]" /> : <Moon className="h-3.5 w-3.5 text-[var(--info)]" />}
      </button>
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
  className = "",
}: {
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  trailing?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`flex items-center justify-between border-b-[1.5px] border-[var(--line)] bg-[var(--panel)] px-4 py-3 ${className}`}>
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
    if (banner) router.replace("/dashboard", { scroll: false });
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
  const analyzeUpload = useAction(api.pipeline.analyzeUpload);
  const scanInbox = useAction(api.gmail.scanInbox);
  const scanDrive = useAction(api.drive.scanDrive);
  const scanGithub = useAction(api.github.scanNotifications);
  const disconnect = useMutation(api.connections.disconnect);
  const removeScan = useMutation(api.scanResults.remove);
  const clearScans = useMutation(api.scanResults.clearForOwner);
  const submitFeedback = useMutation(api.scanResults.submitFeedback);

  const [messageText, setMessageText] = useState("");
  const [inputMode, setInputMode] = useState<InputMode>("message");
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [scanningKind, setScanningKind] = useState<"inbox" | "drive" | "github" | null>(null);
  const [scanDepth, setScanDepth] = useState(25);
  const [scanError, setScanError] = useState<string | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sourceHint, setSourceHint] = useState<string | null>(null);
  const historyOpen = useSyncExternalStore(subscribeHistoryOpen, getHistoryOpenSnapshot, () => true);
  const [historySearch, setHistorySearch] = useState("");
  const [historyFilter, setHistoryFilter] = useState<ScanFilter>("all");
  const [sourceFilter, setSourceFilter] = useState<SourceFilter>("all");
  const [scanSort, setScanSort] = useState<ScanSort>("newest");
  const [deepReviewOnly, setDeepReviewOnly] = useState(false);
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [feedbackSent, setFeedbackSent] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const gmailConnection = connections?.find((c) => c.provider === "gmail" && c.status === "connected");
  const githubConnection = connections?.find((c) => c.provider === "github" && c.status === "connected");
  const selected = scans?.find((s) => s._id === selectedId) ?? scans?.[0];
  const scanCounts = {
    all: scans?.length ?? 0,
    safe: scans?.filter((scan) => scan.verdict === "safe").length ?? 0,
    suspicious: scans?.filter((scan) => scan.verdict === "suspicious").length ?? 0,
    scam: scans?.filter((scan) => scan.verdict === "scam").length ?? 0,
  };
  const sourceCounts = {
    all: scans?.length ?? 0,
    manual: scans?.filter((scan) => scan.provider === "manual").length ?? 0,
    gmail: scans?.filter((scan) => scan.provider === "gmail").length ?? 0,
    github: scans?.filter((scan) => scan.provider === "github").length ?? 0,
  };
  const threatCount = scanCounts.scam + scanCounts.suspicious;
  const threatRate = scanCounts.all ? Math.round((threatCount / scanCounts.all) * 100) : 0;
  const averageRisk = scanCounts.all
    ? Math.round((scans ?? []).reduce((sum, scan) => sum + scamLikelihood(scan), 0) / scanCounts.all)
    : 0;
  const visibleScans = scans
    ?.filter((scan) => {
      const matchesFilter = historyFilter === "all" || scan.verdict === historyFilter;
      const matchesSource = sourceFilter === "all" || scan.provider === sourceFilter;
      const matchesReview = !deepReviewOnly || scan.aiReviewed;
      const query = historySearch.trim().toLowerCase();
      const matchesSearch =
        !query ||
        scan.subject?.toLowerCase().includes(query) ||
        scan.snippet.toLowerCase().includes(query) ||
        scan.provider.toLowerCase().includes(query);
      return matchesFilter && matchesSource && matchesReview && matchesSearch;
    })
    .sort((a, b) => {
      if (scanSort === "risk") return scamLikelihood(b) - scamLikelihood(a);
      if (scanSort === "confidence") return b.confidence - a.confidence;
      return b._creationTime - a._creationTime;
    });

  const selectResult = (id: string | null) => {
    setSelectedId(id);
    setFeedbackOpen(false);
    setFeedbackSent(false);
    setActionStatus(null);
  };

  const analyzeText = async (text: string) => {
    if (!ownerId || !text.trim() || analyzing) return;
    setAnalyzing(true);
    setAnalysisError(null);
    try {
      const result = await analyzeMessage({ text, ownerId });
      selectResult(result.id);
    } catch (err) {
      setAnalysisError(err instanceof Error ? err.message : "We couldn't analyze that message. Please try again.");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleAnalyze = async () => {
    if (inputMode !== "file") {
      await analyzeText(messageText);
      return;
    }
    if (!ownerId || !uploadedFile || analyzing) return;
    setAnalyzing(true);
    setAnalysisError(null);
    try {
      if (uploadedFile.size > 8 * 1024 * 1024) {
        throw new Error("That file is larger than 8 MB. Please upload a smaller file.");
      }

      if (
        uploadedFile.type.startsWith("text/") ||
        /\.(txt|eml)$/i.test(uploadedFile.name)
      ) {
        const text = await uploadedFile.text();
        if (!text.trim()) throw new Error("That file doesn't contain readable text.");
        setMessageText(text.slice(0, 20_000));
        const result = await analyzeMessage({
          text: `Uploaded file: ${uploadedFile.name}\n\n${text.slice(0, 20_000)}`,
          ownerId,
        });
        selectResult(result.id);
      } else {
        const base64 = await new Promise<string>((resolve, reject) => {
          const reader = new FileReader();
          reader.onload = () => {
            const value = String(reader.result ?? "");
            resolve(value.includes(",") ? value.split(",")[1] : value);
          };
          reader.onerror = () => reject(new Error("We couldn't read that file."));
          reader.readAsDataURL(uploadedFile);
        });
        const result = await analyzeUpload({
          ownerId,
          filename: uploadedFile.name,
          mimeType: uploadedFile.type || "application/octet-stream",
          base64,
        });
        setMessageText(result.extractedText);
        selectResult(result.id);
      }
    } catch (err) {
      setAnalysisError(err instanceof Error ? err.message : "We couldn't analyze that file.");
    } finally {
      setAnalyzing(false);
    }
  };

  const chooseMode = (mode: InputMode) => {
    setInputMode(mode);
    setSourceHint(null);
    setAnalysisError(null);
    setUploadedFile(null);
    if (mode !== "file") window.setTimeout(() => textareaRef.current?.focus(), 0);
  };

  const pickChannel = (label: string) => {
    setInputMode("message");
    setSourceHint(label);
    textareaRef.current?.focus();
    textareaRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const startNewScan = () => {
    setMessageText("");
    setInputMode("message");
    setUploadedFile(null);
    setSourceHint(null);
    setAnalysisError(null);
    setActionStatus(null);
    setFeedbackOpen(false);
    setFeedbackSent(false);
    textareaRef.current?.focus();
    textareaRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const toggleHistory = () => {
    setStoredHistoryOpen(!historyOpen);
  };

  const clearHistoryFilters = () => {
    setHistorySearch("");
    setHistoryFilter("all");
    setSourceFilter("all");
    setDeepReviewOnly(false);
    setScanSort("newest");
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

  const handleDeleteSelected = async () => {
    if (!ownerId || !selected) return;
    const ok = window.confirm("Delete this scan from your history?");
    if (!ok) return;
    await removeScan({ ownerId, scanResultId: selected._id as never });
    selectResult(null);
    setActionStatus("Scan deleted");
  };

  const handleClearHistory = async () => {
    if (!ownerId || !scans?.length) return;
    const ok = window.confirm(`Delete all ${scans.length} scans? This cannot be undone.`);
    if (!ok) return;
    await clearScans({ ownerId });
    selectResult(null);
    setActionStatus("History cleared");
  };

  const copyReport = async () => {
    if (!selected) return;
    await navigator.clipboard.writeText(reportText(selected));
    setActionStatus("Report copied");
  };

  const downloadReport = () => {
    if (!selected) return;
    const blob = new Blob([reportText(selected)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ghostfilter-report-${new Date(selected._creationTime).toISOString().slice(0, 10)}.txt`;
    link.click();
    URL.revokeObjectURL(url);
    setActionStatus("Report downloaded");
  };

  const shareReport = async () => {
    if (!selected) return;
    const text = reportText(selected);
    if (navigator.share) {
      await navigator.share({ title: "GhostFilter scan report", text });
      setActionStatus("Report shared");
    } else {
      await navigator.clipboard.writeText(text);
      setActionStatus("Sharing isn't available here, so the report was copied");
    }
  };

  const rescanSelected = () => {
    if (!selected) return;
    setInputMode(detectInputMode(selected.snippet));
    setMessageText(selected.snippet.replace(/^Uploaded file: .+\n\n/, ""));
    setUploadedFile(null);
    setAnalysisError(null);
    textareaRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const sendFeedback = async (expectedVerdict: Verdict) => {
    if (!ownerId || !selected) return;
    await submitFeedback({
      ownerId,
      scanResultId: selected._id as never,
      expectedVerdict,
    });
    setFeedbackSent(true);
    setActionStatus("Thanks — your correction was saved");
  };

  const tone = selected ? verdictTone(selected.verdict) : "clear";
  const gaugeValue = selected ? scamLikelihood(selected) : 0;
  const segments = selected ? buildHighlightSegments(selected.snippet, selected.flaggedPhrases) : [];

  return (
    <div className="dashboard-page min-h-screen w-full bg-[var(--ink)] text-zinc-300">
      <header className="relative z-10 flex min-h-[68px] flex-col gap-2 border-b border-[var(--line)] bg-[var(--ink)] px-5 py-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <GhostMark />
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-[16px] tracking-tight text-zinc-50">
                <span className="font-bold">Ghost</span>
                <span className="font-light text-zinc-400">Filter</span>
                <span className="ml-1 align-top text-[9px] font-bold text-[var(--accent)]">AI</span>
              </h1>
            </div>
            <p className="text-[11px] text-zinc-500">
              Check a message before you trust it.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Suspense fallback={null}>
            <ConnectBanner />
          </Suspense>
          <ThemeSwitcher />
          <Link
            href="/"
            aria-label="Back to home"
            className="flex h-9 w-9 items-center justify-center rounded-md border border-[var(--line-strong)] bg-[var(--panel)] text-zinc-500 hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <Home className="h-4 w-4" />
          </Link>
          <Link
            href="/profile"
            className="flex h-9 items-center gap-1.5 rounded-md border border-[var(--line-strong)] bg-[var(--panel)] px-3 text-[11px] font-semibold text-zinc-400 hover:border-[var(--accent)] hover:text-[var(--accent)]"
          >
            <BarChart3 className="h-3.5 w-3.5" />
            History insights
          </Link>
        </div>
      </header>

      <main className="relative z-10 grid grid-cols-1 lg:grid-cols-12">
        {/* ZONE A — Recent Scans */}
        <motion.section
          id="recent-scans-sidebar"
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
          className={`order-2 col-span-1 flex flex-col border-b-[1.5px] border-[var(--line)] transition-[height] lg:order-1 lg:h-[calc(100vh-73px)] lg:border-b-0 lg:border-r-[1.5px] ${
            historyOpen ? "h-[430px] lg:col-span-3" : "h-[49px] lg:col-span-1"
          }`}
        >
          <SectionLabel
            icon={Inbox}
            trailing={
              <div className="flex items-center gap-2">
                {historyOpen && (
                  <span className="text-[10px] font-bold text-zinc-500">{scanCounts.all} scanned</span>
                )}
                <button
                  onClick={toggleHistory}
                  aria-expanded={historyOpen}
                  aria-controls="recent-scans-content"
                  aria-label={historyOpen ? "Collapse recent scans sidebar" : "Expand recent scans sidebar"}
                  title={historyOpen ? "Collapse recent scans" : "Expand recent scans"}
                  className="flex h-7 w-7 items-center justify-center rounded-md border border-[var(--line-strong)] bg-[var(--input)] text-zinc-400 hover:border-[var(--accent)] hover:text-[var(--accent-bright)]"
                >
                  {historyOpen ? <PanelLeftClose className="h-3.5 w-3.5" /> : <PanelLeftOpen className="h-3.5 w-3.5" />}
                </button>
              </div>
            }
            className={historyOpen ? "" : "lg:px-2"}
          >
            <span className={historyOpen ? "" : "lg:hidden"}>Scan history</span>
          </SectionLabel>
          <AnimatePresence initial={false}>
            {historyOpen && (
              <motion.div
                id="recent-scans-content"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex min-h-0 flex-1 flex-col"
              >
                {scanCounts.all > 0 && (
                  <div className="border-b border-[var(--line)] p-2.5">
                    <div className="mb-2 grid grid-cols-3 gap-1.5">
                      <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-2">
                        <span className="block font-mono text-lg font-bold text-zinc-100">{threatCount}</span>
                        <span className="text-[8px] font-bold uppercase tracking-wide text-zinc-500">Flagged</span>
                      </div>
                      <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-2">
                        <span className="block font-mono text-lg font-bold text-[var(--warn)]">{threatRate}%</span>
                        <span className="text-[8px] font-bold uppercase tracking-wide text-zinc-500">Flagged share</span>
                      </div>
                      <div className="rounded-md border border-[var(--line)] bg-[var(--panel)] p-2">
                        <span className="block font-mono text-lg font-bold text-[var(--info)]">{averageRisk}%</span>
                        <span className="text-[8px] font-bold uppercase tracking-wide text-zinc-500">Avg score</span>
                      </div>
                    </div>
                    <div className="relative">
                      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
                      <input
                        value={historySearch}
                        onChange={(event) => setHistorySearch(event.target.value)}
                        placeholder="Search scans…"
                        aria-label="Search recent scans"
                        className="h-9 w-full rounded-md border border-[var(--line)] bg-[var(--input)] pl-8 pr-3 text-[11px] text-zinc-200 placeholder:text-zinc-600 focus:border-[var(--accent)] focus:outline-none"
                      />
                    </div>
                    <div className="mt-2 grid grid-cols-4 gap-1" role="group" aria-label="Filter scans by verdict">
                      {(["all", "safe", "suspicious", "scam"] as const).map((filter) => (
                        <button
                          key={filter}
                          onClick={() => setHistoryFilter(filter)}
                          aria-pressed={historyFilter === filter}
                          className={`rounded border px-1 py-1.5 text-[8px] font-bold uppercase tracking-wide ${
                            historyFilter === filter
                              ? "border-[var(--accent)] bg-[var(--accent-dim)] text-[var(--accent-bright)]"
                              : "border-[var(--line)] text-zinc-500 hover:border-[var(--line-strong)] hover:text-zinc-300"
                          }`}
                        >
                          {filter}
                          <span className="ml-1 font-mono">{scanCounts[filter]}</span>
                        </button>
                      ))}
                    </div>
                    <div className="mt-2 flex gap-1 overflow-x-auto pb-0.5" role="group" aria-label="Filter scans by source">
                      {(["all", "manual", "gmail", "github"] as const).map((source) => (
                        <button
                          key={source}
                          onClick={() => setSourceFilter(source)}
                          aria-pressed={sourceFilter === source}
                          className={`shrink-0 rounded-full border px-2 py-1 text-[8px] font-bold uppercase tracking-wide ${
                            sourceFilter === source
                              ? "border-[var(--info)] bg-[var(--input)] text-[var(--info)]"
                              : "border-[var(--line)] text-zinc-500 hover:text-zinc-300"
                          }`}
                        >
                          {source === "all" ? "All sources" : SOURCE_LABELS[source]} {sourceCounts[source]}
                        </button>
                      ))}
                    </div>
                    <div className="mt-2 grid grid-cols-[1fr_auto] gap-1.5">
                      <label className="relative flex items-center">
                        <ArrowDownUp className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-zinc-600" />
                        <select
                          value={scanSort}
                          onChange={(event) => setScanSort(event.target.value as ScanSort)}
                          aria-label="Sort recent scans"
                          className="h-8 w-full appearance-none rounded-md border border-[var(--line)] bg-[var(--input)] pl-8 pr-2 text-[9px] font-bold uppercase tracking-wide text-zinc-400 focus:border-[var(--accent)] focus:outline-none"
                        >
                          <option value="newest">Newest first</option>
                          <option value="risk">Highest risk</option>
                          <option value="confidence">Confidence</option>
                        </select>
                      </label>
                      <button
                        onClick={() => setDeepReviewOnly((active) => !active)}
                        aria-pressed={deepReviewOnly}
                        title="Show scans that received a more detailed review"
                        className={`flex h-8 items-center gap-1 rounded-md border px-2 text-[8px] font-bold uppercase tracking-wide ${
                          deepReviewOnly
                            ? "border-[var(--violet)] bg-[var(--input)] text-[var(--violet)]"
                            : "border-[var(--line)] text-zinc-500 hover:text-zinc-300"
                        }`}
                      >
                        <Sparkles className="h-3 w-3" />
                        Detailed
                      </button>
                    </div>
                    <button
                      onClick={startNewScan}
                      className="mt-2 flex w-full items-center justify-center gap-1.5 rounded-md border border-[var(--line-strong)] bg-[var(--panel)] py-2 text-[10px] font-bold uppercase tracking-wide text-zinc-400 hover:border-[var(--accent)] hover:text-[var(--accent-bright)]"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      Check another message
                    </button>
                    <button
                      onClick={handleClearHistory}
                      className="mt-1.5 flex w-full items-center justify-center gap-1.5 rounded-md py-1.5 text-[9px] font-bold uppercase tracking-wide text-zinc-600 hover:text-[var(--danger)]"
                    >
                      <Trash2 className="h-3 w-3" />
                      Clear scan history
                    </button>
                  </div>
                )}
                <div className="flex-1 overflow-y-auto px-2 py-2">
                  {!scans?.length && (
                    <div className="mx-1 mt-1 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] p-4">
                      <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-[var(--accent-bright)]">
                        Your first scan
                      </span>
                      <p className="mt-2 text-[13px] font-semibold leading-snug text-zinc-200">
                        Paste anything that feels off. GhostFilter turns it into a clear next step.
                      </p>
                      <div className="mt-4 flex flex-col gap-3">
                        {[
                          ["1", "Paste the message"],
                          ["2", "Review the risk signals"],
                          ["3", "Follow the safe action"],
                        ].map(([step, label]) => (
                          <div key={step} className="flex items-center gap-2.5 text-[11px] text-zinc-400">
                            <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-[var(--line-strong)] bg-[var(--input)] font-mono text-[10px] font-bold text-[var(--accent-bright)]">
                              {step}
                            </span>
                            {label}
                          </div>
                        ))}
                      </div>
                      <div className="mt-4 flex items-start gap-2 border-t border-[var(--line)] pt-3 text-[10px] leading-relaxed text-zinc-500">
                        <LockKeyhole className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
                        Pasted text is analyzed for you. Connected accounts remain read-only.
                      </div>
                    </div>
                  )}
                  {!!scans?.length && !visibleScans?.length && (
                    <div className="px-3 py-8 text-center">
                      <Search className="mx-auto h-5 w-5 text-zinc-700" />
                      <p className="mt-2 text-[11px] text-zinc-500">No scans match this search.</p>
                      <button
                        onClick={clearHistoryFilters}
                        className="mt-2 text-[10px] font-bold text-[var(--accent-bright)] hover:underline"
                      >
                        Clear filters
                      </button>
                    </div>
                  )}
                  <AnimatePresence initial={false}>
                    {visibleScans?.map((s, index) => {
                      const t = verdictTone(s.verdict);
                      const isSelected = selected?._id === s._id;
                      const dayLabel = scanDayLabel(s._creationTime);
                      const showDayLabel = index === 0 || scanDayLabel(visibleScans[index - 1]._creationTime) !== dayLabel;
                      return (
                        <motion.div key={s._id} layout initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
                          {showDayLabel && (
                            <div className="mb-1.5 mt-2 flex items-center gap-2 px-1 first:mt-0">
                              <span className="text-[8px] font-bold uppercase tracking-[0.16em] text-zinc-600">{dayLabel}</span>
                              <span className="h-px flex-1 bg-[var(--line)]" />
                            </div>
                          )}
                          <button
                            onClick={() => selectResult(s._id)}
                            aria-pressed={isSelected}
                            className={`mb-1.5 flex w-full items-start gap-2.5 rounded-md border-l-[3px] bg-[var(--panel)] px-2.5 py-2 text-left text-[11px] hover:bg-[#181820] ${
                              TONE_BORDER[t]
                            } ${isSelected ? "ring-1 ring-[var(--line-strong)] bg-[var(--input)]" : ""}`}
                          >
                            <div className="flex min-w-0 flex-1 flex-col">
                              <span className="truncate font-mono text-zinc-300">
                                {s.subject || s.snippet}
                              </span>
                              <span className="mt-1 flex items-center gap-1.5 font-mono text-[9px] text-zinc-600">
                                <span>{SOURCE_LABELS[s.provider]}</span>
                                <span>·</span>
                                <span>{new Date(s._creationTime).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                                {s.aiReviewed && (
                                  <>
                                    <span>·</span>
                                    <Sparkles className="h-2.5 w-2.5 text-[var(--violet)]" />
                                  </>
                                )}
                              </span>
                            </div>
                            <div className="flex shrink-0 flex-col items-end gap-1">
                              <span className={`font-mono text-[9px] font-bold ${TONE_TEXT[t]}`}>
                                {s.verdict.toUpperCase()}
                              </span>
                              <span className="flex items-center gap-0.5 font-mono text-[9px] text-zinc-500">
                                <Zap className="h-2.5 w-2.5" />
                                {Math.round(scamLikelihood(s))}%
                              </span>
                            </div>
                          </button>
                        </motion.div>
                      );
                    })}
                  </AnimatePresence>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.section>

        {/* ZONE B — Analyzer */}
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1], delay: 0.08 }}
          className={`order-1 col-span-1 flex flex-col border-b-[1.5px] border-[var(--line)] lg:order-2 lg:h-[calc(100vh-73px)] lg:overflow-y-auto lg:border-b-0 lg:border-r-[1.5px] ${
            historyOpen ? "lg:col-span-6" : "lg:col-span-8"
          }`}
        >
          <details className="group order-5 border-b border-[var(--line)] bg-[var(--panel)]">
            <summary className="flex cursor-pointer list-none items-center justify-between px-5 py-3.5">
              <span className="flex items-center gap-2">
                <Plug className="h-4 w-4 text-[var(--accent)]" />
                <span className="text-[12px] font-semibold text-zinc-300">Check connected sources</span>
                <span className="text-[10px] text-zinc-600">Optional</span>
              </span>
              <ChevronDown className="h-4 w-4 text-zinc-600 transition-transform group-open:rotate-180" />
            </summary>
          <div className="flex flex-wrap gap-2 border-t border-[var(--line)] px-5 py-4">
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
            <div className="flex flex-wrap items-center gap-2 border-t border-[var(--line)] px-5 py-3">
              <span className="text-[10px] font-semibold text-zinc-500">
                Items to check
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
              <span className="text-[10px] text-zinc-600">most recent</span>
            </div>
          )}
          {scanError && (
            <p className="border-t border-[var(--line)] bg-[#1a0c10] px-5 py-2 text-[11px] font-semibold text-[#ef4060]" role="alert">
              {scanError}
            </p>
          )}
          </details>

          {/* Channels that can't be auto-connected (no API to read personal messages) —
              honest manual-paste path instead of fake "connect" buttons. */}
          <div className="order-4 border-b border-[var(--line)] px-5 py-3">
            <p className="mb-2 text-[10px] leading-relaxed text-zinc-500">
              Pasting from a chat app? Choose it below to personalize the prompt.
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

          <div className="order-1 border-b border-[var(--line)] bg-[var(--panel)] px-5 py-5">
            <div className="flex items-start gap-3">
              <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border-[1.5px] border-[var(--accent)] bg-[var(--accent-dim)] text-[var(--accent-bright)]">
                <WandSparkles className="h-4 w-4" />
              </div>
              <div>
                <p className="text-[17px] font-semibold tracking-tight text-zinc-100">What would you like to check?</p>
                <p className="mt-1 text-[12px] leading-relaxed text-zinc-500">
                  Choose a format, then add exactly what you received. We’ll turn it into a clear next step.
                </p>
              </div>
            </div>
            <div className="mt-4 grid grid-cols-4 gap-1.5" role="tablist" aria-label="Type of content to check">
              {INPUT_MODES.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  role="tab"
                  aria-selected={inputMode === id}
                  onClick={() => chooseMode(id)}
                  className={`flex min-h-10 items-center justify-center gap-1.5 rounded-md border text-[10px] font-semibold ${
                    inputMode === id
                      ? "border-[var(--accent)] bg-[var(--accent-dim)] text-[var(--accent-bright)]"
                      : "border-[var(--line)] bg-[var(--input)] text-zinc-500 hover:border-[var(--line-strong)] hover:text-zinc-300"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="order-2">
          <SectionLabel icon={FileSearch}>
            {sourceHint ? `Paste from ${sourceHint}` : MODE_COPY[inputMode].title}
          </SectionLabel>
          <div className="flex flex-col gap-2.5 border-b-[1.5px] border-[var(--line)] px-5 py-4">
            {inputMode === "file" ? (
              <div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".txt,.eml,.pdf,image/png,image/jpeg,image/webp,image/heic,image/heif"
                  className="sr-only"
                  onChange={(event) => {
                    const file = event.target.files?.[0] ?? null;
                    setUploadedFile(file);
                    setAnalysisError(null);
                  }}
                />
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  className="flex min-h-[150px] w-full flex-col items-center justify-center rounded-lg border border-dashed border-[var(--line-strong)] bg-[var(--input)] px-5 text-center hover:border-[var(--accent)]"
                >
                  {uploadedFile ? (
                    <>
                      <FileText className="h-7 w-7 text-[var(--accent)]" />
                      <span className="mt-3 max-w-full truncate text-[13px] font-semibold text-zinc-200">
                        {uploadedFile.name}
                      </span>
                      <span className="mt-1 text-[10px] text-zinc-500">
                        {(uploadedFile.size / 1024).toFixed(0)} KB · Tap to choose another
                      </span>
                    </>
                  ) : (
                    <>
                      <Upload className="h-7 w-7 text-zinc-500" />
                      <span className="mt-3 text-[13px] font-semibold text-zinc-300">
                        Choose a screenshot, PDF, text file, or saved email
                      </span>
                      <span className="mt-1 text-[10px] text-zinc-500">
                        Images and PDFs are read securely before analysis
                      </span>
                    </>
                  )}
                </button>
              </div>
            ) : (
              <textarea
                ref={textareaRef}
                value={messageText}
                onChange={(event) => {
                  const value = event.target.value;
                  setMessageText(value);
                  if (value.trim()) setInputMode(detectInputMode(value));
                }}
                onKeyDown={(event) => {
                  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
                    event.preventDefault();
                    handleAnalyze();
                  }
                }}
                placeholder={
                  sourceHint ? `Paste the ${sourceHint} message here…` : MODE_COPY[inputMode].placeholder
                }
                rows={inputMode === "link" ? 3 : 5}
                aria-describedby="message-help"
                className="w-full resize-y rounded-md border-[1.5px] border-[var(--line)] bg-[var(--input)] px-3.5 py-3 text-[14px] leading-relaxed text-zinc-100 placeholder:text-zinc-600 focus:border-[var(--accent)] focus:outline-none focus:ring-2 focus:ring-[var(--accent)]/15"
              />
            )}
            <div className="flex items-start justify-between gap-3">
            <p id="message-help" className="text-[10px] leading-relaxed text-zinc-500">
              {MODE_COPY[inputMode].helper}
              {inputMode !== "file" && (
                <>
                  {" "}Press <span className="font-mono text-zinc-500">⌘/Ctrl + Enter</span> to check.
                </>
              )}
            </p>
              {inputMode !== "file" && (
                <span className="shrink-0 font-mono text-[10px] text-zinc-600">{messageText.length.toLocaleString()} chars</span>
              )}
            </div>
            {analysisError && (
              <div className="rounded-md border border-[#ef4060]/60 bg-[#1a0c10] px-3 py-2 text-[11px] text-[#ef4060]" role="alert">
                {analysisError}
              </div>
            )}
            <div className="flex flex-wrap items-center gap-1.5">
              {inputMode !== "file" && EXAMPLES.map((ex) => (
                  <button
                    key={ex.label}
                    onClick={() => {
                      setSourceHint(null);
                      setInputMode(detectInputMode(ex.text));
                      setMessageText(ex.text);
                    }}
                    disabled={analyzing}
                    className="rounded-full border-[1.5px] border-[var(--line)] px-2.5 py-1 text-[10px] font-semibold text-zinc-500 transition-colors hover:border-[var(--accent)] hover:text-[var(--accent-bright)] disabled:opacity-50"
                  >
                    {ex.label}
                  </button>
                ))}
              {(messageText || uploadedFile) && (
                <button
                  onClick={() => {
                    setMessageText("");
                    setUploadedFile(null);
                    setSourceHint(null);
                    setAnalysisError(null);
                    textareaRef.current?.focus();
                  }}
                  className="flex items-center gap-1 rounded-full px-2.5 py-1 text-[10px] font-semibold text-zinc-500 hover:text-zinc-200"
                >
                  <X className="h-3 w-3" />
                  Clear
                </button>
              )}
              <button
                onClick={handleAnalyze}
                disabled={(inputMode === "file" ? !uploadedFile : !messageText.trim()) || analyzing}
                className="ml-auto flex min-h-10 items-center gap-2 rounded-md border-[1.5px] border-[var(--accent)] bg-[var(--accent)] px-5 py-2 text-[12px] font-extrabold uppercase tracking-wide text-[var(--accent-ink)] transition-all hover:bg-[var(--accent-bright)] active:translate-x-[1.5px] active:translate-y-[1.5px] active:shadow-none disabled:cursor-not-allowed disabled:border-[var(--line)] disabled:bg-[#1a1a22] disabled:text-zinc-600"
                style={(inputMode === "file" ? !uploadedFile : !messageText.trim()) || analyzing ? undefined : { boxShadow: "2.5px 2.5px 0 0 #0a4a3a" }}
              >
                {analyzing ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}
                {analyzing ? "Checking" : inputMode === "file" ? "Check file" : "Check now"}
              </button>
            </div>
          </div>
          </div>

          <div className="order-3 flex flex-col items-center border-b border-[var(--line)] px-5 py-6" aria-live="polite">
            <TiltCard className="w-full [transform-style:preserve-3d]">
              <ThreatGauge value={gaugeValue} tone={tone} scanning={analyzing} hasResult={!!selected} />
            </TiltCard>
          </div>

          <div className="relative order-6 flex flex-1 flex-col px-5 py-4">
            <span className="pb-2 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
              Message we checked
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
              <details className="group mt-4 rounded-md border border-[var(--line)] bg-[var(--input)]">
                <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3">
                  <span className="flex items-center gap-2">
                  <FileSearch className="h-3.5 w-3.5 text-[var(--accent)]" />
                  <span className="text-[11px] font-semibold text-zinc-400">
                    Technical email checks
                  </span>
                  </span>
                  <ChevronDown className="h-4 w-4 text-zinc-600 transition-transform group-open:rotate-180" />
                </summary>

                {selected.forensics.indicators.length > 0 && (
                  <div className="flex flex-col gap-2 border-t border-b border-[var(--line)] px-4 py-3">
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
              </details>
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
          <SectionLabel icon={ShieldAlert}>Your result</SectionLabel>
          <div className="flex flex-col gap-4 px-4 py-4">
            <div
              className={`rounded-lg border-[1.5px] bg-[var(--panel)] px-4 py-4 ${
                tone === "critical" ? "border-[#ef4060]" : "border-[var(--line)]"
              }`}
            >
              <div className="flex items-center gap-2">
                {tone === "clear" ? (
                  <ShieldCheck className="h-4 w-4 text-[var(--accent)]" />
                ) : (
                  <ShieldAlert className={`h-4 w-4 ${TONE_TEXT[tone]}`} />
                )}
                <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">Overall result</span>
              </div>
              <div className={`mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight ${TONE_TEXT[tone]}`}>
                <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: TONE_HEX[tone] }} />
                {selected ? friendlyVerdict(selected.verdict) : "Waiting for a message"}
              </div>
              {selected && <p className="mt-2 text-[11px] leading-relaxed text-zinc-400">{selected.summary}</p>}
              {!selected && (
                <div className="mt-3 flex flex-col gap-2.5 border-t border-[var(--line)] pt-3">
                  {["A clear result", "The reasons behind it", "What to do next"].map((item) => (
                    <div key={item} className="flex items-center gap-2 text-[11px] text-zinc-400">
                      <CheckCircle2 className="h-3.5 w-3.5 text-[var(--accent)]" />
                      {item}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {selected && (
              <div className="rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
                <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  What you should do
                </span>
                <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-300">{selected.recommendation}</p>
              </div>
            )}

            {selected && (
              <div className="rounded-lg border border-[var(--line)] bg-[var(--panel)] p-3">
                <div className="grid grid-cols-4 gap-1.5">
                  <button onClick={copyReport} className="flex min-h-12 flex-col items-center justify-center gap-1 rounded-md border border-[var(--line)] bg-[var(--input)] text-[9px] font-semibold text-zinc-500 hover:border-[var(--accent)] hover:text-[var(--accent-bright)]">
                    <Copy className="h-3.5 w-3.5" />
                    Copy
                  </button>
                  <button onClick={downloadReport} className="flex min-h-12 flex-col items-center justify-center gap-1 rounded-md border border-[var(--line)] bg-[var(--input)] text-[9px] font-semibold text-zinc-500 hover:border-[var(--accent)] hover:text-[var(--accent-bright)]">
                    <Download className="h-3.5 w-3.5" />
                    Download
                  </button>
                  <button onClick={shareReport} className="flex min-h-12 flex-col items-center justify-center gap-1 rounded-md border border-[var(--line)] bg-[var(--input)] text-[9px] font-semibold text-zinc-500 hover:border-[var(--accent)] hover:text-[var(--accent-bright)]">
                    <Share2 className="h-3.5 w-3.5" />
                    Share
                  </button>
                  <button onClick={rescanSelected} className="flex min-h-12 flex-col items-center justify-center gap-1 rounded-md border border-[var(--line)] bg-[var(--input)] text-[9px] font-semibold text-zinc-500 hover:border-[var(--accent)] hover:text-[var(--accent-bright)]">
                    <RotateCcw className="h-3.5 w-3.5" />
                    Rescan
                  </button>
                </div>
                {actionStatus && (
                  <p className="mt-2 flex items-center gap-1.5 text-[10px] text-[var(--accent-bright)]" role="status">
                    <Check className="h-3 w-3" />
                    {actionStatus}
                  </p>
                )}
              </div>
            )}

            <details className="group rounded-lg border border-[var(--line)] bg-[var(--panel)]">
              <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3.5">
                <span className="flex items-center gap-2 text-[11px] font-semibold text-zinc-400">
                  <Settings2 className="h-4 w-4 text-zinc-500" />
                  Technical details
                </span>
                <ChevronDown className="h-4 w-4 text-zinc-600 transition-transform group-open:rotate-180" />
              </summary>
              <div className="flex flex-col gap-3 border-t border-[var(--line)] p-3">
            <div className="flex flex-col gap-3 rounded-lg border border-[var(--line)] bg-[var(--input)] px-3.5 py-3.5">
              <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                Why we gave this result
              </span>
              {selected ? (
                selected.signals.map((s) => <SignalBar key={s.label} label={s.label} value={s.value} />)
              ) : (
                <p className="text-[11px] text-zinc-600">Check a message to see the reasons behind the result.</p>
              )}
              {selected && !selected.aiReviewed && (
                <p className="text-[10px] text-zinc-600">
                  This result was clear enough that an additional review was not needed.
                </p>
              )}
            </div>

            {selected && selected.flaggedPhrases.length > 0 && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
                <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  Phrases to notice
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
                  Link safety checks
                  <span className="ml-auto font-mono text-[9px] font-normal normal-case tracking-normal text-zinc-600">
                    External safety databases
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
                    No links were found in this message.
                  </p>
                )}
              </div>
            )}

            {selected && selected.screenshot && (
              <div className="flex flex-col gap-2 rounded-lg border-[1.5px] border-[var(--line)] bg-[var(--panel)] px-3.5 py-3.5">
                <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.18em] text-zinc-500">
                  <ImageIcon className="h-3 w-3" />
                  Safe page preview
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
                  Attachment safety
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
              </div>
            </details>

            {selected && (
              <div className="rounded-lg border border-[var(--line)] bg-[var(--panel)] p-3.5">
                {feedbackSent ? (
                  <div className="flex items-start gap-2 text-[11px] text-zinc-400">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
                    <div>
                      <p className="font-semibold text-zinc-300">Correction saved</p>
                      <p className="mt-1 text-[10px] text-zinc-500">This helps improve future GhostFilter evaluations.</p>
                    </div>
                  </div>
                ) : feedbackOpen ? (
                  <div>
                    <p className="text-[11px] font-semibold text-zinc-300">What should the result have been?</p>
                    <div className="mt-2 grid grid-cols-3 gap-1.5">
                      {(["safe", "suspicious", "scam"] as const).map((verdict) => (
                        <button
                          key={verdict}
                          onClick={() => sendFeedback(verdict)}
                          className="rounded-md border border-[var(--line)] bg-[var(--input)] px-2 py-2 text-[9px] font-bold uppercase text-zinc-500 hover:border-[var(--accent)] hover:text-zinc-200"
                        >
                          {friendlyVerdict(verdict)}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  <button
                    onClick={() => setFeedbackOpen(true)}
                    className="flex w-full items-center justify-center gap-2 text-[10px] font-semibold text-zinc-500 hover:text-zinc-300"
                  >
                    <ThumbsDown className="h-3.5 w-3.5" />
                    Is this result wrong?
                  </button>
                )}
              </div>
            )}

            <div className="flex items-center gap-2 px-1 text-[10px] text-zinc-600">
              <ShieldCheck className="h-3 w-3" />
              <span>Automated checks provide guidance, not a guarantee.</span>
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
            {selected && (
              <button
                onClick={handleDeleteSelected}
                className="flex items-center justify-center gap-1.5 rounded-md px-3 py-2 text-[10px] font-semibold text-zinc-600 hover:bg-[var(--danger-soft)] hover:text-[var(--danger)]"
              >
                <Trash2 className="h-3 w-3" />
                Delete this scan
              </button>
            )}
          </div>
        </motion.section>
      </main>
    </div>
  );
}
