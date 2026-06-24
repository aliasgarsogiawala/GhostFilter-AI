"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowRight,
  Bot,
  BrainCircuit,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  Code2,
  FileCheck2,
  Link2,
  LockKeyhole,
  Mail,
  MessageSquareText,
  MessagesSquare,
  Moon,
  ScanLine,
  ShieldCheck,
  ShieldX,
  Smartphone,
  Sun,
  Upload,
} from "lucide-react";
import { useAppearance, useTheme } from "@/lib/useTheme";

const BENEFITS = [
  {
    icon: MessageSquareText,
    title: "Scam detection for people",
    copy: "Paste suspicious messages, emails, links, screenshots, or PDFs and get a clear verdict powered by classifier, rules, threat intel, and AI review.",
  },
  {
    icon: Bot,
    title: "Prompt-injection firewall for GhostGPT",
    copy: "Detect instruction overrides, jailbreaks, secret-extraction attempts, and unsafe tool-use requests before content reaches an AI agent.",
  },
  {
    icon: Link2,
    title: "Safe context handoff",
    copy: "Generate a sanitized wrapper so GhostGPT treats external content as untrusted data, not instructions.",
  },
] as const;

const AI_LAYERS = [
  {
    icon: BrainCircuit,
    title: "ML ensemble",
    copy: "A local classifier is combined with behavioral scam signals like payment intent, impersonation, urgency, and secret-code requests.",
  },
  {
    icon: ShieldX,
    title: "Agent firewall",
    copy: "GhostGPT content gets pass, isolate, or block decisions plus a safe context wrapper for untrusted data.",
  },
  {
    icon: ScanLine,
    title: "Deep review",
    copy: "High-risk items escalate to structured AI review, while link reputation and email forensics add external evidence.",
  },
] as const;

const FAQS = [
  {
    question: "What can I check with GhostFilter?",
    answer:
      "You can paste a text message, email, direct message, link, or AI-agent context. You can also upload screenshots, PDFs, text files, and saved .eml emails.",
  },
  {
    question: "How does GhostFilter protect GhostGPT?",
    answer:
      "GhostFilter scans untrusted content before it reaches GhostGPT. If it finds prompt injection, secret extraction, jailbreak, or tool-abuse attempts, it recommends pass, isolate, or block, saves the firewall run, and can generate a safe context wrapper.",
  },
  {
    question: "Where is the AI/ML part?",
    answer:
      "Scam Shield uses a trained local classifier, deterministic social-engineering signals, link intelligence, email forensics, and selective AI review. GhostGPT Firewall adds a separate prompt-injection and tool-abuse detector.",
  },
  {
    question: "Does GhostFilter open suspicious links?",
    answer:
      "No. Links are inspected from the server using redirect checks and external threat-intelligence services, so you do not need to open them in your own browser.",
  },
  {
    question: "Can GhostFilter guarantee that a message is safe?",
    answer:
      "No automated checker can guarantee that. GhostFilter explains the evidence it found and gives you a safer next step, but you should still verify unexpected requests through an official channel.",
  },
  {
    question: "Do I need to create an account?",
    answer:
      "No. You can use the scanner immediately. Scan history is tied to this browser unless a connected source is used.",
  },
  {
    question: "What happens when I connect Gmail, Drive, or GitHub?",
    answer:
      "GhostFilter receives read-only access for scanning. It cannot send messages, edit files, delete content, or act on your behalf.",
  },
  {
    question: "What should I do after a high-risk result?",
    answer:
      "Do not click, reply, pay, or share a code. Contact the person or organization through a separate method you already trust, such as its official app, website, or phone number.",
  },
] as const;

const LANDING_CONNECTIONS = [
  { icon: Mail, label: "Gmail", status: "Live" },
  { icon: FileCheck2, label: "Drive", status: "Live" },
  { icon: Code2, label: "GitHub", status: "Live" },
  { icon: Mail, label: "Outlook", status: "Next" },
  { icon: MessagesSquare, label: "Slack", status: "Next" },
  { icon: Smartphone, label: "SMS", status: "Paste" },
  { icon: MessageSquareText, label: "WhatsApp", status: "Paste" },
  { icon: Upload, label: "PDF / Image", status: "Live" },
] as const;

function BrandMark({ splash = false }: { splash?: boolean }) {
  return (
    <div
      className={`flex items-center justify-center rounded-md border border-[var(--accent)] bg-[var(--panel)] ${
        splash ? "h-14 w-14" : "h-9 w-9"
      }`}
    >
      <svg viewBox="0 0 24 24" className={splash ? "h-8 w-8" : "h-5 w-5"} fill="none" aria-hidden="true">
        <path
          d="M12 2.5 19.5 5.5V11c0 4.8-3.3 8.2-7.5 10.5C7.8 19.2 4.5 15.8 4.5 11V5.5Z"
          stroke="var(--accent)"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path d="M7.5 9.25h9M9 13.25h6" stroke="var(--accent)" strokeWidth="1.5" strokeLinecap="round" />
      </svg>
    </div>
  );
}

function SplashScreen() {
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const timer = window.setTimeout(() => setVisible(false), 1150);
    return () => window.clearTimeout(timer);
  }, []);

  if (!visible) return null;

  return (
    <div className="landing-splash" aria-hidden="true">
      <div className="landing-splash-emblem">
        <BrandMark splash />
        <span className="landing-splash-line" />
      </div>
      <p className="mt-5 text-xl font-semibold tracking-tight text-zinc-100">
        Ghost<span className="font-normal text-zinc-400">Filter</span>
      </p>
      <p className="mt-2 text-[10px] font-medium tracking-[0.18em] text-zinc-500">
        CHECKING SIGNALS
      </p>
    </div>
  );
}

function AppearanceToggle() {
  const [appearance, setAppearance] = useAppearance();
  useTheme();

  return (
    <button
      onClick={() => setAppearance(appearance === "dark" ? "light" : "dark")}
      aria-label={`Switch to ${appearance === "dark" ? "light" : "dark"} mode`}
      className="flex h-9 w-9 items-center justify-center rounded-md border border-[var(--line-strong)] bg-[var(--panel)] text-zinc-500 transition-colors hover:border-[var(--accent)] hover:text-[var(--accent)]"
    >
      {appearance === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}

function ExampleResult() {
  return (
    <div className="landing-tilt-card overflow-hidden rounded-xl border border-[var(--line-strong)] bg-[var(--panel)]">
      <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
        <div>
          <p className="text-[11px] font-semibold text-zinc-300">Example result</p>
          <p className="mt-0.5 text-[10px] text-zinc-600">A suspicious account-verification message</p>
        </div>
        <span className="rounded-full bg-[var(--danger-soft)] px-2.5 py-1 text-[9px] font-bold text-[var(--danger)]">
          HIGH RISK
        </span>
      </div>

      <div className="p-5 sm:p-6">
        <div className="flex items-end justify-between gap-5">
          <div>
            <p className="text-[10px] font-medium uppercase tracking-[0.12em] text-zinc-600">Scam likelihood</p>
            <p className="mt-2 font-mono text-5xl font-semibold tracking-[-0.06em] text-[var(--danger)]">
              92<span className="ml-1 text-lg tracking-normal">%</span>
            </p>
          </div>
          <CircleAlert className="h-8 w-8 text-[var(--danger)]" />
        </div>

        <div className="mt-6 rounded-lg border border-[var(--line)] bg-[var(--input)] p-4">
          <p className="text-[10px] font-medium uppercase tracking-[0.12em] text-zinc-600">Message excerpt</p>
          <p className="mt-2 text-[12px] leading-6 text-zinc-400">
            Your account has been <span className="font-semibold text-[var(--warn)]">suspended</span>. Verify your
            password <span className="font-semibold text-[var(--danger)]">immediately</span> using the link below.
          </p>
        </div>

        <div className="mt-5 divide-y divide-[var(--line)] border-y border-[var(--line)]">
          {[
            ["Urgent account threat", "Critical"],
            ["Password requested", "Critical"],
            ["Unrecognized domain", "Review"],
          ].map(([label, status]) => (
            <div key={label} className="flex items-center justify-between py-3 text-[11px]">
              <span className="text-zinc-400">{label}</span>
              <span className={status === "Critical" ? "text-[var(--danger)]" : "text-[var(--warn)]"}>{status}</span>
            </div>
          ))}
        </div>

        <div className="mt-5 flex items-start gap-3 rounded-lg bg-[var(--accent-dim)] p-4">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
          <div>
            <p className="text-[11px] font-semibold text-zinc-300">Recommended action</p>
            <p className="mt-1 text-[10px] leading-5 text-zinc-500">
              Do not use the link. Open the official service directly and check your account there.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function LandingPage() {
  return (
    <div className="landing-page min-h-screen bg-[var(--ink)] text-zinc-300">
      <SplashScreen />

      <header className="fixed left-0 top-0 z-50 w-full border-b border-[var(--line)] bg-[var(--ink)]">
        <div className="mx-auto flex h-[68px] max-w-6xl items-center justify-between px-5 lg:px-8">
          <Link href="/" className="flex items-center gap-2.5" aria-label="GhostFilter home">
            <BrandMark />
            <p className="text-[16px] font-semibold tracking-tight text-zinc-100">
              Ghost<span className="font-normal text-zinc-400">Filter</span>
            </p>
          </Link>

          <nav className="flex items-center gap-2" aria-label="Main navigation">
            <a href="#product" className="hidden px-3 py-2 text-[11px] font-medium text-zinc-500 hover:text-zinc-200 sm:block">
              Product
            </a>
            <Link href="/demo" className="hidden px-3 py-2 text-[11px] font-medium text-zinc-500 hover:text-zinc-200 md:block">
              Demo
            </Link>
            <Link href="/eval" className="hidden px-3 py-2 text-[11px] font-medium text-zinc-500 hover:text-zinc-200 md:block">
              Eval
            </Link>
            <a href="#privacy" className="hidden px-3 py-2 text-[11px] font-medium text-zinc-500 hover:text-zinc-200 md:block">
              Privacy
            </a>
            <a href="#faq" className="hidden px-3 py-2 text-[11px] font-medium text-zinc-500 hover:text-zinc-200 lg:block">
              FAQ
            </a>
            <AppearanceToggle />
            <Link
              href="/dashboard"
              className="flex h-9 items-center gap-2 rounded-md bg-[var(--accent)] px-4 text-[11px] font-semibold text-[var(--accent-ink)] transition-colors hover:bg-[var(--accent-bright)]"
            >
              Open scanner
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </nav>
        </div>
      </header>

      <main className="pt-[68px]">
        <section className="border-b border-[var(--line)]">
          <div className="mx-auto grid max-w-6xl gap-12 px-5 py-14 lg:grid-cols-[.92fr_1.08fr] lg:items-center lg:px-8 lg:py-20">
            <div>
              <p className="flex items-center gap-2 text-[11px] font-medium text-[var(--accent)]">
                <ScanLine className="h-4 w-4" />
                Scam detection + AI agent firewall
              </p>
              <h1 className="mt-5 max-w-xl text-4xl font-semibold leading-[1.08] tracking-[-0.045em] text-zinc-100 sm:text-5xl lg:text-[58px]">
                Check the message before you trust it — or before GhostGPT reads it.
              </h1>
              <p className="mt-6 max-w-lg text-[15px] leading-7 text-zinc-400">
                GhostFilter protects people from scams and protects AI agents from prompt injection, jailbreaks, secret extraction, and unsafe tool-use instructions.
              </p>

              <div className="mt-8 flex flex-col gap-3 sm:flex-row">
                <Link
                  href="/dashboard"
                  className="flex min-h-11 items-center justify-center gap-2 rounded-md bg-[var(--accent)] px-5 text-[12px] font-semibold text-[var(--accent-ink)] hover:bg-[var(--accent-bright)]"
                >
                  Open protection console
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <a
                  href="#product"
                  className="flex min-h-11 items-center justify-center gap-2 rounded-md border border-[var(--line-strong)] bg-[var(--panel)] px-5 text-[12px] font-medium text-zinc-300 hover:border-[var(--text-secondary)]"
                >
                  How it works
                  <ChevronRight className="h-4 w-4" />
                </a>
              </div>

              <div className="mt-8 grid max-w-lg gap-2 sm:grid-cols-3">
                {["Scam shield", "GhostGPT firewall", "Safe context handoff"].map((item) => (
                  <span key={item} className="landing-mini-card flex items-center gap-2 rounded-lg border border-[var(--line)] bg-[var(--panel)] px-3 py-2 text-[10px] text-zinc-500">
                    <Check className="h-3.5 w-3.5 text-[var(--accent)]" />
                    {item}
                  </span>
                ))}
              </div>
            </div>

            <ExampleResult />
          </div>
        </section>

        <section id="product" className="border-b border-[var(--line)] bg-[var(--panel)]">
          <div className="mx-auto max-w-6xl px-5 py-14 lg:px-8 lg:py-18">
            <div className="grid gap-8 lg:grid-cols-[.75fr_1.25fr]">
              <div>
                <p className="text-[11px] font-medium text-[var(--accent)]">Two protection layers</p>
                <h2 className="mt-3 text-3xl font-semibold tracking-[-0.035em] text-zinc-100">
                  One scanner for humans. One firewall for AI agents.
                </h2>
                <p className="mt-4 max-w-md text-[13px] leading-6 text-zinc-500">
                  Scam detection catches social-engineering risk. GhostGPT protection catches prompt injection before untrusted content enters an AI agent context.
                </p>
              </div>

              <div className="divide-y divide-[var(--line)] border-y border-[var(--line)]">
                {BENEFITS.map(({ icon: Icon, title, copy }) => (
                  <div key={title} className="grid gap-3 py-5 sm:grid-cols-[36px_180px_1fr] sm:items-start">
                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-[var(--input)]">
                      <Icon className="h-4 w-4 text-[var(--accent)]" />
                    </div>
                    <h3 className="text-[13px] font-semibold text-zinc-300">{title}</h3>
                    <p className="text-[11px] leading-5 text-zinc-500">{copy}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="border-b border-[var(--line)]">
          <div className="mx-auto max-w-6xl px-5 py-12 lg:px-8">
            <div className="mb-7 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
              <div>
                <p className="text-[11px] font-medium text-[var(--accent)]">AI/ML safety engine</p>
                <h2 className="mt-3 max-w-xl text-3xl font-semibold tracking-[-0.035em] text-zinc-100">
                  More than one model. A layered decision system.
                </h2>
              </div>
              <p className="max-w-sm text-[11px] leading-6 text-zinc-500">
                The scanner explains which layer fired, so the result feels inspectable instead of magical.
              </p>
            </div>
            <div className="grid gap-3 lg:grid-cols-3">
              {AI_LAYERS.map(({ icon: Icon, title, copy }, index) => (
                <div key={title} className="landing-tilt-card rounded-xl border border-[var(--line-strong)] bg-[var(--panel)] p-5">
                  <div className="flex items-center justify-between">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[var(--accent)] bg-[var(--input)]">
                      <Icon className="h-4 w-4 text-[var(--accent)]" />
                    </div>
                    <span className="font-mono text-[10px] font-bold text-zinc-600">0{index + 1}</span>
                  </div>
                  <h3 className="mt-5 text-[15px] font-semibold text-zinc-200">{title}</h3>
                  <p className="mt-2 text-[11px] leading-6 text-zinc-500">{copy}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="border-b border-[var(--line)]">
          <div className="mx-auto max-w-6xl px-5 py-12 lg:px-8">
            <div className="mb-7 flex flex-col justify-between gap-3 sm:flex-row sm:items-end">
              <div>
                <p className="text-[11px] font-medium text-[var(--accent)]">Connections and scan lanes</p>
                <h2 className="mt-3 max-w-xl text-3xl font-semibold tracking-[-0.035em] text-zinc-100">
                  Built like a security command center, simple enough for anyone.
                </h2>
              </div>
              <p className="max-w-sm text-[11px] leading-6 text-zinc-500">
                Live connectors, upload scanning, and manual paste lanes make the product feel bigger without pretending browsers can read private chats automatically.
              </p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              {LANDING_CONNECTIONS.map(({ icon: Icon, label, status }) => (
                <div key={label} className="landing-connection-card rounded-xl border border-[var(--line-strong)] bg-[var(--panel)] p-4">
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[var(--accent)] bg-[var(--input)] text-[var(--accent)]">
                      <Icon className="h-4 w-4" />
                    </div>
                    <span className="rounded-full border border-[var(--line-strong)] px-2 py-1 text-[8px] font-bold uppercase tracking-wide text-zinc-500">
                      {status}
                    </span>
                  </div>
                  <p className="mt-4 text-[14px] font-semibold text-zinc-200">{label}</p>
                  <p className="mt-1 text-[10px] leading-5 text-zinc-500">
                    {status === "Live" ? "Available in the scanner." : status === "Paste" ? "Supported through manual paste." : "Roadmap integration slot."}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="privacy" className="border-b border-[var(--line)]">
          <div className="mx-auto grid max-w-6xl gap-8 px-5 py-14 lg:grid-cols-3 lg:px-8">
            <div className="lg:col-span-1">
              <LockKeyhole className="h-5 w-5 text-[var(--accent)]" />
              <h2 className="mt-4 text-2xl font-semibold tracking-[-0.025em] text-zinc-100">Designed to look, not touch.</h2>
            </div>
            <div className="grid gap-5 sm:grid-cols-3 lg:col-span-2">
              {[
                ["Read only", "Connected accounts cannot be used to send, edit, or delete messages."],
                ["Server-side tokens", "OAuth credentials are never exposed to the browser."],
                ["Your decision", "Results explain the evidence instead of pretending to be infallible."],
              ].map(([title, copy]) => (
                <div key={title} className="border-l border-[var(--line-strong)] pl-4">
                  <p className="text-[12px] font-semibold text-zinc-300">{title}</p>
                  <p className="mt-2 text-[10px] leading-5 text-zinc-500">{copy}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="faq" className="border-b border-[var(--line)] bg-[var(--panel)]">
          <div className="mx-auto grid max-w-6xl gap-9 px-5 py-14 lg:grid-cols-[.7fr_1.3fr] lg:px-8 lg:py-18">
            <div>
              <p className="text-[11px] font-medium text-[var(--accent)]">Frequently asked questions</p>
              <h2 className="mt-3 max-w-sm text-3xl font-semibold tracking-[-0.035em] text-zinc-100">
                Clear answers before you check anything.
              </h2>
              <p className="mt-4 max-w-sm text-[12px] leading-6 text-zinc-500">
                GhostFilter is designed to help you decide safely, without pretending automated analysis is perfect.
              </p>
            </div>
            <div className="divide-y divide-[var(--line)] border-y border-[var(--line)]">
              {FAQS.map(({ question, answer }) => (
                <details key={question} className="group">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-5 py-5 text-[13px] font-semibold text-zinc-300">
                    {question}
                    <ChevronDown className="h-4 w-4 shrink-0 text-zinc-600 transition-transform group-open:rotate-180" />
                  </summary>
                  <p className="max-w-2xl pb-5 pr-9 text-[11px] leading-6 text-zinc-500">{answer}</p>
                </details>
              ))}
            </div>
          </div>
        </section>

        <section>
          <div className="mx-auto flex max-w-6xl flex-col justify-between gap-6 px-5 py-12 sm:flex-row sm:items-center lg:px-8">
            <div>
              <h2 className="text-2xl font-semibold tracking-[-0.025em] text-zinc-100">Have a message that feels off?</h2>
              <p className="mt-2 text-[12px] text-zinc-500">Check it before you click, reply, pay, or share a code.</p>
            </div>
            <Link
              href="/dashboard"
              className="flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-md bg-[var(--accent)] px-5 text-[12px] font-semibold text-[var(--accent-ink)] hover:bg-[var(--accent-bright)]"
            >
              Open GhostFilter
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </section>
      </main>

      <footer className="border-t border-[var(--line)] bg-[var(--ink)]">
        <div className="mx-auto flex max-w-6xl flex-col justify-between gap-3 px-5 py-6 text-[10px] text-zinc-600 sm:flex-row sm:items-center lg:px-8">
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-3.5 w-3.5 text-[var(--accent)]" />
            GhostFilter AI · Beta
          </span>
          <span className="flex items-center gap-4">
            <span className="flex items-center gap-1.5"><Mail className="h-3 w-3" /> Gmail</span>
            <span className="flex items-center gap-1.5"><Code2 className="h-3 w-3" /> GitHub</span>
            <span className="flex items-center gap-1.5"><Upload className="h-3 w-3" /> Files</span>
          </span>
        </div>
      </footer>
    </div>
  );
}
