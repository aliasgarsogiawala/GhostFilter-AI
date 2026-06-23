"use node";

import { v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { scoreMessage, ML_REVIEW_THRESHOLD } from "../lib/ml-classifier";
import { analyzeLinks, hostnameOf, type LinkFinding } from "../lib/heuristics";
import { reviewWithGemini, type GeminiVerdict } from "../lib/gemini";
import { detectPromptInjection, type InjectionFinding } from "../lib/promptInjection";
import {
  detectSocialEngineering,
  type SocialEngineeringFinding,
} from "../lib/socialEngineering";
import { checkDomainReputation } from "../lib/virustotal";
import { scanAndCapture, type UrlscanResult } from "../lib/urlscan";
import {
  looksLikeRawEmail,
  parseEmailForensics,
  type EmailForensics,
} from "../lib/emailHeaders";

const SIGNAL_LABELS = [
  "Urgency Language",
  "Spoofed/Lookalike Domain",
  "Suspicious Links",
  "Grammar/Spelling Anomalies",
  "Credential or Payment Request",
  "AI Manipulation Attempt",
] as const;

const URGENCY_HINTS = [
  "urgent",
  "immediately",
  "verify",
  "suspended",
  "act now",
  "limited time",
  "expire",
];

function baselineSignals(
  mlScore: number,
  links: LinkFinding[],
  lowerText: string,
  injection: InjectionFinding,
  socialEngineering?: SocialEngineeringFinding
) {
  const urgencyHits = URGENCY_HINTS.filter((k) => lowerText.includes(k)).length;
  const lookalikeHit = links.some((l) => l.lookalike);
  const suspiciousLinkHit = links.some((l) => l.isShortened || l.lookalike || l.expanded?.blocked);
  const credentialHit =
    ["password", "ssn", "social security", "card number", "cvv", "pin"].some((k) =>
      lowerText.includes(k)
    ) || socialEngineering?.paymentRequest;

  return [
    { label: SIGNAL_LABELS[0], value: Math.min(100, urgencyHits * 30) },
    { label: SIGNAL_LABELS[1], value: lookalikeHit ? 90 : 0 },
    { label: SIGNAL_LABELS[2], value: suspiciousLinkHit ? 75 : links.length ? 15 : 0 },
    { label: SIGNAL_LABELS[3], value: Math.round(mlScore * 40) },
    { label: SIGNAL_LABELS[4], value: credentialHit ? 70 : 0 },
    { label: SIGNAL_LABELS[5], value: injection.detected ? 95 : 0 },
  ];
}

export interface LinkIntel {
  url: string;
  domain: string;
  vtMalicious: number;
  vtSuspicious: number;
}

export interface PipelineResult {
  verdict: "safe" | "suspicious" | "scam";
  confidence: number;
  mlScore: number;
  summary: string;
  recommendation: string;
  flaggedPhrases: { phrase: string; reason: string; severity: "amber" | "red" }[];
  signals: { label: string; value: number }[];
  aiReviewed: boolean;
  linkIntel: LinkIntel[];
  screenshot: UrlscanResult | null;
  forensics: EmailForensics | null;
}

/** Checks domain reputation for up to the first 2 links — cheap, synchronous, no polling. */
async function gatherLinkIntel(links: LinkFinding[]): Promise<LinkIntel[]> {
  const targets = links.slice(0, 2);
  const results = await Promise.all(
    targets.map(async (l) => {
      const finalUrl = l.expanded?.finalUrl ?? l.url;
      const domain = hostnameOf(finalUrl);
      if (!domain) return null;
      const rep = await checkDomainReputation(domain);
      if (!rep) return null;
      return { url: finalUrl, domain, vtMalicious: rep.malicious, vtSuspicious: rep.suspicious };
    })
  );
  return results.filter((r): r is LinkIntel => r !== null);
}

/**
 * Shared analysis pipeline used by both the manual paste-a-message analyzer
 * and the connected-account (Gmail) scanner. ML triage runs on every message
 * (cheap, local, no network); Gemini is only called when the ML score crosses
 * ML_REVIEW_THRESHOLD or a deterministic heuristic already found something
 * concrete (lookalike domain, blocked link expansion) — caps AI cost.
 */
export async function runPipeline(
  text: string,
  opts: { captureScreenshot?: boolean; rawHeaders?: string } = {}
): Promise<PipelineResult> {
  const captureScreenshot = opts.captureScreenshot ?? true;
  const mlScore = scoreMessage(text);
  const links = await analyzeLinks(text);
  const injection = detectPromptInjection(text);
  const socialEngineering = detectSocialEngineering(text);
  const lowerText = text.toLowerCase();

  // Email header forensics: from Gmail-supplied raw headers, or auto-detected when a user
  // pastes a full raw email. Spoofing indicators (Reply-To / Return-Path / auth mismatches)
  // are strong, deterministic fraud signals.
  const forensics: EmailForensics | null = opts.rawHeaders
    ? parseEmailForensics(opts.rawHeaders)
    : looksLikeRawEmail(text)
    ? parseEmailForensics(text)
    : null;
  const forensicHardHit = !!forensics?.indicators.some((i) => i.severity === "red");

  // Threat-intel runs whenever the message has links — it's independent of the ML score, so
  // links get a real VirusTotal reputation check (and, for single manual scans, a urlscan.io
  // sandbox screenshot) even when the text itself looks benign. A VT-flagged link then forces
  // escalation to the AI reviewer.
  const firstUrl = links[0]?.expanded?.finalUrl ?? links[0]?.url;
  const intelPromise = links.length ? gatherLinkIntel(links) : Promise.resolve([] as LinkIntel[]);
  const screenshotPromise =
    captureScreenshot && firstUrl ? scanAndCapture(firstUrl) : Promise.resolve(null);

  const linkIntel = await intelPromise;
  const linkFlagged = linkIntel.some((li) => li.vtMalicious > 0 || li.vtSuspicious > 0);
  const hasHardHeuristicHit =
    links.some((l) => l.lookalike || l.expanded?.blocked) ||
    injection.detected ||
    socialEngineering.combinedImpersonationPayment ||
    linkFlagged ||
    forensicHardHit;
  const shouldEscalate =
    mlScore >= ML_REVIEW_THRESHOLD || hasHardHeuristicHit || socialEngineering.paymentRequest;

  if (!shouldEscalate) {
    const screenshot = await screenshotPromise;
    return {
      verdict: "safe",
      confidence: Math.round((1 - mlScore) * 100),
      mlScore,
      summary:
        "Our fast triage classifier and link checks didn't find meaningful scam signals in this message.",
      recommendation:
        "This looks fine, but stay cautious with any unexpected request for money, codes, or personal info.",
      flaggedPhrases: [],
      signals: baselineSignals(mlScore, links, lowerText, injection, socialEngineering),
      aiReviewed: false,
      linkIntel,
      screenshot,
      forensics,
    };
  }

  let ai: GeminiVerdict;
  try {
    ai = await reviewWithGemini(
      text,
      mlScore,
      links,
      injection,
      forensics?.indicators ?? [],
      socialEngineering
    );
  } catch {
    // Gemini failed (missing key, rate limit, network) — degrade to a heuristic-only
    // verdict instead of crashing the whole analysis.
    const screenshot = await screenshotPromise;
    // Without the AI reviewer we MUST NOT call something a "scam" off the SMS-trained
    // triage score alone — that's what flags legitimate newsletters. Only hard, corroborated
    // signals (prompt-injection or a threat-intel-flagged link) justify "scam" here; everything
    // else that was escalated is at most "suspicious".
    const fallbackVerdict: "suspicious" | "scam" =
      injection.detected ||
      socialEngineering.combinedImpersonationPayment ||
      linkFlagged ||
      forensicHardHit
        ? "scam"
        : "suspicious";
    return {
      verdict: fallbackVerdict,
      confidence: fallbackVerdict === "scam" ? Math.max(85, Math.round(mlScore * 100)) : 50,
      mlScore,
      summary:
        fallbackVerdict === "scam"
          ? "Concrete fraud indicators were found, but full AI review was temporarily unavailable — treat this as a scam."
          : "Our AI reviewer was temporarily unavailable, so this is a cautious triage-only result, not a confirmed scam. Re-run the analysis in a moment for a full verdict.",
      recommendation: "Don't act on any request for money, passwords, or codes until you've verified it through an official channel you trust.",
      flaggedPhrases: socialEngineering.combinedImpersonationPayment
        ? [
            {
              phrase: socialEngineering.identityPhrase ?? "claim to be the real person",
              reason: "The sender claims a trusted identity while asking for money.",
              severity: "red",
            },
          ]
        : [],
      signals: baselineSignals(mlScore, links, lowerText, injection, socialEngineering),
      aiReviewed: false,
      linkIntel,
      screenshot,
      forensics,
    };
  }

  const screenshot = await screenshotPromise;

  let signals = ai.signals.length
    ? ai.signals
    : baselineSignals(mlScore, links, lowerText, injection, socialEngineering);
  let verdict = ai.verdict;
  let confidence = ai.confidence;
  let summary = ai.summary;
  let recommendation = ai.recommendation;
  let flaggedPhrases = ai.flaggedPhrases;
  if (hasHardHeuristicHit) {
    // Don't let the model silently downplay a confirmed heuristic hit.
    signals = signals.map((s) => {
      if (s.label === SIGNAL_LABELS[1] && links.some((l) => l.lookalike)) return { ...s, value: Math.max(s.value, 90) };
      if (s.label === SIGNAL_LABELS[4] && socialEngineering.paymentRequest) {
        return { ...s, value: Math.max(s.value, 95) };
      }
      if (s.label === SIGNAL_LABELS[5] && injection.detected) return { ...s, value: Math.max(s.value, 95) };
      return s;
    });
    if (socialEngineering.combinedImpersonationPayment) {
      verdict = "scam";
      confidence = Math.max(confidence, 90);
      summary =
        "This message asks for money while claiming to be the real identity of another person, a strong impersonation-scam pattern.";
      recommendation =
        "Do not send money. Verify the person through a separate, trusted contact method.";
      if (
        socialEngineering.identityPhrase &&
        !flaggedPhrases.some((finding) => finding.phrase === socialEngineering.identityPhrase)
      ) {
        flaggedPhrases = [
          ...flaggedPhrases,
          {
            phrase: socialEngineering.identityPhrase,
            reason: "An unverified identity claim is paired with a request for money.",
            severity: "red",
          },
        ];
      }
    } else if (injection.detected) verdict = "scam";
    else if (verdict === "safe") verdict = "suspicious";
  }

  return {
    verdict,
    confidence,
    mlScore,
    summary,
    recommendation,
    flaggedPhrases,
    signals,
    aiReviewed: true,
    linkIntel,
    screenshot,
    forensics,
  };
}

export const analyzeMessage = action({
  args: { text: v.string(), ownerId: v.string() },
  handler: async (ctx, { text, ownerId }): Promise<PipelineResult & { id: string }> => {
    const result = await runPipeline(text);
    const id: string = await ctx.runMutation(internal.scanResults.insert, {
      ownerId,
      provider: "manual",
      snippet: text.slice(0, 4000),
      verdict: result.verdict,
      mlScore: result.mlScore,
      confidence: result.confidence,
      summary: result.summary,
      recommendation: result.recommendation,
      flaggedPhrases: result.flaggedPhrases,
      signals: result.signals,
      aiReviewed: result.aiReviewed,
      linkIntel: result.linkIntel,
      screenshot: result.screenshot ?? undefined,
      forensics: result.forensics ?? undefined,
    });
    return { ...result, id };
  },
});
