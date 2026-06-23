"use node";

import { v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { scoreMessage, ML_REVIEW_THRESHOLD } from "../lib/ml-classifier";
import { analyzeLinks, hostnameOf, type LinkFinding } from "../lib/heuristics";
import { reviewWithGemini, type GeminiVerdict } from "../lib/gemini";
import { detectPromptInjection, type InjectionFinding } from "../lib/promptInjection";
import { checkDomainReputation } from "../lib/virustotal";
import { scanAndCapture, type UrlscanResult } from "../lib/urlscan";

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
  injection: InjectionFinding
) {
  const urgencyHits = URGENCY_HINTS.filter((k) => lowerText.includes(k)).length;
  const lookalikeHit = links.some((l) => l.lookalike);
  const suspiciousLinkHit = links.some((l) => l.isShortened || l.lookalike || l.expanded?.blocked);
  const credentialHit = ["password", "ssn", "social security", "card number", "cvv", "pin"].some(
    (k) => lowerText.includes(k)
  );

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
  opts: { captureScreenshot?: boolean } = {}
): Promise<PipelineResult> {
  const captureScreenshot = opts.captureScreenshot ?? true;
  const mlScore = scoreMessage(text);
  const links = await analyzeLinks(text);
  const injection = detectPromptInjection(text);
  const hasHardHeuristicHit = links.some((l) => l.lookalike || l.expanded?.blocked) || injection.detected;
  const shouldEscalate = mlScore >= ML_REVIEW_THRESHOLD || hasHardHeuristicHit;
  const lowerText = text.toLowerCase();

  if (!shouldEscalate) {
    return {
      verdict: "safe",
      confidence: Math.round((1 - mlScore) * 100),
      mlScore,
      summary:
        "Our fast triage classifier and link checks didn't find meaningful scam signals in this message.",
      recommendation:
        "This looks fine, but stay cautious with any unexpected request for money, codes, or personal info.",
      flaggedPhrases: [],
      signals: baselineSignals(mlScore, links, lowerText, injection),
      aiReviewed: false,
      linkIntel: [],
      screenshot: null,
    };
  }

  // Kick these off now so they run concurrently with the Gemini call below,
  // instead of stacking latency on top of it.
  const intelPromise = gatherLinkIntel(links);
  const firstUrl = links[0]?.expanded?.finalUrl ?? links[0]?.url;
  const screenshotPromise =
    captureScreenshot && firstUrl ? scanAndCapture(firstUrl) : Promise.resolve(null);

  let ai: GeminiVerdict;
  try {
    ai = await reviewWithGemini(text, mlScore, links, injection);
  } catch (err) {
    // Gemini failed (missing key, rate limit, network) — degrade to a heuristic-only
    // verdict instead of crashing the whole analysis.
    const [linkIntel, screenshot] = await Promise.all([intelPromise, screenshotPromise]);
    return {
      verdict: injection.detected ? "scam" : hasHardHeuristicHit ? "suspicious" : mlScore >= 0.7 ? "scam" : "suspicious",
      confidence: Math.round(mlScore * 100),
      mlScore,
      summary: `AI review unavailable (${
        err instanceof Error ? err.message : "unknown error"
      }); showing triage-only result.`,
      recommendation: "Treat this message with caution and verify through an official channel before acting on it.",
      flaggedPhrases: [],
      signals: baselineSignals(mlScore, links, lowerText, injection),
      aiReviewed: false,
      linkIntel,
      screenshot,
    };
  }

  const [linkIntel, screenshot] = await Promise.all([intelPromise, screenshotPromise]);

  let signals = ai.signals.length ? ai.signals : baselineSignals(mlScore, links, lowerText, injection);
  let verdict = ai.verdict;
  if (hasHardHeuristicHit) {
    // Don't let the model silently downplay a confirmed heuristic hit.
    signals = signals.map((s) => {
      if (s.label === SIGNAL_LABELS[1] && links.some((l) => l.lookalike)) return { ...s, value: Math.max(s.value, 90) };
      if (s.label === SIGNAL_LABELS[5] && injection.detected) return { ...s, value: Math.max(s.value, 95) };
      return s;
    });
    if (injection.detected) verdict = "scam";
    else if (verdict === "safe") verdict = "suspicious";
  }

  return {
    verdict,
    confidence: ai.confidence,
    mlScore,
    summary: ai.summary,
    recommendation: ai.recommendation,
    flaggedPhrases: ai.flaggedPhrases,
    signals,
    aiReviewed: true,
    linkIntel,
    screenshot,
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
    });
    return { ...result, id };
  },
});
