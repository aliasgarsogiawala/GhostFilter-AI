"use node";

import { v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { scoreMessage, ML_REVIEW_THRESHOLD } from "../lib/ml-classifier";
import { analyzeLinks, type LinkFinding } from "../lib/heuristics";
import { reviewWithGemini, type GeminiVerdict } from "../lib/gemini";

const SIGNAL_LABELS = [
  "Urgency Language",
  "Spoofed/Lookalike Domain",
  "Suspicious Links",
  "Grammar/Spelling Anomalies",
  "Credential or Payment Request",
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

function baselineSignals(mlScore: number, links: LinkFinding[], lowerText: string) {
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
  ];
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
}

/**
 * Shared analysis pipeline used by both the manual paste-a-message analyzer
 * and the connected-account (Gmail) scanner. ML triage runs on every message
 * (cheap, local, no network); Gemini is only called when the ML score crosses
 * ML_REVIEW_THRESHOLD or a deterministic heuristic already found something
 * concrete (lookalike domain, blocked link expansion) — caps AI cost.
 */
export async function runPipeline(text: string): Promise<PipelineResult> {
  const mlScore = scoreMessage(text);
  const links = await analyzeLinks(text);
  const hasHardHeuristicHit = links.some((l) => l.lookalike || l.expanded?.blocked);
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
      signals: baselineSignals(mlScore, links, lowerText),
      aiReviewed: false,
    };
  }

  let ai: GeminiVerdict;
  try {
    ai = await reviewWithGemini(text, mlScore, links);
  } catch (err) {
    // Gemini failed (missing key, rate limit, network) — degrade to a heuristic-only
    // verdict instead of crashing the whole analysis.
    return {
      verdict: hasHardHeuristicHit ? "suspicious" : mlScore >= 0.7 ? "scam" : "suspicious",
      confidence: Math.round(mlScore * 100),
      mlScore,
      summary: `AI review unavailable (${
        err instanceof Error ? err.message : "unknown error"
      }); showing triage-only result.`,
      recommendation: "Treat this message with caution and verify through an official channel before acting on it.",
      flaggedPhrases: [],
      signals: baselineSignals(mlScore, links, lowerText),
      aiReviewed: false,
    };
  }

  let signals = ai.signals.length ? ai.signals : baselineSignals(mlScore, links, lowerText);
  let verdict = ai.verdict;
  if (hasHardHeuristicHit) {
    // Don't let the model silently downplay a confirmed heuristic hit.
    signals = signals.map((s) =>
      s.label === SIGNAL_LABELS[1] ? { ...s, value: Math.max(s.value, 90) } : s
    );
    if (verdict === "safe") verdict = "suspicious";
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
  };
}

export const analyzeMessage = action({
  args: { text: v.string(), ownerId: v.string() },
  handler: async (ctx, { text, ownerId }): Promise<PipelineResult & { id: string }> => {
    const result = await runPipeline(text);
    const id: string = await ctx.runMutation(internal.scanResults.insert, {
      ownerId,
      provider: "manual",
      snippet: text.slice(0, 280),
      verdict: result.verdict,
      mlScore: result.mlScore,
      confidence: result.confidence,
      summary: result.summary,
      recommendation: result.recommendation,
      flaggedPhrases: result.flaggedPhrases,
      signals: result.signals,
      aiReviewed: result.aiReviewed,
    });
    return { ...result, id };
  },
});
