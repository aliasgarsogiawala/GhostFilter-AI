import { GoogleGenAI, Type } from "@google/genai";
import type { LinkFinding } from "./heuristics";

export interface GeminiVerdict {
  verdict: "safe" | "suspicious" | "scam";
  confidence: number; // 0-100
  summary: string;
  flaggedPhrases: { phrase: string; reason: string; severity: "amber" | "red" }[];
  signals: { label: string; value: number }[];
  recommendation: string;
}

const RESPONSE_SCHEMA = {
  type: Type.OBJECT,
  properties: {
    verdict: { type: Type.STRING, enum: ["safe", "suspicious", "scam"] },
    confidence: { type: Type.NUMBER },
    summary: { type: Type.STRING },
    flaggedPhrases: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          phrase: { type: Type.STRING },
          reason: { type: Type.STRING },
          severity: { type: Type.STRING, enum: ["amber", "red"] },
        },
        required: ["phrase", "reason", "severity"],
      },
    },
    signals: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          label: { type: Type.STRING },
          value: { type: Type.NUMBER },
        },
        required: ["label", "value"],
      },
    },
    recommendation: { type: Type.STRING },
  },
  required: ["verdict", "confidence", "summary", "flaggedPhrases", "signals", "recommendation"],
};

let client: GoogleGenAI | null = null;
function getClient(): GoogleGenAI {
  if (!client) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) throw new Error("GEMINI_API_KEY is not set");
    client = new GoogleGenAI({ apiKey });
  }
  return client;
}

export async function reviewWithGemini(
  text: string,
  mlScore: number,
  linkFindings: LinkFinding[]
): Promise<GeminiVerdict> {
  const heuristicNotes = linkFindings.length
    ? linkFindings
        .map((f) => {
          const bits = [`url=${f.url}`];
          if (f.isShortened) bits.push("shortened-link");
          if (f.expanded) bits.push(`expands-to=${f.expanded.finalUrl}`);
          if (f.lookalike) bits.push(`lookalike-of=${f.lookalike.brand}`);
          return bits.join(", ");
        })
        .join("\n")
    : "No links found in the message.";

  const prompt = `You are a consumer-protection scam/phishing analyst. Analyze the message below for a non-technical reader. Be specific about WHY something is or isn't a scam, in plain English (no jargon like "SPF/DKIM" without explaining it).

A fast triage classifier already scored this message's spam/scam likelihood at ${(mlScore * 100).toFixed(1)}/100 — treat that as one input, not the final answer.

Deterministic link analysis findings:
${heuristicNotes}

Message to analyze:
"""
${text}
"""

Identify specific phrases in the message that are red flags (quote them exactly as they appear). Score the signals: Urgency Language, Spoofed/Lookalike Domain, Suspicious Links, Grammar/Spelling Anomalies, Credential or Payment Request (0-100 each, 0 = not present). Give a one-sentence recommendation of what the reader should actually do.`;

  const response = await getClient().models.generateContent({
    model: "gemini-2.5-flash",
    contents: prompt,
    config: {
      responseMimeType: "application/json",
      responseSchema: RESPONSE_SCHEMA,
    },
  });

  const raw = response.text;
  if (!raw) throw new Error("Empty response from Gemini");
  return JSON.parse(raw) as GeminiVerdict;
}
