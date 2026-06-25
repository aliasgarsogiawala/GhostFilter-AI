import { GoogleGenAI } from "@google/genai";

const GEMINI_KEY_NAMES = [
  "GEMINI_API_KEY_1",
  "GEMINI_API_KEY_2",
] as const;

interface GeminiKeyEntry {
  name: string;
  key: string;
}

let clients: Map<string, GoogleGenAI> | null = null;

export function getGeminiKeys(): GeminiKeyEntry[] {
  const seen = new Set<string>();
  return GEMINI_KEY_NAMES.flatMap((name) => {
    const key = process.env[name]?.trim();
    if (!key || seen.has(key)) return [];
    seen.add(key);
    return [{ name, key }];
  });
}

export function getGeminiClientForKey(entry: GeminiKeyEntry) {
  clients ??= new Map();
  const existing = clients.get(entry.name);
  if (existing) return existing;
  const client = new GoogleGenAI({ apiKey: entry.key });
  clients.set(entry.name, client);
  return client;
}

export function geminiKeyHelpText() {
  return "Set at least one Gemini key: GEMINI_API_KEY_1 or GEMINI_API_KEY_2.";
}

export function isGeminiTransientOrQuotaError(err: unknown) {
  const msg = String(err);
  return (
    msg.includes("503") ||
    msg.includes("UNAVAILABLE") ||
    msg.includes("overloaded") ||
    msg.includes("429") ||
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.toLowerCase().includes("quota")
  );
}
