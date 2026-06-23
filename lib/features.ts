// Shared feature extraction used by both the offline training script
// (scripts/train-classifier.ts) and the runtime classifier (lib/ml-classifier.ts).
// Keeping this in one place guarantees train-time and inference-time features
// are computed identically.

export const URGENCY_KEYWORDS = [
  "urgent",
  "immediately",
  "verify",
  "suspended",
  "suspend",
  "winner",
  "claim",
  "congratulations",
  "act now",
  "limited time",
  "click here",
  "confirm",
  "password",
  "bank",
  "account",
  "prize",
  "won",
  "free",
  "guarantee",
  "credit",
  "offer",
  "cash",
  "txt",
  "text back",
  "call now",
  "expire",
  "expires",
  "security alert",
  "unauthorized",
  "locked",
];

const URL_RE = /\bhttps?:\/\/\S+|\bwww\.\S+/gi;
const WORD_RE = /[a-z']+/gi;

export interface HandcraftedFeatures {
  length: number;
  wordCount: number;
  urlCount: number;
  exclamationCount: number;
  digitRatio: number;
  upperRatio: number;
  currencyCount: number;
  urgencyKeywordCount: number;
}

export function tokenize(text: string): string[] {
  return (text.toLowerCase().match(WORD_RE) ?? []).filter((w) => w.length > 1);
}

export function handcraftedFeatures(text: string): HandcraftedFeatures {
  const lower = text.toLowerCase();
  const words = tokenize(text);
  const len = text.length || 1;
  const digits = (text.match(/[0-9]/g) ?? []).length;
  const upper = (text.match(/[A-Z]/g) ?? []).length;
  const urgencyKeywordCount = URGENCY_KEYWORDS.reduce(
    (acc, kw) => acc + (lower.includes(kw) ? 1 : 0),
    0
  );

  return {
    length: Math.log(text.length + 1),
    wordCount: words.length,
    urlCount: (text.match(URL_RE) ?? []).length,
    exclamationCount: (text.match(/!/g) ?? []).length,
    digitRatio: digits / len,
    upperRatio: upper / len,
    currencyCount: (
      text.match(
        /[$£€₹]|\b(?:rs\.?|inr|rupees?|dollars?|usd|euros?|eur|pounds?|gbp|dirhams?|aed|yen|jpy)\b/gi
      ) ?? []
    ).length,
    urgencyKeywordCount,
  };
}

export const HANDCRAFTED_KEYS: (keyof HandcraftedFeatures)[] = [
  "length",
  "wordCount",
  "urlCount",
  "exclamationCount",
  "digitRatio",
  "upperRatio",
  "currencyCount",
  "urgencyKeywordCount",
];

/** Feature vector = handcrafted features followed by one 0/1 flag per vocab word. */
export function extractFeatureVector(text: string, vocab: string[]): number[] {
  const hc = handcraftedFeatures(text);
  const handcrafted = HANDCRAFTED_KEYS.map((k) => hc[k]);
  const words = new Set(tokenize(text));
  const bow = vocab.map((w) => (words.has(w) ? 1 : 0));
  return [...handcrafted, ...bow];
}

export function extractUrls(text: string): string[] {
  return text.match(URL_RE) ?? [];
}
