import type { InjectionFinding } from "./promptInjection";
import type { SocialEngineeringFinding } from "./socialEngineering";
import type { EmailForensics } from "./emailHeaders";

export interface ScamModelLayer {
  label: string;
  score: number;
  evidence: string;
  explanation: string;
}

export interface ScamEnsembleResult {
  score: number;
  needsReview: boolean;
  hardScam: boolean;
  layers: ScamModelLayer[];
  flaggedPhrases: { phrase: string; reason: string; severity: "amber" | "red" }[];
  signals: { label: string; value: number }[];
}

const MONEY_OR_CODE_RE =
  /(?:[$£€₹]\s*\d[\d,.]*|\d[\d,.]*\s*(?:rs\.?|inr|rupees?|dollars?|usd|euros?|eur|pounds?|gbp|dirhams?|aed|yen|jpy)\b|\b(?:money|cash|payment|crypto|bitcoin|btc|usdt|gift cards?|otp|one[-\s]?time code|verification code|pin)\b)/i;

const PAYMENT_VERB_RE = /\b(?:send|pay|transfer|wire|deposit|remit|give|loan|lend|share|tell|forward)\b/i;

const TRUST_CLAIM_RE =
  /\b(?:i\s*(?:am|'?m)|im|this\s+is|it\s+is)\s+(?:really\s+|actually\s+)?(?:the\s+)?(?:real|official|verified)\s+[a-z][a-z'-]*(?:\s+[a-z][a-z'-]*){0,4}/i;

const PRESSURE_RE =
  /\b(?:urgent|immediately|right now|asap|last chance|limited time|before it expires|account locked|suspended|final warning|don't tell anyone|keep this private)\b/i;

const PRIZE_CRYPTO_JOB_RE =
  /\b(?:congratulations|winner|won|prize|airdrop|crypto|bitcoin|investment|double your money|work from home|easy income|guaranteed returns?)\b/i;

function clampScore(score: number) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function addLayer(layers: ScamModelLayer[], layer: ScamModelLayer) {
  layers.push({ ...layer, score: clampScore(layer.score) });
}

function weightedScore(layers: ScamModelLayer[]) {
  if (!layers.length) return 0;
  const top = [...layers].sort((a, b) => b.score - a.score).slice(0, 4);
  const weighted = top.reduce((sum, layer, index) => sum + layer.score * (1 - index * 0.13), 0);
  const weight = top.reduce((sum, _layer, index) => sum + (1 - index * 0.13), 0);
  return clampScore(weighted / weight);
}

export function analyzeScamEnsemble(
  text: string,
  mlScore: number,
  opts: {
    socialEngineering: SocialEngineeringFinding;
    injection: InjectionFinding;
    forensics?: EmailForensics | null;
  }
): ScamEnsembleResult {
  const layers: ScamModelLayer[] = [];
  const flaggedPhrases: ScamEnsembleResult["flaggedPhrases"] = [];
  const paymentLike = MONEY_OR_CODE_RE.test(text) && PAYMENT_VERB_RE.test(text);
  const trustClaim = opts.socialEngineering.identityClaim || TRUST_CLAIM_RE.test(text);
  const pressure = PRESSURE_RE.test(text);
  const prizeCryptoJob = PRIZE_CRYPTO_JOB_RE.test(text);
  const forensicHit = !!opts.forensics?.indicators.some((indicator) => indicator.severity === "red");

  addLayer(layers, {
    label: "Statistical scam classifier",
    score: mlScore * 100,
    evidence: `${Math.round(mlScore * 100)}% raw classifier probability`,
    explanation: "A lightweight logistic-regression model scores the text using trained word and structure features.",
  });

  if (paymentLike) {
    const phrase = opts.socialEngineering.paymentPhrase ?? text.match(MONEY_OR_CODE_RE)?.[0] ?? "money/code request";
    addLayer(layers, {
      label: "Payment or secret-code intent",
      score: 82,
      evidence: phrase,
      explanation: "The message asks for money, payment, crypto, gift cards, OTPs, PINs, or similar high-risk assets.",
    });
    flaggedPhrases.push({
      phrase,
      reason: "A request for money or secret codes is a high-value scam target.",
      severity: "amber",
    });
  }

  if (trustClaim) {
    const phrase = opts.socialEngineering.identityPhrase ?? text.match(TRUST_CLAIM_RE)?.[0] ?? "real/official identity claim";
    addLayer(layers, {
      label: "Unverified trust claim",
      score: paymentLike ? 96 : 66,
      evidence: phrase,
      explanation: "The sender claims to be a real or official identity without proof.",
    });
    flaggedPhrases.push({
      phrase,
      reason: paymentLike
        ? "An unverified identity claim is paired with a money or secret request."
        : "Scammers often claim trusted identities to lower your guard.",
      severity: paymentLike ? "red" : "amber",
    });
  }

  if (pressure) {
    const phrase = text.match(PRESSURE_RE)?.[0] ?? "urgent language";
    addLayer(layers, {
      label: "Behavioral pressure",
      score: 68,
      evidence: phrase,
      explanation: "The message creates urgency, secrecy, or pressure so the recipient acts before verifying.",
    });
  }

  if (prizeCryptoJob) {
    const phrase = text.match(PRIZE_CRYPTO_JOB_RE)?.[0] ?? "prize/crypto/job promise";
    addLayer(layers, {
      label: "Common scam storyline",
      score: 64,
      evidence: phrase,
      explanation: "The text matches common prize, crypto, job, or guaranteed-return scam narratives.",
    });
  }

  if (opts.injection.detected) {
    addLayer(layers, {
      label: "AI manipulation language",
      score: 78,
      evidence: opts.injection.matches[0] ?? "prompt-injection style language",
      explanation: "The message contains language aimed at manipulating an automated reviewer or assistant.",
    });
  }

  if (forensicHit) {
    addLayer(layers, {
      label: "Email sender forensics",
      score: 88,
      evidence: opts.forensics?.indicators.find((indicator) => indicator.severity === "red")?.detail ?? "sender mismatch",
      explanation: "Technical email metadata indicates sender/authentication mismatch.",
    });
  }

  const score = weightedScore(layers);
  const hardScam = opts.socialEngineering.combinedImpersonationPayment || (paymentLike && trustClaim) || forensicHit;
  const needsReview = hardScam || score >= 38 || paymentLike || trustClaim;

  return {
    score,
    needsReview,
    hardScam,
    layers,
    flaggedPhrases,
    signals: [
      { label: "ML Ensemble Risk", value: score },
      { label: "Payment / Code Intent", value: paymentLike ? 88 : 0 },
      { label: "Trust Impersonation", value: trustClaim ? (paymentLike ? 96 : 62) : 0 },
      { label: "Behavioral Pressure", value: pressure ? 68 : 0 },
    ],
  };
}
