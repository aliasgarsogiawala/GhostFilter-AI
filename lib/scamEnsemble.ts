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
  /(?:[$£€₹]\s*\d[\d,.]*|\d[\d,.]*\s*(?:rs\.?|inr|rupees?|dollars?|usd|euros?|eur|pounds?|gbp|dirhams?|aed|yen|jpy)\b|\b(?:money|cash|rent|payment|fee|refund|crypto|bitcoin|btc|usdt|gift cards?|gift card codes?|otp|code|one[-\s]?time code|verification code|pin|upi pin|seed phrase|recovery phrase|wallet seed)\b)/i;

const PAYMENT_VERB_RE = /\b(?:send|pay|transfer|wire|deposit|remit|give|loan|lend|buy|buying|purchase|share|tell|forward|connect|enter|submit)\b/i;

const TRUST_CLAIM_RE =
  /\b(?:i\s*(?:am|'?m)|im|this\s+is|it\s+is)\s+(?:really\s+|actually\s+)?(?:the\s+)?(?:real|official|verified)\s+[a-z][a-z'-]*(?:\s+[a-z][a-z'-]*){0,4}/i;

const PRESSURE_RE =
  /\b(?:urgent|immediately|right now|asap|last chance|limited time|before it expires|account locked|suspended|final warning|don't tell anyone|keep this private)\b/i;

const PRIZE_CRYPTO_JOB_RE =
  /\b(?:congratulations|winner|won|prize|airdrop|free\s+(?:nitro|iphone|gift|reward)|nitro\s+(?:drop|gift)|gift\s*cards?|crypto|bitcoin|investment|double your money|work from home|easy income|guaranteed returns?)\b/i;

const SUPPORT_IMPERSONATION_RE =
  /\b(?:instagram|meta|facebook|whatsapp|telegram|discord|sbi|hdfc|icici|axis|bank|support|admin|security)\b.{0,35}\b(?:support|security|team|admin|official|verification|helpdesk|copyright|appeal)\b|\b(?:instagram|meta|facebook|whatsapp|telegram|discord|sbi|hdfc|icici|axis|bank)\s+(?:support|copyright|appeal)\b/i;

const ACCOUNT_SECURITY_RE =
  /\b(?:account|apple\s*id|kyc|card|bank|upi|netbanking|profile|page)\b.{0,45}\b(?:blocked|locked|suspended|verify|verification|kyc|reactivate|restore|deleted|disabled|appeal)\b|\b(?:blocked|locked|suspended|deleted|disabled)\b.{0,45}\b(?:account|apple\s*id|kyc|card|bank|upi|netbanking|profile|page)\b/i;

const URL_RE = /\bhttps?:\/\/\S+|\bwww\.\S+/i;
const PASSWORD_REQUEST_RE = /\b(?:send|share|tell|reply with|enter|submit)\b.{0,50}\b(?:password|passcode|login|credentials?)\b|\b(?:password|passcode|login|credentials?)\b.{0,50}\b(?:send|share|tell|reply|enter|submit)\b/i;
const STRONG_SECRET_RE = /\b(?:otp|one[-\s]?time code|verification code|upi pin|pin|seed phrase|recovery phrase|wallet seed|password|passcode|credentials?)\b/i;
const SERVICE_DISCONNECT_RE =
  /\b(?:electricity|power|mobile|internet|gas|water|service)\b.{0,60}\b(?:disconnect(?:ed|ion)?|suspend(?:ed)?|restore|overdue)\b|\b(?:disconnect(?:ed|ion)?|suspend(?:ed)?)\b.{0,60}\b(?:electricity|power|mobile|internet|gas|water|service)\b/i;

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
  const supportImpersonation = SUPPORT_IMPERSONATION_RE.test(text);
  const accountSecurity = ACCOUNT_SECURITY_RE.test(text);
  const hasUrl = URL_RE.test(text);
  const passwordRequest = PASSWORD_REQUEST_RE.test(text);
  const secretCredentialRequest = STRONG_SECRET_RE.test(text);
  const serviceDisconnect = SERVICE_DISCONNECT_RE.test(text);
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

  if (supportImpersonation) {
    const phrase = text.match(SUPPORT_IMPERSONATION_RE)?.[0] ?? "platform/support identity claim";
    addLayer(layers, {
      label: "Platform/support impersonation",
      score: paymentLike || pressure ? 92 : 70,
      evidence: phrase,
      explanation: "The sender claims to be a platform, bank, support, admin, or security team.",
    });
    flaggedPhrases.push({
      phrase,
      reason: "Fake support/admin messages commonly ask for OTPs, passwords, or urgent verification.",
      severity: paymentLike || pressure ? "red" : "amber",
    });
  }

  if (accountSecurity) {
    const phrase = text.match(ACCOUNT_SECURITY_RE)?.[0] ?? "account security warning";
    addLayer(layers, {
      label: "Account/KYC takeover lure",
      score: hasUrl ? 94 : 74,
      evidence: phrase,
      explanation: "The message threatens account loss or KYC/account blocking to push the user toward a verification action.",
    });
    flaggedPhrases.push({
      phrase,
      reason: hasUrl
        ? "Account-block/KYC warnings with links are a classic credential-phishing pattern."
        : "Account-block/KYC pressure is a common phishing setup.",
      severity: hasUrl ? "red" : "amber",
    });
  }

  if (serviceDisconnect) {
    const phrase = text.match(SERVICE_DISCONNECT_RE)?.[0] ?? "service disconnection threat";
    addLayer(layers, {
      label: "Utility/service disconnection lure",
      score: hasUrl || paymentLike ? 90 : 70,
      evidence: phrase,
      explanation: "The message threatens an essential service interruption to force an urgent payment or link visit.",
    });
    flaggedPhrases.push({
      phrase,
      reason: "Unexpected disconnection threats should be verified through the provider's official app or number.",
      severity: hasUrl || paymentLike ? "red" : "amber",
    });
  }

  if (passwordRequest) {
    const phrase = text.match(PASSWORD_REQUEST_RE)?.[0] ?? "password or credential request";
    addLayer(layers, {
      label: "Password or credential request",
      score: 96,
      evidence: phrase,
      explanation: "Legitimate teams should not ask you to send passwords, passcodes, or login credentials in a message.",
    });
    flaggedPhrases.push({
      phrase,
      reason: "Requests for passwords or credentials are direct account-takeover indicators.",
      severity: "red",
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
  const hardScam =
    opts.socialEngineering.combinedImpersonationPayment ||
    (paymentLike && trustClaim) ||
    (paymentLike && supportImpersonation) ||
    (paymentLike && prizeCryptoJob) ||
    passwordRequest ||
    (paymentLike && secretCredentialRequest) ||
    (prizeCryptoJob && hasUrl) ||
    (accountSecurity && hasUrl) ||
    (serviceDisconnect && (hasUrl || paymentLike)) ||
    forensicHit;
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
      { label: "Trust Impersonation", value: trustClaim || supportImpersonation ? (paymentLike ? 96 : 72) : 0 },
      { label: "Behavioral Pressure", value: pressure ? 68 : 0 },
      { label: "Account / KYC Threat", value: accountSecurity ? (hasUrl ? 94 : 72) : 0 },
    ],
  };
}
