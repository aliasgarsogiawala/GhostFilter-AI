export interface SocialEngineeringFinding {
  paymentRequest: boolean;
  identityClaim: boolean;
  combinedImpersonationPayment: boolean;
  paymentPhrase: string | null;
  identityPhrase: string | null;
}

const PAYMENT_REQUEST_RE =
  /\b(?:send|pay|transfer|wire|deposit|remit|give|loan|lend)\b.{0,45}(?:[$£€₹]\s*\d[\d,.]*|\d[\d,.]*\s*(?:rs\.?|inr|rupees?|dollars?|usd|euros?|eur|pounds?|gbp|dirhams?|aed|yen|jpy)\b|\b(?:money|cash|payment|crypto|bitcoin|btc|usdt|gift cards?)\b)/i;

const REVERSED_PAYMENT_REQUEST_RE =
  /(?:[$£€₹]\s*\d[\d,.]*|\d[\d,.]*\s*(?:rs\.?|inr|rupees?|dollars?|usd|euros?|eur|pounds?|gbp|dirhams?|aed|yen|jpy)\b|\b(?:money|cash|payment|crypto|bitcoin|btc|usdt|gift cards?)\b).{0,45}\b(?:send|pay|transfer|wire|deposit|remit|give|loan|lend)\b/i;

const IDENTITY_CLAIM_RE =
  /\b(?:i\s*(?:am|'?m)|this\s+is|it\s+is)\s+(?:really\s+|actually\s+)?(?:the\s+)?real\s+[a-z][a-z'-]*(?:\s+[a-z][a-z'-]*)+/i;

function matchedPhrase(text: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[0]) return match[0].trim();
  }
  return null;
}

/**
 * Finds social-engineering patterns that short statistical messages can miss.
 * A payment request alone is not proof of fraud; pairing it with an unsolicited
 * "real person" identity claim is a strong impersonation-scam indicator.
 */
export function detectSocialEngineering(text: string): SocialEngineeringFinding {
  const paymentPhrase = matchedPhrase(text, [PAYMENT_REQUEST_RE, REVERSED_PAYMENT_REQUEST_RE]);
  const identityPhrase = matchedPhrase(text, [IDENTITY_CLAIM_RE]);
  const paymentRequest = paymentPhrase !== null;
  const identityClaim = identityPhrase !== null;

  return {
    paymentRequest,
    identityClaim,
    combinedImpersonationPayment: paymentRequest && identityClaim,
    paymentPhrase,
    identityPhrase,
  };
}
