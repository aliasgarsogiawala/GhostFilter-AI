import { isIP } from "node:net";
import { lookup } from "node:dns/promises";
import { extractUrls } from "./features";

// Commonly-spoofed brand domains used for lookalike-domain detection.
const KNOWN_BRAND_DOMAINS = [
  "paypal.com",
  "amazon.com",
  "apple.com",
  "microsoft.com",
  "google.com",
  "netflix.com",
  "bankofamerica.com",
  "wellsfargo.com",
  "chase.com",
  "americanexpress.com",
  "irs.gov",
  "usps.com",
  "fedex.com",
  "ups.com",
  "dhl.com",
  "facebook.com",
  "instagram.com",
  "linkedin.com",
  "ebay.com",
  "walmart.com",
  "target.com",
  "coinbase.com",
  "binance.com",
  "dropbox.com",
  "docusign.com",
  "outlook.com",
  "icloud.com",
  "sbi.co.in",
  "onlinesbi.sbi",
  "hdfcbank.com",
  "icicibank.com",
  "axisbank.com",
];

const URL_SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
  "rb.gy",
]);

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [
    i,
    ...new Array(b.length).fill(0),
  ]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

export function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

export interface LookalikeResult {
  brand: string;
  distance: number;
}

/** Flags a hostname that's suspiciously close to (but not exactly) a known brand domain. */
export function lookalikeDomainCheck(hostname: string): LookalikeResult | null {
  let best: LookalikeResult | null = null;
  for (const brand of KNOWN_BRAND_DOMAINS) {
    if (hostname === brand || hostname.endsWith(`.${brand}`)) continue; // legitimate or real subdomain

    // brand name embedded as a deceptive subdomain/segment, e.g. Paypal-secure.com, secure-paypal.verify.ru
    const brandRoot = brand.split(".")[0];
    if (hostname.includes(brandRoot)) {
      if (!best || best.distance > 1) best = { brand, distance: 1 };
      continue;
    }

    // close character-level typo of the full domain, e.g. Paypa1.com
    if (Math.abs(hostname.length - brand.length) > 4) continue;
    const distance = levenshtein(hostname, brand);
    if (distance > 0 && distance <= 2) {
      if (!best || distance < best.distance) best = { brand, distance };
    }
  }
  return best;
}

export function isShortenedUrl(url: string): boolean {
  const host = hostnameOf(url);
  return host ? URL_SHORTENERS.has(host) : false;
}

function isPrivateOrReservedIp(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
    return false;
  }
  if (version === 6) {
    const lower = ip.toLowerCase();
    return (
      lower === "::1" ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") ||
      lower.startsWith("fe80")
    );
  }
  return true; // unresolvable / unknown. Treat as unsafe
}

interface ExpandResult {
  finalUrl: string;
  blocked: boolean;
  reason?: string;
}

/**
 * Follows a (likely shortened) URL's redirect chain server-side, with SSRF guards:
 * only http/https, max 3 hops, 5s timeout per hop, and every resolved hostname is
 * checked against private/loopback/link-local IP ranges before connecting.
 */
export async function expandShortenedUrl(url: string, maxHops = 3): Promise<ExpandResult> {
  let current = url;
  for (let hop = 0; hop < maxHops; hop++) {
    let parsed: URL;
    try {
      parsed = new URL(current);
    } catch {
      return { finalUrl: current, blocked: true, reason: "invalid-url" };
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { finalUrl: current, blocked: true, reason: "unsupported-scheme" };
    }

    try {
      const { address } = await lookup(parsed.hostname);
      if (isPrivateOrReservedIp(address)) {
        return { finalUrl: current, blocked: true, reason: "private-ip-target" };
      }
    } catch {
      return { finalUrl: current, blocked: true, reason: "dns-failure" };
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    let res: Response;
    try {
      res = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        signal: controller.signal,
      });
    } catch {
      return { finalUrl: current, blocked: true, reason: "fetch-failed" };
    } finally {
      clearTimeout(timeout);
    }

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) return { finalUrl: current, blocked: false };
      current = new URL(location, current).toString();
      continue;
    }
    return { finalUrl: current, blocked: false };
  }
  return { finalUrl: current, blocked: true, reason: "too-many-redirects" };
}

export interface LinkFinding {
  url: string;
  hostname: string | null;
  isShortened: boolean;
  lookalike: LookalikeResult | null;
  expanded?: ExpandResult;
}

/** Top-level entry point used by the analysis pipeline: extracts and inspects every URL in a message. */
export async function analyzeLinks(text: string): Promise<LinkFinding[]> {
  const urls = extractUrls(text);
  const findings: LinkFinding[] = [];
  for (const url of urls) {
    const hostname = hostnameOf(url);
    const finding: LinkFinding = {
      url,
      hostname,
      isShortened: isShortenedUrl(url),
      lookalike: hostname ? lookalikeDomainCheck(hostname) : null,
    };
    if (finding.isShortened) {
      finding.expanded = await expandShortenedUrl(url);
      if (finding.expanded.finalUrl && !finding.expanded.blocked) {
        const finalHost = hostnameOf(finding.expanded.finalUrl);
        if (finalHost) {
          const finalLookalike = lookalikeDomainCheck(finalHost);
          if (finalLookalike) finding.lookalike = finalLookalike;
        }
      }
    }
    findings.push(finding);
  }
  return findings;
}
