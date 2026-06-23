// Parses raw email headers (RFC822) into a PhishTool-style forensics view and detects
// classic spoofing tells: From vs Return-Path / Reply-To domain mismatches, failed
// SPF/DKIM/DMARC, and an originating server whose rDNS doesn't match the sender domain.
// Used by both the manual analyzer (pasted raw email) and the Gmail scanner.

export type FieldStatus = "ok" | "warn" | "bad";

export interface ForensicField {
  label: string;
  value: string;
  status?: FieldStatus;
}

export interface ForensicIndicator {
  label: string;
  detail: string;
  severity: "amber" | "red";
}

export interface EmailForensics {
  fields: ForensicField[];
  indicators: ForensicIndicator[];
}

const HEADER_HINTS =
  /^(received|return-path|message-id|dkim-signature|authentication-results|reply-to|x-[a-z-]+):/im;

/** Heuristic: does this pasted text look like a raw email with headers (vs. plain message body)? */
export function looksLikeRawEmail(text: string): boolean {
  const hasFrom = /^from:\s*.+/im.test(text);
  const hasOtherHeaders = HEADER_HINTS.test(text);
  return hasFrom && hasOtherHeaders;
}

function unfold(headerBlock: string): string[] {
  const lines = headerBlock.split(/\r?\n/);
  const out: string[] = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && out.length) {
      out[out.length - 1] += " " + line.trim();
    } else {
      out.push(line);
    }
  }
  return out;
}

interface ParsedHeaders {
  get: (name: string) => string | undefined;
  all: (name: string) => string[];
}

function parseHeaderBlock(raw: string): ParsedHeaders {
  const sepIdx = raw.search(/\r?\n\r?\n/);
  const block = sepIdx === -1 ? raw : raw.slice(0, sepIdx);
  const map = new Map<string, string[]>();
  for (const line of unfold(block)) {
    const m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const arr = map.get(key) ?? [];
    arr.push(m[2].trim());
    map.set(key, arr);
  }
  return {
    get: (name) => map.get(name.toLowerCase())?.[0],
    all: (name) => map.get(name.toLowerCase()) ?? [],
  };
}

function parseAddress(value?: string): { display: string; email: string; domain: string } {
  if (!value) return { display: "", email: "", domain: "" };
  const angle = value.match(/<([^>]+)>/);
  const email = (angle ? angle[1] : value).trim().replace(/^"|"$/g, "");
  let display = angle ? value.slice(0, angle.index).trim().replace(/^"|"$/g, "") : "";
  if (!display && !angle) display = "";
  const domain = email.includes("@") ? email.split("@").pop()!.toLowerCase() : "";
  return { display, email, domain };
}

/** eTLD+1 approximation (last two labels) so checkout.paypal.com and paypal.com compare equal. */
function rootDomain(domain: string): string {
  const parts = domain.split(".").filter(Boolean);
  return parts.length <= 2 ? domain : parts.slice(-2).join(".");
}

function isPrivateIp(ip: string): boolean {
  const [a, b] = ip.split(".").map(Number);
  return (
    a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254)
  );
}

function extractOrigin(received: string[]): { ip: string; rdns: string } {
  // The earliest hop (origin) is the last Received header; scan from the bottom for a public IP.
  for (let i = received.length - 1; i >= 0; i--) {
    const line = received[i];
    const ips = [...line.matchAll(/\[?(\d{1,3}(?:\.\d{1,3}){3})\]?/g)].map((m) => m[1]);
    const publicIp = ips.find((ip) => !isPrivateIp(ip));
    if (publicIp) {
      // rDNS host usually appears right before the [ip], e.g. "host.example.com [1.2.3.4]"
      const rdnsMatch = line.match(/([a-z0-9.-]+)\s*[\[(]\s*\d{1,3}(?:\.\d{1,3}){3}/i);
      return { ip: publicIp, rdns: rdnsMatch ? rdnsMatch[1].toLowerCase() : "" };
    }
  }
  return { ip: "", rdns: "" };
}

function authResult(headers: ParsedHeaders, mech: "spf" | "dkim" | "dmarc"): string {
  const ar = headers.all("authentication-results").join("; ");
  const m = ar.match(new RegExp(`${mech}=(\\w+)`, "i"));
  if (m) return m[1].toLowerCase();
  if (mech === "spf") {
    const rs = headers.get("received-spf");
    if (rs) {
      const r = rs.match(/^(pass|fail|softfail|neutral|none)/i);
      if (r) return r[1].toLowerCase();
    }
  }
  return "";
}

export function parseEmailForensics(raw: string): EmailForensics {
  const h = parseHeaderBlock(raw);
  const from = parseAddress(h.get("from"));
  const replyTo = parseAddress(h.get("reply-to"));
  const returnPath = parseAddress(h.get("return-path"));
  const to = parseAddress(h.get("to"));
  const origin = extractOrigin(h.all("received"));
  const spf = authResult(h, "spf");
  const dkim = authResult(h, "dkim");
  const dmarc = authResult(h, "dmarc");

  const indicators: ForensicIndicator[] = [];
  const fromRoot = from.domain ? rootDomain(from.domain) : "";

  let replyToStatus: FieldStatus | undefined;
  if (replyTo.domain && fromRoot && rootDomain(replyTo.domain) !== fromRoot) {
    replyToStatus = "bad";
    indicators.push({
      label: "Reply-To mismatch",
      detail: `Replies go to ${replyTo.domain}, not the sender's domain (${from.domain}). A common trick to capture your response on a different account.`,
      severity: "red",
    });
  }

  let returnPathStatus: FieldStatus | undefined;
  if (returnPath.domain && fromRoot && rootDomain(returnPath.domain) !== fromRoot) {
    returnPathStatus = "bad";
    indicators.push({
      label: "Return-Path mismatch",
      detail: `Bounce address (${returnPath.domain}) doesn't match the sender (${from.domain}) — a sign the From address may be spoofed.`,
      severity: "red",
    });
  }

  let originStatus: FieldStatus | undefined;
  if (origin.rdns && fromRoot && rootDomain(origin.rdns) !== fromRoot) {
    originStatus = "warn";
    indicators.push({
      label: "Originating server mismatch",
      detail: `The email was actually sent from ${origin.rdns}, which isn't part of ${from.domain}.`,
      severity: "amber",
    });
  }

  const authStatus = (r: string): FieldStatus | undefined =>
    !r ? undefined : r === "pass" ? "ok" : r === "neutral" || r === "none" ? "warn" : "bad";
  for (const [mech, r] of [["SPF", spf], ["DKIM", dkim], ["DMARC", dmarc]] as const) {
    if (r && r !== "pass" && r !== "neutral" && r !== "none") {
      indicators.push({
        label: `${mech} ${r}`,
        detail: `${mech} authentication did not pass — the sender may not be who they claim.`,
        severity: mech === "DKIM" ? "amber" : "red",
      });
    }
  }

  const fields: ForensicField[] = [];
  const push = (label: string, value: string, status?: FieldStatus) => {
    if (value) fields.push({ label, value, status });
  };
  push("From", from.email, replyToStatus || returnPathStatus ? "bad" : undefined);
  push("Display name", from.display);
  push("Reply-To", replyTo.email, replyToStatus);
  push("Return-Path", returnPath.email, returnPathStatus);
  push("To", to.email);
  push("Subject", h.get("subject") ?? "");
  push("Message-ID", h.get("message-id") ?? "");
  push("Date", h.get("date") ?? "");
  push("Originating IP", origin.ip, origin.ip ? (originStatus ?? "ok") : undefined);
  push("rDNS", origin.rdns, originStatus);
  if (spf) push("SPF", spf, authStatus(spf));
  if (dkim) push("DKIM", dkim, authStatus(dkim));
  if (dmarc) push("DMARC", dmarc, authStatus(dmarc));

  return { fields, indicators };
}

/** Build a raw header block from Gmail's payload.headers array so the same parser works. */
export function rawHeadersFromList(headers: { name?: string | null; value?: string | null }[]): string {
  return headers
    .filter((h) => h.name && h.value)
    .map((h) => `${h.name}: ${h.value}`)
    .join("\n");
}
