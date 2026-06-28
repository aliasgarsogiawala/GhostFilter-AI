"use node";

import { createHash } from "node:crypto";
import { v } from "convex/values";
import { google } from "googleapis";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { runPipeline } from "./pipeline";
import { checkFileHash } from "../lib/virustotal";
import { rawHeadersFromList } from "../lib/emailHeaders";
import { decryptSecret } from "../lib/secretBox";
import { assertOwnerToken } from "../lib/ownerToken";

function decodeBase64Url(data: string): string {
  return Buffer.from(data, "base64url").toString("utf-8");
}

function stripHtml(html: string): string {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

interface GmailPart {
  filename?: string | null;
  mimeType?: string | null;
  body?: { data?: string | null; attachmentId?: string | null } | null;
  parts?: GmailPart[] | null;
}

function findBody(part: GmailPart | undefined, mimeType: string): string | null {
  if (!part) return null;
  if (part.mimeType === mimeType && part.body?.data) {
    return decodeBase64Url(part.body.data);
  }
  if (part.parts) {
    for (const child of part.parts) {
      const found = findBody(child, mimeType);
      if (found) return found;
    }
  }
  return null;
}

interface AttachmentRef {
  filename: string;
  attachmentId: string;
}

function findAttachments(part: GmailPart | undefined, acc: AttachmentRef[] = []): AttachmentRef[] {
  if (!part) return acc;
  if (part.filename && part.body?.attachmentId) {
    acc.push({ filename: part.filename, attachmentId: part.body.attachmentId });
  }
  if (part.parts) {
    for (const child of part.parts) findAttachments(child, acc);
  }
  return acc;
}

const MAX_ATTACHMENTS_PER_MESSAGE = 3;

interface AttachmentIntel {
  filename: string;
  sha256: string;
  found: boolean;
  vtMalicious: number;
  vtSuspicious: number;
}

/** Hashes each attachment and checks the hash against VirusTotal. The file
 *  content itself is never uploaded anywhere, only its SHA-256 digest. */
async function scanAttachments(
  gmail: ReturnType<typeof google.gmail>,
  messageId: string,
  payload: GmailPart | undefined
): Promise<AttachmentIntel[]> {
  const refs = findAttachments(payload).slice(0, MAX_ATTACHMENTS_PER_MESSAGE);
  const results: AttachmentIntel[] = [];
  for (const ref of refs) {
    try {
      const att = await gmail.users.messages.attachments.get({
        userId: "me",
        messageId,
        id: ref.attachmentId,
      });
      if (!att.data.data) continue;
      const bytes = Buffer.from(att.data.data, "base64url");
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      const rep = await checkFileHash(sha256);
      results.push({
        filename: ref.filename,
        sha256,
        found: rep.found,
        vtMalicious: rep.malicious,
        vtSuspicious: rep.suspicious,
      });
    } catch {
      // Skip this attachment on any failure. Never block the rest of the scan over it.
    }
  }
  return results;
}

function extractEmailContent(message: {
  payload?: GmailPart | null;
}): { subject: string; body: string } {
  const headers = (message.payload as { headers?: { name?: string; value?: string }[] })
    ?.headers;
  const subject = headers?.find((h) => h.name?.toLowerCase() === "subject")?.value ?? "(no subject)";

  const payload = message.payload ?? undefined;
  const plain = findBody(payload, "text/plain");
  if (plain) return { subject, body: plain };
  const html = findBody(payload, "text/html");
  if (html) return { subject, body: stripHtml(html) };
  return { subject, body: "" };
}

const MAX_MESSAGES = 50;

export const scanInbox = action({
  args: { ownerId: v.string(), ownerToken: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, { ownerId, ownerToken, limit }): Promise<{
    scanned: number;
    skipped: number;
    failed: number;
    total: number;
  }> => {
    await assertOwnerToken(ownerId, ownerToken);
    const max = Math.min(MAX_MESSAGES, Math.max(1, limit ?? 25));
    const connection = await ctx.runQuery(internal.connections.getActiveGmail, { ownerId });
    if (!connection) {
      throw new Error("No connected Gmail account for this session");
    }

    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );
    try {
      oauth2Client.setCredentials({
        access_token: decryptSecret(connection.accessToken),
        refresh_token: connection.refreshToken ? decryptSecret(connection.refreshToken) : undefined,
      });
    } catch {
      throw new Error("Google credentials need to be refreshed. Disconnect Google, reconnect it, then scan again.");
    }
    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

    const list = await gmail.users.messages.list({
      userId: "me",
      maxResults: max,
      q: "in:inbox",
    });
    const messages = list.data.messages ?? [];

    let scanned = 0;
    let skipped = 0;
    let failed = 0;
    for (const m of messages) {
      if (!m.id) {
        skipped++;
        continue;
      }

      try {
        const existing = await ctx.runQuery(internal.scanResults.findByExternalId, {
          connectionId: connection._id,
          externalId: m.id,
        });
        if (existing) {
          skipped++;
          continue;
        }

        const full = await gmail.users.messages.get({ userId: "me", id: m.id, format: "full" });
        const { subject, body } = extractEmailContent(full.data);
        if (!body.trim()) {
          skipped++;
          continue;
        }

        const headerList = (full.data.payload as { headers?: { name?: string | null; value?: string | null }[] })?.headers ?? [];

        // Bulk scans omit the slower screenshot capture. Reputation checks and
        // header forensics still run for every readable message.
        const result = await runPipeline(`Subject: ${subject}\n\n${body}`, {
          captureScreenshot: false,
          rawHeaders: rawHeadersFromList(headerList),
        });

        const attachmentIntel = await scanAttachments(gmail, m.id, full.data.payload ?? undefined);
        const maliciousAttachment = attachmentIntel.find((a) => a.vtMalicious > 0);
        if (maliciousAttachment) {
          result.verdict = "scam";
          result.confidence = Math.max(result.confidence, 95);
          result.signals = [...result.signals, { label: "Malicious Attachment", value: 100 }];
        }

        await ctx.runMutation(internal.scanResults.insert, {
          ownerId,
          connectionId: connection._id,
          provider: "gmail",
          externalId: m.id,
          subject,
          snippet: body.slice(0, 4000),
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
          attachmentIntel: attachmentIntel.length ? attachmentIntel : undefined,
          forensics: result.forensics ?? undefined,
        });
        scanned++;
      } catch (error) {
        failed++;
        console.error(`Gmail message scan failed for ${m.id}:`, error);
      }
    }

    await ctx.runMutation(internal.connections.touchLastScanned, {
      connectionId: connection._id,
    });

    return { scanned, skipped, failed, total: messages.length };
  },
});
