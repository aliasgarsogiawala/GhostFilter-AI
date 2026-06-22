"use node";

import { v } from "convex/values";
import { google } from "googleapis";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { runPipeline } from "./pipeline";

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
  mimeType?: string | null;
  body?: { data?: string | null } | null;
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
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }): Promise<{ scanned: number; total: number }> => {
    const connection = await ctx.runQuery(internal.connections.getActiveGmail, { ownerId });
    if (!connection) {
      throw new Error("No connected Gmail account for this session");
    }

    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );
    oauth2Client.setCredentials({
      access_token: connection.accessToken,
      refresh_token: connection.refreshToken,
    });
    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

    const list = await gmail.users.messages.list({
      userId: "me",
      maxResults: MAX_MESSAGES,
      q: "in:inbox",
    });
    const messages = list.data.messages ?? [];

    let scanned = 0;
    for (const m of messages) {
      if (!m.id) continue;

      const existing = await ctx.runQuery(internal.scanResults.findByExternalId, {
        connectionId: connection._id,
        externalId: m.id,
      });
      if (existing) continue; // already scanned in a previous pass

      const full = await gmail.users.messages.get({ userId: "me", id: m.id, format: "full" });
      const { subject, body } = extractEmailContent(full.data);
      if (!body.trim()) continue;

      const result = await runPipeline(`Subject: ${subject}\n\n${body}`);
      await ctx.runMutation(internal.scanResults.insert, {
        ownerId,
        connectionId: connection._id,
        provider: "gmail",
        externalId: m.id,
        subject,
        snippet: body.slice(0, 280),
        verdict: result.verdict,
        mlScore: result.mlScore,
        confidence: result.confidence,
        summary: result.summary,
        recommendation: result.recommendation,
        flaggedPhrases: result.flaggedPhrases,
        signals: result.signals,
        aiReviewed: result.aiReviewed,
      });
      scanned++;
    }

    await ctx.runMutation(internal.connections.touchLastScanned, {
      connectionId: connection._id,
    });

    return { scanned, total: messages.length };
  },
});
