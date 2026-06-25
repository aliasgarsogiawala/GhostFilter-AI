"use node";

import { v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { runPipeline } from "./pipeline";

interface GraphMessage {
  id: string;
  subject?: string;
  from?: { emailAddress?: { name?: string; address?: string } };
  bodyPreview?: string;
  receivedDateTime?: string;
}

const MAX_MESSAGES = 50;

export const scanInbox = action({
  args: { ownerId: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, { ownerId, limit }): Promise<{ scanned: number; total: number }> => {
    const max = Math.min(MAX_MESSAGES, Math.max(1, limit ?? 25));
    const connection = await ctx.runQuery(internal.connections.getActiveOutlook, { ownerId });
    if (!connection) throw new Error("No connected Outlook account for this session");

    const url = new URL("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages");
    url.searchParams.set("$top", String(max));
    url.searchParams.set("$select", "id,subject,from,bodyPreview,receivedDateTime");
    url.searchParams.set("$orderby", "receivedDateTime desc");

    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${connection.accessToken}` },
    });
    if (!res.ok) throw new Error(`Outlook API error ${res.status} — try reconnecting Outlook.`);

    const data = (await res.json()) as { value?: GraphMessage[] };
    const messages = data.value ?? [];
    let scanned = 0;

    for (const message of messages) {
      const existing = await ctx.runQuery(internal.scanResults.findByExternalId, {
        connectionId: connection._id,
        externalId: message.id,
      });
      if (existing) continue;

      const subject = message.subject || "(no subject)";
      const sender = message.from?.emailAddress?.address ?? message.from?.emailAddress?.name ?? "unknown sender";
      const text = `Outlook message\nFrom: ${sender}\nSubject: ${subject}\n\n${message.bodyPreview ?? ""}`;
      const result = await runPipeline(text, { captureScreenshot: false });

      await ctx.runMutation(internal.scanResults.insert, {
        ownerId,
        connectionId: connection._id,
        provider: "outlook",
        externalId: message.id,
        subject,
        snippet: text.slice(0, 4000),
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
        forensics: result.forensics ?? undefined,
        ensembleScore: result.ensembleScore,
        mlBreakdown: result.mlBreakdown,
      });
      scanned++;
    }

    await ctx.runMutation(internal.connections.touchLastScanned, {
      connectionId: connection._id,
    });

    return { scanned, total: messages.length };
  },
});
