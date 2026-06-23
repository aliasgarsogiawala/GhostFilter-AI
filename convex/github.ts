"use node";

import { v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { runPipeline } from "./pipeline";

interface GithubNotification {
  id: string;
  reason: string;
  subject: { title: string; type: string };
  repository: { full_name: string };
}

const MAX_NOTIFICATIONS = 50;

export const scanNotifications = action({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }): Promise<{ scanned: number; total: number }> => {
    const connection = await ctx.runQuery(internal.connections.getActiveGithub, { ownerId });
    if (!connection) {
      throw new Error("No connected GitHub account for this session");
    }

    const res = await fetch(`https://api.github.com/notifications?all=true&per_page=${MAX_NOTIFICATIONS}`, {
      headers: {
        Authorization: `Bearer ${connection.accessToken}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
    });
    if (!res.ok) {
      throw new Error(`GitHub API error ${res.status} — try reconnecting GitHub.`);
    }
    const notifications = (await res.json()) as GithubNotification[];

    let scanned = 0;
    for (const n of notifications) {
      const existing = await ctx.runQuery(internal.scanResults.findByExternalId, {
        connectionId: connection._id,
        externalId: n.id,
      });
      if (existing) continue;

      // The notification title is the issue/PR/discussion subject — that's where GitHub
      // scams show up (fake security alerts, airdrop spam, impersonation).
      const text = `${n.subject.title}\n\nRepository: ${n.repository.full_name} (${n.reason})`;
      const result = await runPipeline(text, { captureScreenshot: false });

      await ctx.runMutation(internal.scanResults.insert, {
        ownerId,
        connectionId: connection._id,
        provider: "github",
        externalId: n.id,
        subject: n.subject.title,
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
      });
      scanned++;
    }

    await ctx.runMutation(internal.connections.touchLastScanned, {
      connectionId: connection._id,
    });

    return { scanned, total: notifications.length };
  },
});
