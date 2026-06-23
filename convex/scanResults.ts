import { v } from "convex/values";
import { internalMutation, internalQuery, query } from "./_generated/server";

export const insert = internalMutation({
  args: {
    ownerId: v.string(),
    connectionId: v.optional(v.id("connections")),
    provider: v.union(v.literal("gmail"), v.literal("github"), v.literal("manual")),
    externalId: v.optional(v.string()),
    subject: v.optional(v.string()),
    snippet: v.string(),
    verdict: v.union(v.literal("safe"), v.literal("suspicious"), v.literal("scam")),
    mlScore: v.number(),
    confidence: v.number(),
    summary: v.string(),
    recommendation: v.string(),
    flaggedPhrases: v.array(
      v.object({
        phrase: v.string(),
        reason: v.string(),
        severity: v.union(v.literal("amber"), v.literal("red")),
      })
    ),
    signals: v.array(v.object({ label: v.string(), value: v.number() })),
    aiReviewed: v.boolean(),
    linkIntel: v.optional(
      v.array(
        v.object({
          url: v.string(),
          domain: v.string(),
          vtMalicious: v.number(),
          vtSuspicious: v.number(),
        })
      )
    ),
    screenshot: v.optional(
      v.object({
        url: v.string(),
        resultUrl: v.string(),
        screenshotUrl: v.string(),
        uuid: v.string(),
        ready: v.boolean(),
      })
    ),
    attachmentIntel: v.optional(
      v.array(
        v.object({
          filename: v.string(),
          sha256: v.string(),
          found: v.boolean(),
          vtMalicious: v.number(),
          vtSuspicious: v.number(),
        })
      )
    ),
    forensics: v.optional(
      v.object({
        fields: v.array(
          v.object({
            label: v.string(),
            value: v.string(),
            status: v.optional(
              v.union(v.literal("ok"), v.literal("warn"), v.literal("bad"))
            ),
          })
        ),
        indicators: v.array(
          v.object({
            label: v.string(),
            detail: v.string(),
            severity: v.union(v.literal("amber"), v.literal("red")),
          })
        ),
      })
    ),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("scanResults", args);
  },
});

export const listForOwner = query({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    return await ctx.db
      .query("scanResults")
      .withIndex("by_owner", (q) => q.eq("ownerId", ownerId))
      .order("desc")
      .take(30);
  },
});

export const analyticsForOwner = query({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    const rows = await ctx.db
      .query("scanResults")
      .withIndex("by_owner", (q) => q.eq("ownerId", ownerId))
      .order("desc")
      .take(500);

    const byVerdict = { safe: 0, suspicious: 0, scam: 0 };
    const bySource: Record<string, number> = {};
    const signalTotals: Record<string, { sum: number; n: number }> = {};
    let aiReviewed = 0;
    let confidenceSum = 0;
    let linkChecks = 0;
    let flaggedLinks = 0;

    for (const r of rows) {
      byVerdict[r.verdict] += 1;
      bySource[r.provider] = (bySource[r.provider] ?? 0) + 1;
      if (r.aiReviewed) aiReviewed += 1;
      confidenceSum += r.confidence;
      for (const s of r.signals) {
        const t = (signalTotals[s.label] ??= { sum: 0, n: 0 });
        t.sum += s.value;
        t.n += 1;
      }
      for (const li of r.linkIntel ?? []) {
        linkChecks += 1;
        if (li.vtMalicious > 0 || li.vtSuspicious > 0) flaggedLinks += 1;
      }
    }

    const topSignals = Object.entries(signalTotals)
      .map(([label, { sum, n }]) => ({ label, avg: n ? sum / n : 0 }))
      .sort((a, b) => b.avg - a.avg);

    return {
      total: rows.length,
      byVerdict,
      bySource,
      aiReviewed,
      avgConfidence: rows.length ? Math.round(confidenceSum / rows.length) : 0,
      topSignals,
      linkChecks,
      flaggedLinks,
      recent: rows.slice(0, 8).map((r) => ({
        _id: r._id,
        subject: r.subject,
        snippet: r.snippet,
        verdict: r.verdict,
        provider: r.provider,
        createdAt: r._creationTime,
      })),
    };
  },
});

export const findByExternalId = internalQuery({
  args: { connectionId: v.id("connections"), externalId: v.string() },
  handler: async (ctx, { connectionId, externalId }) => {
    return await ctx.db
      .query("scanResults")
      .withIndex("by_connection_external", (q) =>
        q.eq("connectionId", connectionId).eq("externalId", externalId)
      )
      .first();
  },
});
