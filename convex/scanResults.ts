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
