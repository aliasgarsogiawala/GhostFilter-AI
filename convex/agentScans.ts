import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

const findingValidator = v.object({
  label: v.string(),
  detail: v.string(),
  severity: v.union(v.literal("amber"), v.literal("red")),
  evidence: v.string(),
});

export const insertManual = mutation({
  args: {
    ownerId: v.string(),
    source: v.union(v.literal("manual"), v.literal("file"), v.literal("api")),
    subject: v.optional(v.string()),
    snippet: v.string(),
    verdict: v.union(v.literal("pass"), v.literal("isolate"), v.literal("block")),
    score: v.number(),
    title: v.string(),
    summary: v.string(),
    recommendation: v.string(),
    findings: v.array(findingValidator),
    sanitizedContext: v.string(),
  },
  handler: async (ctx, args) => {
    return await ctx.db.insert("agentScans", {
      ...args,
      snippet: args.snippet.slice(0, 6000),
      sanitizedContext: args.sanitizedContext.slice(0, 9000),
    });
  },
});

export const listForOwner = query({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    return await ctx.db
      .query("agentScans")
      .withIndex("by_owner", (q) => q.eq("ownerId", ownerId))
      .order("desc")
      .take(30);
  },
});

export const clearForOwner = mutation({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    const rows = await ctx.db
      .query("agentScans")
      .withIndex("by_owner", (q) => q.eq("ownerId", ownerId))
      .collect();
    await Promise.all(rows.map((row) => ctx.db.delete(row._id)));
    return { deleted: rows.length };
  },
});
