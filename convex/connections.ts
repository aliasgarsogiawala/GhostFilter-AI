import { v } from "convex/values";
import { mutation, query, internalQuery, internalMutation } from "./_generated/server";

export const upsertGmail = mutation({
  args: {
    ownerId: v.string(),
    accessToken: v.string(),
    refreshToken: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    accountEmail: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", args.ownerId).eq("provider", "gmail"))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        status: "connected",
        accessToken: args.accessToken,
        refreshToken: args.refreshToken ?? existing.refreshToken,
        expiresAt: args.expiresAt,
        accountEmail: args.accountEmail ?? existing.accountEmail,
      });
      return existing._id;
    }

    return await ctx.db.insert("connections", {
      ownerId: args.ownerId,
      provider: "gmail",
      status: "connected",
      accessToken: args.accessToken,
      refreshToken: args.refreshToken,
      expiresAt: args.expiresAt,
      accountEmail: args.accountEmail,
    });
  },
});

export const upsertGithub = mutation({
  args: {
    ownerId: v.string(),
    accessToken: v.string(),
    accountName: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", args.ownerId).eq("provider", "github"))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        status: "connected",
        accessToken: args.accessToken,
        accountName: args.accountName ?? existing.accountName,
      });
      return existing._id;
    }

    return await ctx.db.insert("connections", {
      ownerId: args.ownerId,
      provider: "github",
      status: "connected",
      accessToken: args.accessToken,
      accountName: args.accountName,
    });
  },
});

// Public list — strips tokens before returning, never expose them to the client.
export const listForOwner = query({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    const rows = await ctx.db
      .query("connections")
      .withIndex("by_owner", (q) => q.eq("ownerId", ownerId))
      .collect();
    return rows.map(({ accessToken: _accessToken, refreshToken: _refreshToken, ...safe }) => safe);
  },
});

export const disconnect = mutation({
  args: { connectionId: v.id("connections"), ownerId: v.string() },
  handler: async (ctx, { connectionId, ownerId }) => {
    const row = await ctx.db.get(connectionId);
    if (!row || row.ownerId !== ownerId) throw new Error("Connection not found");
    await ctx.db.patch(connectionId, {
      status: "disconnected",
      accessToken: "",
      refreshToken: undefined,
    });
  },
});

// Internal — used only by the convex/gmail.ts scan action, never exposed with tokens to the client.
export const getActiveGmail = internalQuery({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    const row = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", ownerId).eq("provider", "gmail"))
      .first();
    return row && row.status === "connected" ? row : null;
  },
});

export const getActiveGithub = internalQuery({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    const row = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", ownerId).eq("provider", "github"))
      .first();
    return row && row.status === "connected" ? row : null;
  },
});

export const touchLastScanned = internalMutation({
  args: { connectionId: v.id("connections") },
  handler: async (ctx, { connectionId }) => {
    await ctx.db.patch(connectionId, { lastScannedAt: Date.now() });
  },
});
