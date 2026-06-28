import { v } from "convex/values";
import { mutation, query, internalQuery, internalMutation } from "./_generated/server";
import { assertOwnerToken } from "../lib/ownerToken";

export const upsertGmail = mutation({
  args: {
    ownerId: v.string(),
    ownerToken: v.string(),
    accessToken: v.string(),
    refreshToken: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    accountEmail: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await assertOwnerToken(args.ownerId, args.ownerToken);
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
    ownerToken: v.string(),
    accessToken: v.string(),
    accountName: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await assertOwnerToken(args.ownerId, args.ownerToken);
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

export const upsertOutlook = mutation({
  args: {
    ownerId: v.string(),
    accessToken: v.string(),
    refreshToken: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    accountEmail: v.optional(v.string()),
    accountName: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", args.ownerId).eq("provider", "outlook"))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        status: "connected",
        accessToken: args.accessToken,
        refreshToken: args.refreshToken ?? existing.refreshToken,
        expiresAt: args.expiresAt,
        accountEmail: args.accountEmail ?? existing.accountEmail,
        accountName: args.accountName ?? existing.accountName,
      });
      return existing._id;
    }

    return await ctx.db.insert("connections", {
      ownerId: args.ownerId,
      provider: "outlook",
      status: "connected",
      accessToken: args.accessToken,
      refreshToken: args.refreshToken,
      expiresAt: args.expiresAt,
      accountEmail: args.accountEmail,
      accountName: args.accountName,
    });
  },
});

export const upsertSlack = mutation({
  args: {
    ownerId: v.string(),
    ownerToken: v.string(),
    accessToken: v.string(),
    accountName: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await assertOwnerToken(args.ownerId, args.ownerToken);
    const existing = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", args.ownerId).eq("provider", "slack"))
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
      provider: "slack",
      status: "connected",
      accessToken: args.accessToken,
      accountName: args.accountName,
    });
  },
});

// Public list. Strips tokens before returning, never expose them to the client.
export const listForOwner = query({
  args: { ownerId: v.string(), ownerToken: v.string() },
  handler: async (ctx, { ownerId, ownerToken }) => {
    await assertOwnerToken(ownerId, ownerToken);
    const rows = await ctx.db
      .query("connections")
      .withIndex("by_owner", (q) => q.eq("ownerId", ownerId))
      .collect();
    return rows.map((row) => {
      const { accessToken, refreshToken, ...safe } = row;
      void accessToken;
      void refreshToken;
      return safe;
    });
  },
});

export const disconnect = mutation({
  args: { connectionId: v.id("connections"), ownerId: v.string(), ownerToken: v.string() },
  handler: async (ctx, { connectionId, ownerId, ownerToken }) => {
    await assertOwnerToken(ownerId, ownerToken);
    const row = await ctx.db.get(connectionId);
    if (!row || row.ownerId !== ownerId) throw new Error("Connection not found");
    await ctx.db.patch(connectionId, {
      status: "disconnected",
      accessToken: "",
      refreshToken: undefined,
    });
  },
});

// Internal. Used only by the convex/gmail.ts scan action, never exposed with tokens to the client.
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

export const getActiveOutlook = internalQuery({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    const row = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", ownerId).eq("provider", "outlook"))
      .first();
    return row && row.status === "connected" ? row : null;
  },
});

export const getActiveSlack = internalQuery({
  args: { ownerId: v.string() },
  handler: async (ctx, { ownerId }) => {
    const row = await ctx.db
      .query("connections")
      .withIndex("by_owner_provider", (q) => q.eq("ownerId", ownerId).eq("provider", "slack"))
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
