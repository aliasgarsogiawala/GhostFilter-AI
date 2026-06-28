import { v } from "convex/values";
import { internalMutation, internalQuery } from "./_generated/server";

export const findByEmail = internalQuery({
  args: { email: v.string() },
  handler: async (ctx, { email }) =>
    await ctx.db.query("users").withIndex("by_email", (q) => q.eq("email", email)).unique(),
});

export const createUser = internalMutation({
  args: { email: v.string(), name: v.string(), passwordHash: v.string() },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("users")
      .withIndex("by_email", (q) => q.eq("email", args.email))
      .unique();
    if (existing) throw new Error("An account with this email already exists.");
    return await ctx.db.insert("users", {
      email: args.email,
      name: args.name,
      passwordHash: args.passwordHash,
      createdAt: Date.now(),
    });
  },
});

export const recordLogin = internalMutation({
  args: { userId: v.id("users") },
  handler: async (ctx, { userId }) => {
    await ctx.db.patch(userId, { lastLoginAt: Date.now() });
  },
});
