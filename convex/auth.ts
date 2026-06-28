"use node";

import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";

const KEY_LENGTH = 64;

function assertServiceSecret(value: string) {
  const expected = process.env.AUTH_SERVICE_SECRET;
  if (!expected || value !== expected) throw new Error("Unauthorized authentication service.");
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function validateInput(email: string, password: string) {
  const normalized = normalizeEmail(email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) throw new Error("Enter a valid email address.");
  if (password.length < 10 || password.length > 128) {
    throw new Error("Password must be between 10 and 128 characters.");
  }
  return normalized;
}

function hashPassword(password: string) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, KEY_LENGTH).toString("hex");
  return `scrypt:${salt}:${hash}`;
}

function passwordMatches(password: string, stored: string) {
  const [algorithm, salt, encoded] = stored.split(":");
  if (algorithm !== "scrypt" || !salt || !encoded) return false;
  const expected = Buffer.from(encoded, "hex");
  const actual = scryptSync(password, salt, expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export const register = action({
  args: {
    serviceSecret: v.string(),
    email: v.string(),
    name: v.string(),
    password: v.string(),
  },
  handler: async (ctx, args): Promise<{ id: string; email: string; name: string }> => {
    assertServiceSecret(args.serviceSecret);
    const email = validateInput(args.email, args.password);
    const name = args.name.trim().slice(0, 80);
    if (name.length < 2) throw new Error("Enter your name.");
    const id = await ctx.runMutation(internal.authData.createUser, {
      email,
      name,
      passwordHash: hashPassword(args.password),
    });
    return { id: String(id), email, name };
  },
});

export const login = action({
  args: { serviceSecret: v.string(), email: v.string(), password: v.string() },
  handler: async (ctx, args): Promise<{ id: string; email: string; name: string } | null> => {
    assertServiceSecret(args.serviceSecret);
    const email = validateInput(args.email, args.password);
    const user = await ctx.runQuery(internal.authData.findByEmail, { email });
    if (!user || !passwordMatches(args.password, user.passwordHash)) return null;
    await ctx.runMutation(internal.authData.recordLogin, { userId: user._id });
    return { id: String(user._id), email: user.email, name: user.name };
  },
});
