import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  users: defineTable({
    email: v.string(),
    name: v.string(),
    passwordHash: v.string(),
    createdAt: v.number(),
    lastLoginAt: v.optional(v.number()),
  }).index("by_email", ["email"]),

  // One row per account a browser has connected. Tokens are stripped from the
  // public list query and only used by server-side scan actions.
  connections: defineTable({
    ownerId: v.string(), // NextAuth session user id
    provider: v.union(v.literal("gmail"), v.literal("github"), v.literal("outlook"), v.literal("slack")),
    status: v.union(v.literal("connected"), v.literal("disconnected")),
    accessToken: v.string(),
    refreshToken: v.optional(v.string()),
    expiresAt: v.optional(v.number()),
    accountEmail: v.optional(v.string()),
    accountName: v.optional(v.string()), // e.g. GitHub @handle, Slack workspace/team, Microsoft display name
    lastScannedAt: v.optional(v.number()),
  })
    .index("by_owner", ["ownerId"])
    .index("by_owner_provider", ["ownerId", "provider"]),

  // One row per analyzed message, whether it came from a connected account's
  // scan or the manual paste-a-message analyzer (connectionId is undefined for manual).
  scanResults: defineTable({
    ownerId: v.string(),
    connectionId: v.optional(v.id("connections")),
    provider: v.union(v.literal("gmail"), v.literal("drive"), v.literal("github"), v.literal("outlook"), v.literal("slack"), v.literal("manual")),
    externalId: v.optional(v.string()), // e.g. Gmail message id, for de-duplication
    subject: v.optional(v.string()),
    snippet: v.string(),
    verdict: v.union(v.literal("safe"), v.literal("suspicious"), v.literal("scam")),
    mlScore: v.number(), // 0-1, raw classifier output
    confidence: v.number(), // 0-100, final displayed confidence
    summary: v.string(),
    recommendation: v.string(),
    flaggedPhrases: v.array(
      v.object({
        phrase: v.string(),
        reason: v.string(),
        severity: v.union(v.literal("amber"), v.literal("red")),
      })
    ),
    signals: v.array(
      v.object({
        label: v.string(),
        value: v.number(), // 0-100
      })
    ),
    aiReviewed: v.boolean(), // false if the ML score never crossed the Gemini-review threshold
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
    ensembleScore: v.optional(v.number()),
    mlBreakdown: v.optional(
      v.array(
        v.object({
          label: v.string(),
          score: v.number(),
          evidence: v.string(),
          explanation: v.string(),
        })
      )
    ),
  })
    .index("by_owner", ["ownerId"])
    .index("by_connection_external", ["connectionId", "externalId"]),

  agentScans: defineTable({
    ownerId: v.string(),
    source: v.union(v.literal("manual"), v.literal("file"), v.literal("api")),
    subject: v.optional(v.string()),
    snippet: v.string(),
    verdict: v.union(v.literal("pass"), v.literal("isolate"), v.literal("block")),
    score: v.number(),
    title: v.string(),
    summary: v.string(),
    recommendation: v.string(),
    findings: v.array(
      v.object({
        label: v.string(),
        detail: v.string(),
        severity: v.union(v.literal("amber"), v.literal("red")),
        evidence: v.string(),
      })
    ),
    sanitizedContext: v.string(),
  }).index("by_owner", ["ownerId"]),

  scanFeedback: defineTable({
    ownerId: v.string(),
    scanResultId: v.id("scanResults"),
    expectedVerdict: v.union(v.literal("safe"), v.literal("suspicious"), v.literal("scam")),
    note: v.optional(v.string()),
  })
    .index("by_owner", ["ownerId"])
    .index("by_scan", ["scanResultId"]),
});
