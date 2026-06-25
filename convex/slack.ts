"use node";

import { v } from "convex/values";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { runPipeline } from "./pipeline";

interface SlackConversation {
  id: string;
  name?: string;
  is_channel?: boolean;
  is_private?: boolean;
  is_im?: boolean;
  is_mpim?: boolean;
  is_member?: boolean;
}

interface SlackMessage {
  ts: string;
  text?: string;
  user?: string;
  bot_id?: string;
}

class SlackApiError extends Error {
  constructor(public code: string) {
    super(`Slack API error: ${code}`);
  }
}

async function slackApi<T>(token: string, path: string, params: Record<string, string>) {
  const url = new URL(`https://slack.com/api/${path}`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const json = (await res.json()) as T & { ok?: boolean; error?: string };
  if (!json.ok) throw new SlackApiError(json.error ?? String(res.status));
  return json;
}

const MAX_CHANNELS = 8;
const MAX_MESSAGES_PER_CHANNEL = 5;

export const scanWorkspace = action({
  args: { ownerId: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, { ownerId, limit }): Promise<{ scanned: number; total: number }> => {
    const connection = await ctx.runQuery(internal.connections.getActiveSlack, { ownerId });
    if (!connection) throw new Error("No connected Slack workspace for this session");

    const maxChannels = Math.min(MAX_CHANNELS, Math.max(1, Math.ceil((limit ?? 25) / MAX_MESSAGES_PER_CHANNEL)));
    const conversations = await slackApi<{ channels?: SlackConversation[] }>(
      connection.accessToken,
      "conversations.list",
      {
        limit: String(maxChannels),
        types: "public_channel,private_channel,im,mpim",
        exclude_archived: "true",
      }
    );

    let total = 0;
    let scanned = 0;

    for (const conversation of conversations.channels ?? []) {
      if ((conversation.is_channel || conversation.is_private) && conversation.is_member === false) {
        continue;
      }

      let history: { messages?: SlackMessage[] };
      try {
        history = await slackApi<{ messages?: SlackMessage[] }>(
          connection.accessToken,
          "conversations.history",
          {
            channel: conversation.id,
            limit: String(MAX_MESSAGES_PER_CHANNEL),
          }
        );
      } catch (error) {
        if (
          error instanceof SlackApiError &&
          ["not_in_channel", "channel_not_found", "is_archived", "missing_scope"].includes(error.code)
        ) {
          continue;
        }
        throw error;
      }
      const messages = history.messages ?? [];
      total += messages.length;

      for (const message of messages) {
        if (!message.text?.trim()) continue;
        const externalId = `${conversation.id}:${message.ts}`;
        const existing = await ctx.runQuery(internal.scanResults.findByExternalId, {
          connectionId: connection._id,
          externalId,
        });
        if (existing) continue;

        const channelLabel = conversation.name
          ? `#${conversation.name}`
          : conversation.is_im
            ? "Slack DM"
            : conversation.is_mpim
              ? "Slack group DM"
              : conversation.id;
        const text = `Slack message from ${channelLabel}\nSender: ${message.user ?? message.bot_id ?? "unknown"}\n\n${message.text}`;
        const result = await runPipeline(text, { captureScreenshot: false });

        await ctx.runMutation(internal.scanResults.insert, {
          ownerId,
          connectionId: connection._id,
          provider: "slack",
          externalId,
          subject: channelLabel,
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
          ensembleScore: result.ensembleScore,
          mlBreakdown: result.mlBreakdown,
        });
        scanned++;
      }
    }

    await ctx.runMutation(internal.connections.touchLastScanned, {
      connectionId: connection._id,
    });

    return { scanned, total };
  },
});
