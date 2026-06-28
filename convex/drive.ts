"use node";

import { v } from "convex/values";
import { google } from "googleapis";
import { action } from "./_generated/server";
import { internal } from "./_generated/api";
import { runPipeline } from "./pipeline";
import { decryptSecret } from "../lib/secretBox";
import { assertOwnerToken } from "../lib/ownerToken";

const MAX_FILES = 30;
const TEXT_MIME = "text/plain";
const DOC_MIME = "application/vnd.google-apps.document";

export const scanDrive = action({
  args: { ownerId: v.string(), ownerToken: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, { ownerId, ownerToken, limit }): Promise<{ scanned: number; total: number }> => {
    await assertOwnerToken(ownerId, ownerToken);
    const max = Math.min(MAX_FILES, Math.max(1, limit ?? 25));
    // Reuses the existing Google (Gmail) connection. Same OAuth, now with the drive.readonly
    // scope. Attackers share malicious Google Docs (phishing links) to bypass email filters,
    // so we scan files recently shared with the user.
    const connection = await ctx.runQuery(internal.connections.getActiveGmail, { ownerId });
    if (!connection) {
      throw new Error("Connect Google (Gmail) first. Drive scanning reuses that connection.");
    }

    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET
    );
    oauth2Client.setCredentials({
      access_token: decryptSecret(connection.accessToken),
      refresh_token: connection.refreshToken ? decryptSecret(connection.refreshToken) : undefined,
    });
    const drive = google.drive({ version: "v3", auth: oauth2Client });

    let list;
    try {
      list = await drive.files.list({
        q: "sharedWithMe = true and trashed = false",
        orderBy: "sharedWithMeTime desc",
        pageSize: max,
        fields: "files(id, name, mimeType, webViewLink, owners(displayName, emailAddress))",
      });
    } catch {
      throw new Error("Drive API request failed. Make sure the Drive API is enabled and reconnect Google to grant Drive access.");
    }

    const files = list.data.files ?? [];
    let scanned = 0;

    for (const f of files) {
      if (!f.id) continue;
      const existing = await ctx.runQuery(internal.scanResults.findByExternalId, {
        connectionId: connection._id,
        externalId: `drive:${f.id}`,
      });
      if (existing) continue;

      // For Google Docs / plain-text files, pull the actual text so we can catch phishing
      // links inside the document; otherwise scan the filename + sharer as the signal.
      let body = "";
      try {
        if (f.mimeType === DOC_MIME) {
          const exp = await drive.files.export({ fileId: f.id, mimeType: TEXT_MIME });
          body = typeof exp.data === "string" ? exp.data : "";
        } else if (f.mimeType === TEXT_MIME) {
          const dl = await drive.files.get({ fileId: f.id, alt: "media" });
          body = typeof dl.data === "string" ? dl.data : "";
        }
      } catch {
        // can't read contents. Fall back to filename-only scan
      }

      const owner = f.owners?.[0];
      const ownerNote = owner ? `Shared by ${owner.displayName ?? ""} <${owner.emailAddress ?? ""}>` : "Shared file";
      const text = `Shared document: ${f.name}\n${ownerNote}\n\n${body}`.slice(0, 4000);

      const result = await runPipeline(text, { captureScreenshot: false });
      await ctx.runMutation(internal.scanResults.insert, {
        ownerId,
        connectionId: connection._id,
        provider: "drive",
        externalId: `drive:${f.id}`,
        subject: f.name ?? "Shared file",
        snippet: text,
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

    return { scanned, total: files.length };
  },
});
