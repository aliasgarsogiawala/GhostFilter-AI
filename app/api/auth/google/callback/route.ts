import { NextRequest, NextResponse } from "next/server";
import { ConvexHttpClient } from "convex/browser";
import { google } from "googleapis";
import { getOAuthClient } from "@/lib/google-oauth";
import { api } from "@/convex/_generated/api";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const ownerId = req.nextUrl.searchParams.get("state");
  const error = req.nextUrl.searchParams.get("error");

  if (error || !code || !ownerId) {
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }

  try {
    const oauth2Client = getOAuthClient();
    const { tokens } = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();

    if (!tokens.access_token) {
      throw new Error("No access token returned");
    }

    const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
    await convex.mutation(api.connections.upsertGmail, {
      ownerId,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token ?? undefined,
      expiresAt: tokens.expiry_date ?? undefined,
      accountEmail: data.email ?? undefined,
    });

    return NextResponse.redirect(new URL("/dashboard?connect=success", req.url));
  } catch (err) {
    console.error("Google OAuth callback failed:", err);
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }
}
