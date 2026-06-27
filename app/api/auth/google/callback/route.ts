import { NextRequest, NextResponse } from "next/server";
import { ConvexHttpClient } from "convex/browser";
import { google } from "googleapis";
import { getOAuthClient } from "@/lib/google-oauth";
import { api } from "@/convex/_generated/api";
import { verifyOAuthState } from "@/lib/oauthState";
import { encryptSecret } from "@/lib/secretBox";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { createOwnerToken } from "@/lib/ownerToken";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const state = verifyOAuthState(req.nextUrl.searchParams.get("state"), "google");
  const error = req.nextUrl.searchParams.get("error");

  if (error || !code || !state) {
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }

  try {
    const session = await getServerSession(authOptions);
    if (session?.user?.id !== state.ownerId) {
      return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
    }
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
      ownerId: state.ownerId,
      ownerToken: await createOwnerToken(state.ownerId),
      accessToken: encryptSecret(tokens.access_token),
      refreshToken: tokens.refresh_token ? encryptSecret(tokens.refresh_token) : undefined,
      expiresAt: tokens.expiry_date ?? undefined,
      accountEmail: data.email ?? undefined,
    });

    return NextResponse.redirect(new URL("/dashboard?connect=success", req.url));
  } catch (err) {
    console.error("Google OAuth callback failed:", err);
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }
}
