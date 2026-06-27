import { NextRequest, NextResponse } from "next/server";
import { ConvexHttpClient } from "convex/browser";
import { api } from "@/convex/_generated/api";
import { exchangeSlackCode } from "@/lib/slack-oauth";
import { verifyOAuthState } from "@/lib/oauthState";
import { encryptSecret } from "@/lib/secretBox";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { createOwnerToken } from "@/lib/ownerToken";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const state = verifyOAuthState(req.nextUrl.searchParams.get("state"), "slack");
  const error = req.nextUrl.searchParams.get("error");
  if (error || !code || !state) {
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }

  try {
    const session = await getServerSession(authOptions);
    if (session?.user?.id !== state.ownerId) {
      return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
    }
    const data = await exchangeSlackCode(code);
    const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
    await convex.mutation(api.connections.upsertSlack, {
      ownerId: state.ownerId,
      ownerToken: await createOwnerToken(state.ownerId),
      accessToken: encryptSecret(data.access_token!),
      accountName: data.team?.name,
    });

    return NextResponse.redirect(new URL("/dashboard?connect=success", req.url));
  } catch (err) {
    console.error("Slack OAuth callback failed:", err);
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }
}
