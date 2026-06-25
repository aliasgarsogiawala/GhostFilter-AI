import { NextRequest, NextResponse } from "next/server";
import { ConvexHttpClient } from "convex/browser";
import { api } from "@/convex/_generated/api";
import { exchangeSlackCode } from "@/lib/slack-oauth";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const ownerId = req.nextUrl.searchParams.get("state");
  const error = req.nextUrl.searchParams.get("error");
  if (error || !code || !ownerId) {
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }

  try {
    const data = await exchangeSlackCode(code);
    const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
    await convex.mutation(api.connections.upsertSlack, {
      ownerId,
      accessToken: data.access_token!,
      accountName: data.team?.name,
    });

    return NextResponse.redirect(new URL("/dashboard?connect=success", req.url));
  } catch (err) {
    console.error("Slack OAuth callback failed:", err);
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }
}
