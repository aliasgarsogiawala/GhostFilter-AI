import { NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { slackAuthUrl } from "@/lib/slack-oauth";
import { createOAuthState } from "@/lib/oauthState";

export async function GET() {
  const session = await getServerSession(authOptions);
  const ownerId = session?.user?.id;
  if (!ownerId) return NextResponse.redirect("/dashboard");
  return NextResponse.redirect(slackAuthUrl(createOAuthState(ownerId, "slack")));
}
