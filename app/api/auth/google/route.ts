import { NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { getOAuthClient, GMAIL_SCOPES } from "@/lib/google-oauth";
import { createOAuthState } from "@/lib/oauthState";

export async function GET() {
  const session = await getServerSession(authOptions);
  const ownerId = session?.user?.id;
  if (!ownerId) {
    return NextResponse.redirect("/dashboard");
  }

  const oauth2Client = getOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: GMAIL_SCOPES,
    prompt: "consent",
    state: createOAuthState(ownerId, "google"),
  });

  return NextResponse.redirect(url);
}
