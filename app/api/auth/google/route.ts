import { NextRequest, NextResponse } from "next/server";
import { getOAuthClient, GMAIL_SCOPES } from "@/lib/google-oauth";

export async function GET(req: NextRequest) {
  const ownerId = req.nextUrl.searchParams.get("ownerId");
  if (!ownerId) {
    return NextResponse.json({ error: "missing ownerId" }, { status: 400 });
  }

  const oauth2Client = getOAuthClient();
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: GMAIL_SCOPES,
    prompt: "consent",
    state: ownerId,
  });

  return NextResponse.redirect(url);
}
