import { NextRequest, NextResponse } from "next/server";
import { slackAuthUrl } from "@/lib/slack-oauth";

export async function GET(req: NextRequest) {
  const ownerId = req.nextUrl.searchParams.get("ownerId");
  if (!ownerId) return NextResponse.json({ error: "missing ownerId" }, { status: 400 });
  return NextResponse.redirect(slackAuthUrl(ownerId));
}
