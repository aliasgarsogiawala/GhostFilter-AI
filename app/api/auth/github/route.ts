import { NextResponse } from "next/server";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { githubAuthUrl } from "@/lib/github-oauth";
import { createOAuthState } from "@/lib/oauthState";

export async function GET() {
  const session = await getServerSession(authOptions);
  const ownerId = session?.user?.id;
  if (!ownerId) {
    return NextResponse.redirect("/dashboard");
  }
  return NextResponse.redirect(githubAuthUrl(createOAuthState(ownerId, "github")));
}
