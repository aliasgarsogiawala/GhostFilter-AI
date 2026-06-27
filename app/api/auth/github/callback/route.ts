import { NextRequest, NextResponse } from "next/server";
import { ConvexHttpClient } from "convex/browser";
import { exchangeGithubCode } from "@/lib/github-oauth";
import { api } from "@/convex/_generated/api";
import { verifyOAuthState } from "@/lib/oauthState";
import { encryptSecret } from "@/lib/secretBox";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/lib/auth";
import { createOwnerToken } from "@/lib/ownerToken";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const state = verifyOAuthState(req.nextUrl.searchParams.get("state"), "github");
  const error = req.nextUrl.searchParams.get("error");

  if (error || !code || !state) {
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }

  try {
    const session = await getServerSession(authOptions);
    if (session?.user?.id !== state.ownerId) {
      return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
    }
    const accessToken = await exchangeGithubCode(code);
    if (!accessToken) throw new Error("No access token returned");

    // Look up the GitHub username so the UI can show "Connected as @handle".
    let login: string | undefined;
    try {
      const userRes = await fetch("https://api.github.com/user", {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
      });
      if (userRes.ok) login = (await userRes.json()).login;
    } catch {
      // non-fatal — the handle is just cosmetic
    }

    const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
    await convex.mutation(api.connections.upsertGithub, {
      ownerId: state.ownerId,
      ownerToken: await createOwnerToken(state.ownerId),
      accessToken: encryptSecret(accessToken),
      accountName: login,
    });

    return NextResponse.redirect(new URL("/dashboard?connect=success", req.url));
  } catch (err) {
    console.error("GitHub OAuth callback failed:", err);
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }
}
