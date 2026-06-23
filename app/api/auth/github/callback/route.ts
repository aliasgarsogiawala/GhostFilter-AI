import { NextRequest, NextResponse } from "next/server";
import { ConvexHttpClient } from "convex/browser";
import { exchangeGithubCode } from "@/lib/github-oauth";
import { api } from "@/convex/_generated/api";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const ownerId = req.nextUrl.searchParams.get("state");
  const error = req.nextUrl.searchParams.get("error");

  if (error || !code || !ownerId) {
    return NextResponse.redirect(new URL("/?connect=error", req.url));
  }

  try {
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
      ownerId,
      accessToken,
      accountName: login,
    });

    return NextResponse.redirect(new URL("/?connect=success", req.url));
  } catch (err) {
    console.error("GitHub OAuth callback failed:", err);
    return NextResponse.redirect(new URL("/?connect=error", req.url));
  }
}
