import { NextRequest, NextResponse } from "next/server";
import { ConvexHttpClient } from "convex/browser";
import { api } from "@/convex/_generated/api";
import { exchangeMicrosoftCode } from "@/lib/microsoft-oauth";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const ownerId = req.nextUrl.searchParams.get("state");
  const error = req.nextUrl.searchParams.get("error");
  if (error || !code || !ownerId) {
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }

  try {
    const tokens = await exchangeMicrosoftCode(code);
    if (!tokens.access_token) throw new Error("No Microsoft access token returned");

    let accountEmail: string | undefined;
    let accountName: string | undefined;
    try {
      const profile = await fetch("https://graph.microsoft.com/v1.0/me", {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      });
      if (profile.ok) {
        const data = (await profile.json()) as { mail?: string; userPrincipalName?: string; displayName?: string };
        accountEmail = data.mail ?? data.userPrincipalName;
        accountName = data.displayName;
      }
    } catch {
      // Cosmetic only.
    }

    const convex = new ConvexHttpClient(process.env.NEXT_PUBLIC_CONVEX_URL!);
    await convex.mutation(api.connections.upsertOutlook, {
      ownerId,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token ?? undefined,
      expiresAt: tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined,
      accountEmail,
      accountName,
    });

    return NextResponse.redirect(new URL("/dashboard?connect=success", req.url));
  } catch (err) {
    console.error("Outlook OAuth callback failed:", err);
    return NextResponse.redirect(new URL("/dashboard?connect=error", req.url));
  }
}
