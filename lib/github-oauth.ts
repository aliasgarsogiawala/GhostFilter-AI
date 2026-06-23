// GitHub OAuth — read-only access to the user's notifications, which is where
// GitHub-channel scams surface (fake "security alert" issues, crypto-airdrop
// spam mentions, impersonation in issue/PR comments).

export const GITHUB_SCOPE = "notifications";

export function githubAuthUrl(ownerId: string): string {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID ?? "",
    redirect_uri: `${baseUrl}/api/auth/github/callback`,
    scope: GITHUB_SCOPE,
    state: ownerId,
  });
  return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

export async function exchangeGithubCode(code: string): Promise<string | null> {
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });
  if (!res.ok) return null;
  const json = await res.json();
  return json.access_token ?? null;
}
