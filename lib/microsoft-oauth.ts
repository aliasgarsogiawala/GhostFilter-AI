const MICROSOFT_AUTH_BASE = "https://login.microsoftonline.com/common/oauth2/v2.0";

export const OUTLOOK_SCOPES = ["offline_access", "User.Read", "Mail.Read"];

export function microsoftRedirectUri() {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";
  return `${baseUrl}/api/auth/outlook/callback`;
}

export function microsoftAuthUrl(ownerId: string) {
  const url = new URL(`${MICROSOFT_AUTH_BASE}/authorize`);
  url.searchParams.set("client_id", process.env.MICROSOFT_CLIENT_ID ?? "");
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", microsoftRedirectUri());
  url.searchParams.set("response_mode", "query");
  url.searchParams.set("scope", OUTLOOK_SCOPES.join(" "));
  url.searchParams.set("state", ownerId);
  return url.toString();
}

export async function exchangeMicrosoftCode(code: string) {
  const body = new URLSearchParams({
    client_id: process.env.MICROSOFT_CLIENT_ID ?? "",
    client_secret: process.env.MICROSOFT_CLIENT_SECRET ?? "",
    code,
    redirect_uri: microsoftRedirectUri(),
    grant_type: "authorization_code",
    scope: OUTLOOK_SCOPES.join(" "),
  });

  const res = await fetch(`${MICROSOFT_AUTH_BASE}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error(`Microsoft token exchange failed: ${res.status}`);
  return (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
  };
}
